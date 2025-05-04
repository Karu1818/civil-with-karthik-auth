// File: auth-server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const path = require('path');
const { OAuth2Client } = require('google-auth-library');
const nodemailer = require('nodemailer');
const { authenticator } = require('otplib');
require('dotenv').config({ path: './email.env' });

const app = express();
const PORT = process.env.PORT || 5000;
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, required: true, unique: true },
  age: Number,
  role: String, // 'student' or 'professional'
  phone: String,
  googleId: String,
  experience: String,
  specialization: String,
  skills: [String],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Create nodemailer transporter
const transporter = nodemailer.createTransport({
  service: process.env.EMAIL_SERVICE || 'gmail',
  auth: {
    user: process.env.EMAIL_USERNAME,
    pass: process.env.EMAIL_PASSWORD
  }
});

// OTP storage - In production, use Redis or a database
const otpStorage = new Map();

// Configure OTP library
authenticator.options = {
  digits: 6,
  step: 600  // 10 minutes validity
};

// Google Authentication
app.post('/api/auth/google', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID
    });
    
    const payload = ticket.getPayload();
    const { name, email, sub: googleId } = payload;
    
    // Check if user exists
    let user = await User.findOne({ email });
    let profileComplete = false;
    
    if (!user) {
      // Create new user
      user = new User({
        name,
        email,
        googleId
      });
      await user.save();
    } else {
      // Check if profile is complete
      profileComplete = Boolean(user.name && user.age && user.role);
    }
    
    res.json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        age: user.age,
        role: user.role,
        phone: user.phone,
        experience: user.experience,
        specialization: user.specialization,
        skills: user.skills
      },
      profileComplete
    });
  } catch (error) {
    console.error('Google auth error:', error);
    res.status(500).json({ success: false, message: 'Authentication failed' });
  }
});

// Check if email exists
app.get('/api/users/check-email', async (req, res) => {
  try {
    const { email } = req.query;
    const user = await User.findOne({ email });
    
    if (user) {
      // User exists
      const profileComplete = Boolean(user.name && user.age && user.role);
      res.json({
        exists: true,
        user: {
          _id: user._id,
          name: user.name,
          email: user.email,
          age: user.age,
          role: user.role,
          phone: user.phone,
          experience: user.experience,
          specialization: user.specialization,
          skills: user.skills
        },
        profileComplete
      });
    } else {
      // User doesn't exist
      res.json({ exists: false });
    }
  } catch (error) {
    console.error('Error checking email:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Update user profile
app.post('/api/users/update-profile', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    
    // Find user by email
    let user = await User.findOne({ email });
    
    if (!user) {
      // Create new user if not exists
      user = new User({ email });
    }
    
    // Update user fields
    const updateFields = ['name', 'age', 'role', 'phone', 'experience', 'specialization', 'skills'];
    
    updateFields.forEach(field => {
      if (req.body[field] !== undefined) {
        user[field] = req.body[field];
      }
    });
    
    user.updatedAt = Date.now();
    await user.save();
    
    res.json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        age: user.age,
        role: user.role,
        phone: user.phone,
        experience: user.experience,
        specialization: user.specialization,
        skills: user.skills
      }
    });
  } catch (error) {
    console.error('Error updating profile:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get user profile
app.get('/api/users/profile', async (req, res) => {
  try {
    const { email } = req.query;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    res.json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        age: user.age,
        role: user.role,
        phone: user.phone,
        experience: user.experience,
        specialization: user.specialization,
        skills: user.skills
      }
    });
  } catch (error) {
    console.error('Error fetching profile:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Request OTP
app.post('/api/auth/request-otp', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ success: false, message: 'Email is required' });
    }
    
    // Check if user exists
    const user = await User.findOne({ email });
    
    if (!user) {
      // Don't reveal that the user doesn't exist for security
      return res.json({ 
        success: true, 
        message: 'If the email exists, an OTP has been sent' 
      });
    }
    
    // Generate OTP
    const secret = authenticator.generateSecret();
    const otp = authenticator.generate(secret);
    
    // Store OTP with timestamp
    otpStorage.set(email, {
      secret,
      expiresAt: Date.now() + 10 * 60 * 1000  // 10 minutes from now
    });
    
    // Send OTP email
    const mailOptions = {
      from: process.env.EMAIL_FROM || 'Civil With Karthik <noreply@civilwithkarthik.com>',
      to: email,
      subject: 'Your OTP for Civil With Karthik',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px; background-color: #f9f9f9;">
          <div style="text-align: center; margin-bottom: 20px;">
            <h2 style="color: #1e40af;">Civil With Karthik</h2>
          </div>
          <div style="background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
            <h3 style="margin-top: 0;">Your One-Time Password</h3>
            <p>Hello ${user.name || 'there'},</p>
            <p>Your verification code for Civil With Karthik is:</p>
            <div style="text-align: center; margin: 20px 0;">
              <div style="font-size: 24px; font-weight: bold; letter-spacing: 8px; padding: 15px; background-color: #f0f4ff; border-radius: 5px;">${otp}</div>
            </div>
            <p>This code will expire in 10 minutes.</p>
            <p>If you didn't request this code, please ignore this email.</p>
          </div>
          <div style="text-align: center; margin-top: 20px; font-size: 12px; color: #666;">
            <p>© ${new Date().getFullYear()} Civil With Karthik. All rights reserved.</p>
          </div>
        </div>
      `
    };
    
    await transporter.sendMail(mailOptions);
    
    res.json({
      success: true,
      message: 'OTP sent successfully'
    });
  } catch (error) {
    console.error('Error sending OTP:', error);
    res.status(500).json({ success: false, message: 'Failed to send OTP' });
  }
});

// Verify OTP
app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp } = req.body;
    
    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email and OTP are required' });
    }
    
    // Check if OTP exists and is valid
    const otpData = otpStorage.get(email);
    
    if (!otpData) {
      return res.status(400).json({ success: false, message: 'OTP expired or invalid' });
    }
    
    // Check if OTP is expired
    if (Date.now() > otpData.expiresAt) {
      otpStorage.delete(email);
      return res.status(400).json({ success: false, message: 'OTP expired' });
    }
    
    // Verify OTP
    const isValid = authenticator.verify({
      token: otp,
      secret: otpData.secret
    });
    
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid OTP' });
    }
    
    // OTP is valid - Get user data
    const user = await User.findOne({ email });
    
    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }
    
    // Clear the OTP from storage
    otpStorage.delete(email);
    
    // Check if profile is complete
    const profileComplete = Boolean(user.name && user.age && user.role);
    
    res.json({
      success: true,
      user: {
        _id: user._id,
        name: user.name,
        email: user.email,
        age: user.age,
        role: user.role,
        phone: user.phone,
        experience: user.experience,
        specialization: user.specialization,
        skills: user.skills
      },
      profileComplete
    });
  } catch (error) {
    console.error('Error verifying OTP:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Add a cleanup function to remove expired OTPs
function cleanupExpiredOTPs() {
  const now = Date.now();
  for (const [email, otpData] of otpStorage.entries()) {
    if (now > otpData.expiresAt) {
      otpStorage.delete(email);
    }
  }
}

// Run cleanup every 5 minutes
setInterval(cleanupExpiredOTPs, 5 * 60 * 1000);

// Add a simple root route for testing
app.get('/', (req, res) => {
  res.send('Civil With Karthik Auth Server is running!');
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ success: false, message: 'Internal server error' });
});

// Start the server

//app.listen(PORT, '0.0.0.0', () => {
 // console.log(`Server running on port ${PORT}`);
//});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});