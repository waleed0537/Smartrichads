const express = require('express');
const router = express.Router();
const axios = require('axios');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const bcrypt = require('bcryptjs');

// Existing auth routes
const authController = require('../controllers/authController');
router.post('/signup', authController.signup);
router.post('/login', authController.login);

// Google OAuth routes
router.get('/auth/google/callback', async (req, res) => {
    const { code } = req.query;
    
    if (req.query.error) {
        console.error('Google OAuth error:', req.query.error);
        return res.redirect('/frontend/login.html?error=Authentication+denied');
    }
    
    try {
        // Exchange authorization code for tokens
        const tokenResponse = await axios.post('https://oauth2.googleapis.com/token', {
            code,
            client_id: process.env.GOOGLE_CLIENT_ID,
            client_secret: process.env.GOOGLE_CLIENT_SECRET,
            redirect_uri: `${req.protocol}://${req.get('host')}/api/auth/google/callback`,
            grant_type: 'authorization_code'
        });
        
        const { access_token, id_token } = tokenResponse.data;
        
        // Get user profile information
        const userInfoResponse = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
            headers: { Authorization: `Bearer ${access_token}` }
        });
        
        const { sub, email, name } = userInfoResponse.data;
        
        // Check if user exists in database
        let user = await User.findOne({ email });
        
        if (!user) {
            // Generate a random password for the user (they'll never use it directly)
            const password = Math.random().toString(36).slice(-8);
            const hashedPassword = await bcrypt.hash(password, 12);
            
            // Create a new user with Google profile
            user = await User.create({
                name,
                email,
                password: hashedPassword,
                userType: 'affiliate', // Default to affiliate, can be changed later
                googleId: sub
            });
        } else if (!user.googleId) {
            // If user exists but doesn't have googleId, update their record
            user.googleId = sub;
            await user.save();
        }
        
        // Generate JWT token
        const token = jwt.sign(
            { userId: user._id, userType: user.userType },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );
        
        // Set cookie - ensure SameSite and secure attributes are properly set
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax', // Use 'lax' for better security with OAuth flows
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        // Store user info in localStorage via a redirect
        return res.redirect(`/frontend/auth-success.html?userType=${user.userType}&name=${encodeURIComponent(user.name)}`);
    } catch (error) {
        console.error('Google OAuth error:', error);
        return res.redirect('/frontend/login.html?error=Authentication+failed');
    }
});

module.exports = router;