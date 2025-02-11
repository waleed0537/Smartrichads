const User = require('../models/User');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Payment = require('../models/payment');

exports.signup = async (req, res) => {
    try {
        const { name, email, password, userType } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        const user = await User.create({
            name,
            email,
            password,
            userType
        });

        const token = jwt.sign(
            { userId: user._id },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        res.cookie('token', token, {
            httpOnly: true,
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.status(201).json({
            status: 'success',
            token
        });
    } catch (error) {
        res.status(500).json({
            status: 'error',
            message: error.message
        });
    }
};


exports.login = async (req, res) => {
    try {
        const { email, password, userType } = req.body;

        // Special admin login
        if (email === 'admin@mail.com' && password === 'admin123') {
            // Create admin token
            const token = jwt.sign(
                { userId: 'admin', userType: 'admin' },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Set cookie
            res.cookie('token', token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                maxAge: 24 * 60 * 60 * 1000 // 24 hours
            });

            return res.json({ 
                success: true,
                userType: 'admin',
                name: 'Admin'
            });
        }

        // Regular user login
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ 
                message: 'Invalid email or password' 
            });
        }

        // Verify user type matches
        if (user.userType !== userType) {
            return res.status(401).json({ 
                message: `Please switch to ${user.userType} login type` 
            });
        }

        // Check password
        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) {
            return res.status(401).json({ 
                message: 'Invalid email or password' 
            });
        }

        // Generate token
        const token = jwt.sign(
            { userId: user._id, userType: user.userType },
            process.env.JWT_SECRET,
            { expiresIn: '24h' }
        );

        // Set cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });

        res.json({ 
            success: true,
            userType: user.userType,
            name: user.name
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error during login' });
    }
};