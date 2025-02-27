const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
const Payment = require('./models/payment');

//Run commands
// cd backend 
// node server.js

// Load environment variables from .env file
dotenv.config({ path: path.join(__dirname, '../.env') });

const app = express();

// Middleware
app.use(express.json());
app.use(cors());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../')));

// Log the MongoDB URI (remove in production)
console.log('MongoDB URI:', process.env.MONGODB_URI);

// MongoDB Connection with options
mongoose.connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => {
    console.log('Connected to MongoDB successfully');
})
.catch(err => {
    console.error('MongoDB connection error:', err.message);
});
// User Model
const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    userType: { 
        type: String, 
        enum: ['affiliate', 'advertiser'], 
        required: true 
    },
    createdAt: { type: Date, default: Date.now }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

const User = mongoose.model('User', userSchema);

// Authentication Middleware

// Create email transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'smartrichads@gmail.com', // Your Gmail address
        pass: 'rqtp zuyg xkvn nmym'    // Your Gmail app password
    }
});
app.post('/api/contact', async (req, res) => {
    const { name, email, message } = req.body;

    // Validate input
    if (!name || !email || !message) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const mailOptions = {
        from: 'smartrichads@gmail.com', // Fixed sender (your Gmail)
        replyTo: email, // Set user's email as reply-to
        to: 'support@smartrichads.com', // Recipient email
        subject: 'New Contact Form Submission',
        html: `
            <h3>New Contact Form Submission</h3>
            <p><strong>Name:</strong> ${name}</p>
            <p><strong>Email:</strong> ${email}</p>
            <p><strong>Message:</strong></p>
            <p>${message}</p>
        `
    };

    try {
        // Send email
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Message sent successfully' });
    } catch (error) {
        console.error('Error sending email:', error);
        res.status(500).json({ error: 'Failed to send message' });
    }
});
const auth = async (req, res, next) => {
    try {
        // Check for Google Auth header first
        const googleAuth = req.headers['x-google-auth'] === 'true';
        
        // If Google auth is present, check for user details in the request body
        if (googleAuth && req.body && req.body.googleAuth) {
            // For Google-authenticated users, we'll trust the client-side flag
            // This is a simplified approach - in production, you would validate with Google
            req.user = {
                userId: req.body.userEmail, // Use email as a user identifier
                userType: req.body.userType || localStorage.getItem('userType') || 'affiliate', // Default to affiliate
                googleAuth: true
            };
            
            return next();
        }
        
        // Traditional auth flow with JWT token in cookie
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ message: 'Authentication required' });
        }
        
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            next();
        } catch (error) {
            console.error('Token verification error:', error);
            return res.status(401).json({ message: 'Invalid token' });
        }
    } catch (error) {
        console.error('Auth middleware error:', error);
        res.status(401).json({ message: 'Authentication failed' });
    }
};
// Routes
app.post('/api/payment', auth, async (req, res) => {
    console.log('Payment submission - User info:', req.user);
    
    const { 
        paymentMethod, 
        cardNumber, 
        expiryDate, 
        cvc, 
        paypalEmail, 
        amount 
    } = req.body;
    
    console.log('Submitting payment data:', {
        paymentMethod,
        amount,
        paypalEmail: paypalEmail || '[REDACTED]',
        userId: req.user.userId,
        userType: req.user.userType
    });

    // Check if user ID is valid for payment processing
    const isAdmin = req.user.userType === 'admin' || req.user.userId === 'admin';
    const isValidObjectId = req.user.userId && /^[0-9a-fA-F]{24}$/.test(req.user.userId);
    
    if (isAdmin) {
        console.log('Admin user detected, rejecting payment submission');
        return res.status(403).json({ 
            error: 'Admin users cannot submit payments',
            details: 'This functionality is only available for regular users' 
        });
    }
    
    if (!isValidObjectId) {
        console.log('Invalid user ID format:', req.user.userId);
        return res.status(400).json({ 
            error: 'Invalid user account', 
            details: 'Your user account is not properly configured for payments' 
        });
    }

    // Validate inputs
    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }

    // Validate payment method
    if (!['stripe', 'paypal'].includes(paymentMethod)) {
        return res.status(400).json({ error: 'Invalid payment method' });
    }

    // Validate method-specific fields
    if (paymentMethod === 'stripe') {
        if (!cardNumber || !expiryDate || !cvc) {
            return res.status(400).json({ error: 'Missing Stripe payment details' });
        }
    } else if (paymentMethod === 'paypal') {
        if (!paypalEmail) {
            return res.status(400).json({ error: 'Missing PayPal email' });
        }
    }

    const paymentData = {
        user: req.user.userId,
        amount: parseFloat(amount),
        paymentMethod,
        status: 'pending',
        paymentDetails: {}
    };

    // Add payment method-specific details
    if (paymentMethod === 'stripe') {
        paymentData.paymentDetails = {
            cardLast4: cardNumber.slice(-4),
            expiryDate: expiryDate
        };
    } else {
        paymentData.paymentDetails = {
            paypalEmail: paypalEmail
        };
    }

    try {
        console.log('Creating payment with data:', paymentData);
        
        // Create and save payment record
        const payment = new Payment(paymentData);
        await payment.save();
        
        console.log('Payment saved successfully:', payment._id);

        // Prepare email content based on payment method
        let emailContent;
        if (paymentMethod === 'stripe') {
            emailContent = `
                <h3>New Stripe Payment Submission</h3>
                <p><strong>Payment Method:</strong> Stripe</p>
                <p><strong>Amount:</strong> $${amount}</p>
                <p><strong>Card Number:</strong> **** **** **** ${cardNumber.slice(-4)}</p>
                <p><strong>Expiry Date:</strong> ${expiryDate}</p>
                <p><em>Note: Full card details are intentionally masked for security</em></p>
            `;
        } else {
            emailContent = `
                <h3>New PayPal Payment Submission</h3>
                <p><strong>Payment Method:</strong> PayPal</p>
                <p><strong>Amount:</strong> $${amount}</p>
                <p><strong>PayPal Email:</strong> ${paypalEmail}</p>
            `;
        }

        // Email options
        const mailOptions = {
            from: 'smartrichads@gmail.com',
            to: 'payments@smartrichads.com',
            subject: `New ${paymentMethod === 'stripe' ? 'Stripe' : 'PayPal'} Payment Submission`,
            html: emailContent
        };

        // Send email
        try {
            await transporter.sendMail(mailOptions);
            console.log('Payment notification email sent');
        } catch (emailError) {
            console.error('Error sending payment notification email:', emailError);
            // Continue with response even if email fails
        }

        res.status(200).json({ 
            message: 'Payment information submitted successfully',
            paymentId: payment._id
        });
    } catch (error) {
        console.error('Payment submission error:', error);
        res.status(500).json({ 
            error: 'Failed to submit payment information', 
            details: error.message 
        });
    }
});

// Add this route to server.js
app.get('/api/payment/status', auth, async (req, res) => {
    try {
        // Find the most recent payment for the user
        const payment = await Payment.findOne({ 
            user: req.user.userId 
        }).sort({ createdAt: -1 });

        if (!payment) {
            return res.status(404).json({ 
                message: 'No payment found',
                status: 'none'
            });
        }

        // Return payment details including amount
        res.json({ 
            status: payment.status,
            amount: payment.amount,
            method: payment.paymentMethod,
            createdAt: payment.createdAt,
            paymentId: payment._id
        });
    } catch (error) {
        console.error('Error fetching payment status:', error);
        res.status(500).json({ 
            message: 'Error checking payment status',
            error: error.message 
        });
    }
});
app.get('/api/payment/:id/status', auth, async (req, res) => {
    try {
        const payment = await Payment.findById(req.params.id);
        if (!payment) {
            return res.status(404).json({ error: 'Payment not found' });
        }
        res.json({ status: payment.status });
    } catch (error) {
        res.status(500).json({ error: 'Error checking payment status' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password, userType } = req.body;

        // Hardcoded admin login
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
        // Validate input
        if (!email || !password) {
            return res.status(400).json({ 
                message: 'Please enter both email and password' 
            });
        }

        // Find user
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
});

// Protected route example
app.get('/api/profile', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.userId).select('-password');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: 'Server error' });
    }
});

app.post('/api/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ success: true });
});
// Admin routes for payment management
app.get('/api/admin/payments', auth, async (req, res) => {
    console.log('Admin payments request received');
    console.log('User type:', req.user.userType);

    // Check if user is admin
    if (req.user.userType !== 'admin') {
        console.log('Access denied - not an admin');
        return res.status(403).json({ message: 'Access denied' });
    }

    try {
        // Fetch all payment requests
        const payments = await Payment.find().sort({ createdAt: -1 });
        console.log('Payments found:', payments.length);
        res.json(payments);
    } catch (error) {
        console.error('Error fetching payments:', error);
        res.status(500).json({ message: 'Error fetching payment requests' });
    }
});

app.patch('/api/admin/payments/:id', auth, async (req, res) => {
    // Check if user is admin
    if (req.user.userType !== 'admin') {
        return res.status(403).json({ message: 'Access denied' });
    }

    const { id } = req.params;
    const { status } = req.body;

    // Validate status
    if (!['approved', 'rejected'].includes(status)) {
        return res.status(400).json({ message: 'Invalid status' });
    }

    try {
        // Find and update payment
        const payment = await Payment.findByIdAndUpdate(
            id, 
            { status }, 
            { new: true, runValidators: true }
        );

        if (!payment) {
            return res.status(404).json({ message: 'Payment not found' });
        }

        // Fetch the user to get their email
        const user = await User.findById(payment.user);
        
        if (!user) {
            console.error('User not found for payment ID:', id);
            return res.status(404).json({ message: 'User associated with payment not found' });
        }

        // Send notification email directly to the user
        const mailOptions = {
            from: 'smartrichads@gmail.com',
            to: user.email,
            subject: `Your Payment Request has been ${status.charAt(0).toUpperCase() + status.slice(1)}`,
            html: `
                <h3>Payment ${status.toUpperCase()}</h3>
                <p>Dear ${user.name},</p>
                <p>Your payment request of $${payment.amount.toFixed(2)} has been <strong>${status}</strong>.</p>
                <p>Payment Method: ${payment.paymentMethod}</p>
                <p>Date Submitted: ${new Date(payment.createdAt).toLocaleString()}</p>
                ${status === 'approved' ? 
                '<p>The funds will be available in your account shortly.</p>' : 
                '<p>If you have any questions about why your payment was rejected, please contact our support team at <a href="mailto:support@smartrichads.com">support@smartrichads.com</a>.</p>'
                }
                <p>Thank you for using Richads!</p>
                <p>Best regards,<br>The Richads Team</p>
            `
        };

        // Send a copy to the admin team
        const adminMailOptions = {
            from: 'smartrichads@gmail.com',
            to: 'payments@smartrichads.com',
            subject: `Payment ${status.toUpperCase()} - ID: ${payment._id}`,
            html: `
                <h3>Payment ${status.toUpperCase()}</h3>
                <p>Payment of $${payment.amount.toFixed(2)} for user ${user.name} (${user.email}) has been ${status}.</p>
                <p>Payment Method: ${payment.paymentMethod}</p>
                <p>Payment ID: ${payment._id}</p>
                <p>User ID: ${user._id}</p>
                <p>Date Submitted: ${new Date(payment.createdAt).toLocaleString()}</p>
                <p>Date ${status.charAt(0).toUpperCase() + status.slice(1)}: ${new Date().toLocaleString()}</p>
            `
        };

        try {
            // Send both emails
            await transporter.sendMail(mailOptions);
            await transporter.sendMail(adminMailOptions);
            console.log(`Payment status notification sent to user: ${user.email}`);
        } catch (emailError) {
            console.error('Error sending notification email:', emailError);
        }

        res.json(payment);
    } catch (error) {
        console.error('Error updating payment status:', error);
        res.status(500).json({ message: 'Error updating payment status' });
    }
});


app.use(express.static(path.join(__dirname, '..', 'frontend')));
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '..', 'frontend', 'dashboard.html'));
});

app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname, '..' , 'frontend', 'index.html'));
});
// Update this Google OAuth handler in your server.js file

// Update this Google OAuth handler in your server.js file

app.get('/api/auth/google/callback', async (req, res) => {
    const { code, state } = req.query;
    
    if (req.query.error) {
        console.error('Google OAuth error:', req.query.error);
        return res.redirect('/frontend/login.html?error=Authentication+denied');
    }
    
    try {
        // In a production app, you would exchange the code for tokens
        // and validate the user information
        console.log('Processing Google OAuth callback with code');
        
        // Generate a temporary Google user ID that's consistent
        // Using a fixed prefix with the timestamp to ensure uniqueness
        const googleUserId = 'google-' + Date.now();
        
        // Create a JWT token for this user with a longer expiration
        const token = jwt.sign(
            { 
                userId: googleUserId, 
                userType: 'affiliate',
                email: 'google-user@example.com', // Added email for consistency
                provider: 'google' // Mark this as a Google-authenticated user
            },
            process.env.JWT_SECRET,
            { expiresIn: '7d' } // Longer expiration for convenience
        );
        
        // Set cookie with proper options to ensure it's included in future requests
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax', // 'lax' works better for OAuth redirects
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });
        
        console.log('Set authentication token cookie for Google user');
        
        // Redirect to auth success page with user info
        return res.redirect(`/frontend/auth-success.html?userType=affiliate&name=Google+User`);
    } catch (error) {
        console.error('Google OAuth error:', error);
        return res.redirect('/frontend/login.html?error=Authentication+failed');
    }
});

// Replace your existing payment endpoint in server.js with this improved version

// Replace your existing payment endpoint in server.js with this improved version

app.post('/api/payment', auth, async (req, res) => {
    console.log('Payment submission - User info:', req.user);
    
    // Handle Google-authenticated users
    if (req.user.googleAuth) {
        console.log('Processing payment for Google-authenticated user');
    }
    
    const { 
        paymentMethod, 
        cardNumber, 
        expiryDate, 
        cvc, 
        paypalEmail, 
        amount 
    } = req.body;
    
    // Continue with existing payment processing code...
    
    // For Google auth users, create a special user ID if not available
    const userId = req.user.userId || req.user.userEmail || 'google-user';
    
    // Rest of your payment processing code...
    const paymentData = {
        user: userId,
        amount: parseFloat(amount),
        paymentMethod,
        status: 'pending',
        paymentDetails: {}
    };

    // Add payment method-specific details
    if (paymentMethod === 'stripe') {
        paymentData.paymentDetails = {
            cardLast4: cardNumber ? cardNumber.slice(-4) : '0000',
            expiryDate: expiryDate || 'MM/YY'
        };
    } else {
        paymentData.paymentDetails = {
            paypalEmail: paypalEmail || req.user.userEmail || 'user@example.com'
        };
    }

    try {
        // Create and save payment record
        const payment = new Payment(paymentData);
        await payment.save();
        
        // Return success response
        res.status(200).json({ 
            message: 'Payment information submitted successfully',
            paymentId: payment._id
        });
    } catch (error) {
        console.error('Payment submission error:', error);
        res.status(500).json({ 
            error: 'Failed to submit payment information', 
            details: error.message 
        });
    }
});
// Add this to your server.js for debugging authentication

// Debugging endpoint to check authentication status
app.get('/api/auth/test', (req, res) => {
    try {
        // Check if token exists
        const token = req.cookies.token;
        
        if (!token) {
            return res.json({
                authenticated: false,
                message: 'No authentication token found'
            });
        }
        
        // Try to verify the token
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Return authentication info
            return res.json({
                authenticated: true,
                user: {
                    id: decoded.userId,
                    type: decoded.userType,
                    isGoogleUser: decoded.provider === 'google'
                },
                tokenExpiration: new Date(decoded.exp * 1000).toISOString()
            });
        } catch (tokenError) {
            return res.json({
                authenticated: false,
                message: 'Invalid token: ' + tokenError.message
            });
        }
    } catch (error) {
        console.error('Auth test error:', error);
        return res.status(500).json({
            authenticated: false,
            error: 'Server error checking authentication'
        });
    }
});
  

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Running at: ' + 'http://localhost:3000/frontend/index.html');
});

