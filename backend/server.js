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
const auth = async (req, res, next) => {
    try {
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ message: 'Authentication required' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Invalid token' });
    }
};

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
// Routes
app.post('/api/signup', async (req, res) => {
    try {
        const { name, email, password, userType } = req.body;

        // Validate input
        if (!name || !email || !password || !userType) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already registered' });
        }

        // Create user
        const user = new User({
            name,
            email,
            password, // Will be hashed by pre-save middleware
            userType
        });

        await user.save();

        res.status(201).json({ 
            success: true,
            message: 'Registration successful! Please login.' 
        });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Server error during registration' });
    }
});

app.post('/api/payment', async (req, res) => {
    const { 
        paymentMethod, 
        cardNumber, 
        expiryDate, 
        cvc, 
        paypalEmail, 
        amount 
    } = req.body;

    // Validate inputs
    if (!amount || amount <= 0) {
        return res.status(400).json({ error: 'Invalid amount' });
    }

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

    try {
        // Send email
        await transporter.sendMail(mailOptions);
        res.status(200).json({ message: 'Payment information submitted successfully' });
    } catch (error) {
        console.error('Error sending payment email:', error);
        res.status(500).json({ error: 'Failed to submit payment information' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password, userType } = req.body;

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


app.use(express.static(path.join(__dirname, '..', 'frontend')));

app.get('/', function(req, res) {
    res.sendFile(path.join(__dirname, '..' , 'frontend', 'index.html'));
});

  

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log('Running at: ' + 'http://localhost:3000/frontend/index.html');
});

