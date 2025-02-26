// Enhanced auth middleware to debug token handling
const jwt = require('jsonwebtoken');

const auth = async (req, res, next) => {
    try {
        console.log('Auth middleware running');
        console.log('Cookies:', req.cookies);
        
        // Check for token in cookies first
        let token = req.cookies.token;
        console.log('Token from cookies:', token ? 'Found' : 'Not found');
        
        // If no token in cookies, check Authorization header (for API requests)
        if (!token && req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
            token = req.headers.authorization.split(' ')[1];
            console.log('Token from Authorization header:', token ? 'Found' : 'Not found');
        }
        
        if (!token) {
            console.log('No token found in request');
            return res.status(401).json({ message: 'Authentication required' });
        }
        
        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            console.log('Token successfully verified:', decoded);
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

module.exports = auth;