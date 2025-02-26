// Simple auth handler for Richads application
const authHandler = {
    // Simple function to check if user is logged in
    isLoggedIn: function() {
      return document.cookie.includes('token=');
    },
    
    // Simple logout function
    logout: function() {
      // Clear localStorage
      localStorage.removeItem('userType');
      localStorage.removeItem('userName');
      
      // Call the logout API
      fetch('/api/logout', {
        method: 'POST',
        credentials: 'include'
      }).then(() => {
        // Redirect to login page
        window.location.href = '/frontend/login.html';
      }).catch(error => {
        console.error('Logout error:', error);
        // Redirect anyway
        window.location.href = '/frontend/login.html';
      });
    },
    
    // Process OAuth redirect
    processOAuthRedirect: function() {
      // Check if we have a code parameter (OAuth callback)
      const urlParams = new URLSearchParams(window.location.search);
      const code = urlParams.get('code');
      
      if (code) {
        console.log('Processing OAuth redirect');
        
        // Clean up URL
        const cleanUrl = window.location.origin + window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);
        
        return true;
      }
      
      return false;
    }
    
  };
  // Updated Google OAuth callback route in authRoutes.js

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
        // Updated to include email and googleAuth flag
        return res.redirect(
            `/frontend/auth-success.html?userType=${user.userType}&name=${encodeURIComponent(user.name)}&email=${encodeURIComponent(email)}&googleAuth=true`
        );
    } catch (error) {
        console.error('Google OAuth error:', error);
        return res.redirect('/frontend/login.html?error=Authentication+failed');
    }
});