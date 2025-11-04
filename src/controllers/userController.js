const User = require('../models/User');
const { validateEmail, validatePassword, validateName, sanitizeInput } = require('../utils/validators');

const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const sanitizedEmail = sanitizeInput(email);
        
        if (!validateEmail(sanitizedEmail)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        const user = await User.findOne({ email: sanitizedEmail });
        
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const isPasswordValid = await user.comparePassword(password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        user.lastLogin = new Date();
        await user.save();
        
        res.json({ 
            message: 'User logged in!', 
            email: user.email,
            name: user.name
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
};

const registerUser = async (req, res) => {
    try {
        const { email, password, name } = req.body;
        
        if (!email || !password || !name) {
            return res.status(400).json({ error: 'Email, password and name required' });
        }
        
        const sanitizedEmail = sanitizeInput(email);
        const sanitizedName = sanitizeInput(name);
        
        if (!validateEmail(sanitizedEmail)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        if (!validateName(sanitizedName)) {
            return res.status(400).json({ error: 'Invalid name. Use only letters and spaces (2-50 characters)' });
        }
        
        const passwordCheck = validatePassword(password);
        if (!passwordCheck.isValid) {
            const errorMessages = [];
            if (passwordCheck.errors.minLength) errorMessages.push('at least 8 characters');
            if (passwordCheck.errors.hasUpperCase) errorMessages.push('one uppercase letter');
            if (passwordCheck.errors.hasLowerCase) errorMessages.push('one lowercase letter');
            if (passwordCheck.errors.hasNumber) errorMessages.push('one number');
            if (passwordCheck.errors.hasSpecialChar) errorMessages.push('one special character');
            
            return res.status(400).json({ 
                error: 'Password must contain: ' + errorMessages.join(', ')
            });
        }
        
        const existingUser = await User.findOne({ email: sanitizedEmail });
        if (existingUser) {
            return res.status(409).json({ error: 'Email already registered' });
        }
        
        const user = new User({
            name: sanitizedName,
            email: sanitizedEmail,
            password: password
        });
        
        await user.save();
        
        res.status(201).json({ 
            message: 'User registered!', 
            email: user.email, 
            name: user.name 
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
};

module.exports = {
    loginUser,
    registerUser
};