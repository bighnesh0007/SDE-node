const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const app = express();
const PORT = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

mongoose.connect('mongodb://localhost:27017/authDB', {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: 2,
        maxlength: 50
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    }
});

const adminSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true,
        minlength: 2,
        maxlength: 50
    },
    email: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        lowercase: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        default: 'admin',
        immutable: true
    },
    permissions: [{
        type: String,
        enum: ['read', 'write', 'delete', 'manage_users']
    }],
    createdAt: {
        type: Date,
        default: Date.now
    },
    lastLogin: {
        type: Date
    },
    isActive: {
        type: Boolean,
        default: true
    }
});

userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

adminSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    this.password = await bcrypt.hash(this.password, 10);
    next();
});

userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

adminSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);
const Admin = mongoose.model('Admin', adminSchema);

const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

const validatePassword = (password) => {
    const minLength = 8;
    const hasUpperCase = /[A-Z]/.test(password);
    const hasLowerCase = /[a-z]/.test(password);
    const hasNumber = /[0-9]/.test(password);
    const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    return {
        isValid: password.length >= minLength && hasUpperCase && hasLowerCase && hasNumber && hasSpecialChar,
        errors: {
            minLength: password.length < minLength,
            hasUpperCase: !hasUpperCase,
            hasLowerCase: !hasLowerCase,
            hasNumber: !hasNumber,
            hasSpecialChar: !hasSpecialChar
        }
    };
};

const validateName = (name) => {
    const nameRegex = /^[a-zA-Z\s]{2,50}$/;
    return nameRegex.test(name);
};

const sanitizeInput = (input) => {
    return input.trim().replace(/[<>]/g, '');
};

app.get('/', (req, res) => {
    res.send('Hello World!');
});

app.post('/user/login', async (req, res) => {
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
});

app.post('/user/register', async (req, res) => {
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
});

app.post('/admin/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
            return res.status(400).json({ error: 'Email and password required' });
        }
        
        const sanitizedEmail = sanitizeInput(email);
        
        if (!validateEmail(sanitizedEmail)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        const admin = await Admin.findOne({ email: sanitizedEmail });
        
        if (!admin) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        if (!admin.isActive) {
            return res.status(403).json({ error: 'Account is deactivated' });
        }
        
        const isPasswordValid = await admin.comparePassword(password);
        
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        admin.lastLogin = new Date();
        await admin.save();
        
        res.json({ 
            message: 'Admin logged in!', 
            email: admin.email, 
            name: admin.name,
            role: admin.role,
            permissions: admin.permissions
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/admin/register', async (req, res) => {
    try {
        const { email, password, name, secretKey } = req.body;
        
        if (!email || !password || !name || !secretKey) {
            return res.status(400).json({ error: 'Email, password, name and secretKey required' });
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
        
        if (secretKey !== 'ADMIN_SECRET_KEY') {
            return res.status(403).json({ error: 'Invalid secret key' });
        }
        
        const existingAdmin = await Admin.findOne({ email: sanitizedEmail });
        if (existingAdmin) {
            return res.status(409).json({ error: 'Email already registered' });
        }
        
        const admin = new Admin({
            name: sanitizedName,
            email: sanitizedEmail,
            password: password,
            permissions: ['read', 'write', 'delete', 'manage_users']
        });
        
        await admin.save();
        
        res.status(201).json({ 
            message: 'Admin registered!', 
            email: admin.email, 
            name: admin.name, 
            role: admin.role 
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});