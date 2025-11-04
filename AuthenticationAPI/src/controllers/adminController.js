const Admin = require('../models/Admin');
const User = require('../models/User');
const { validateEmail, validatePassword, validateName, sanitizeInput } = require('../utils/validators');

const loginAdmin = async (req, res) => {
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
};

const registerAdmin = async (req, res) => {
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
        
        // Move this to environment variable in production
        const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || 'ADMIN_SECRET_KEY';
        
        if (secretKey !== ADMIN_SECRET) {
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
};

const deleteAllRecords = async (req, res) => {
    try {
        const userCount = await User.countDocuments();
        const adminCount = await Admin.countDocuments();
        
        const deletedUsers = await User.deleteMany({});
        
        const deletedAdmins = await Admin.deleteMany({});
        
        console.log(`[CRITICAL] All records deleted by admin: ${req.admin.email}`);
        console.log(`Users deleted: ${deletedUsers.deletedCount}, Admins deleted: ${deletedAdmins.deletedCount}`);
        
        res.json({
            message: 'All records deleted successfully',
            deleted: {
                users: deletedUsers.deletedCount,
                admins: deletedAdmins.deletedCount
            },
            previousCounts: {
                users: userCount,
                admins: adminCount
            },
            deletedBy: {
                email: req.admin.email,
                name: req.admin.name
            },
            timestamp: new Date()
        });
    } catch (error) {
        console.error('Error deleting records:', error);
        res.status(500).json({ error: 'Server error during deletion' });
    }
};

module.exports = {
    loginAdmin,
    registerAdmin,
    deleteAllRecords
};