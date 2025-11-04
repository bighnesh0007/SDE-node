const Admin = require('../models/Admin');
const { validateEmail, sanitizeInput } = require('../utils/validators');

const verifyAdminAccess = async (req, res, next) => {
    try {
        const { adminEmail, adminPassword, secretKey } = req.body;
        
        if (!adminEmail || !adminPassword || !secretKey) {
            return res.status(400).json({ 
                error: 'Admin email, password, and secret key required for this operation' 
            });
        }
        
        const sanitizedEmail = sanitizeInput(adminEmail);
        
        if (!validateEmail(sanitizedEmail)) {
            return res.status(400).json({ error: 'Invalid email format' });
        }
        
        const ADMIN_SECRET = process.env.ADMIN_SECRET_KEY || 'ADMIN_SECRET_KEY';
        if (secretKey !== ADMIN_SECRET) {
            return res.status(403).json({ error: 'Invalid secret key' });
        }
        
        const admin = await Admin.findOne({ email: sanitizedEmail });
        
        if (!admin) {
            return res.status(401).json({ error: 'Invalid admin credentials' });
        }
        
        if (!admin.isActive) {
            return res.status(403).json({ error: 'Admin account is deactivated' });
        }
        
        const isPasswordValid = await admin.comparePassword(adminPassword);
        
        if (!isPasswordValid) {
            return res.status(401).json({ error: 'Invalid admin credentials' });
        }
        
        if (!admin.permissions.includes('delete')) {
            return res.status(403).json({ error: 'Admin does not have delete permissions' });
        }
        
        req.admin = {
            id: admin._id,
            email: admin.email,
            name: admin.name,
            permissions: admin.permissions
        };
        
        next();
    } catch (error) {
        console.error('Admin verification error:', error);
        res.status(500).json({ error: 'Server error during admin verification' });
    }
};

module.exports = {
    verifyAdminAccess
};