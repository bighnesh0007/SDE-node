const express = require('express');
const router = express.Router();
const { loginAdmin, registerAdmin, deleteAllRecords } = require('../controllers/adminController');
const { verifyAdminAccess } = require('../middlewares/auth');

router.post('/login', loginAdmin);
router.post('/register', registerAdmin);


router.delete('/delete-all-records', verifyAdminAccess, deleteAllRecords);

module.exports = router;