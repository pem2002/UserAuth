const express = require('express');
const authController = require('../Controllers/authController');    
const router = express.Router();

// Root route
router.get('/', (req, res) => {
    res.render('pages/landing');
});

// Signup routes
router.get('/signup', authController.getSignUp);
router.post('/signup', authController.postSignUp);

// Email verification
router.get('/verify-email', authController.verifyEmail);

// Login routes
router.get('/login', authController.getLogin);  
router.post('/login', authController.postLogin);

//forgot password route
router.get('/forgot-password', authController.getForgotPassword);
router.post('/forgot-password', authController.postForgotPassword);
router.get('/reset-password', authController.getForgotPassword);
router.post('/reset-password', authController.resetPassword);

//logout route
router.get('/logout', authController.logout);

router.get('/user/dashboard',authController.getResetPassword);
router.post('/user/dashboard',authController.resetPassword); 

module.exports = router;
