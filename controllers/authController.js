const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('../Config/db');
const nodemailer = require('nodemailer');
require('dotenv').config();

const saltRounds = 10;

// Render the sign up page
exports.getSignUp = (req, res) => {
    res.render('pages/signup', {message: null});
}

//email transporter setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});


// handles sign up logic
exports.postSignUp = async (req, res) => {
    const { name, email, password, role } = req.body;
    try {
        // Check if user already exists
        const existingUser = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (existingUser) {
            return res.render('pages/signup', { message: 'Email already Regestered' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Generate verification token
        const verificationToken = jwt.sign({ email }, process.env.JWT_SECRET, { expiresIn: '1h' });

        //insert user into the database
        await db.none(
            `INSERT INTO users (name, email, password, role, verification_token) VALUES ($1, $2, $3, $4, $5)`,
            [name, email, hashedPassword, role, verificationToken]
        )

        // Send verification email
        const verificationLink = `${process.env.BASE_URL}/verify-email?token=${verificationToken}`;

        await transporter.sendMail({
            from: `"Bootcamp Auth" <${process.env.EMAIL}>`,
            to: email,
            subject: 'Email Verification',
            html: `<p>Hi ${name},</p>
                   <p>Thank you for signing up! Please verify your email by clicking the link below:</p>
                   <a href="${verificationLink}">Verify Email</a>
                   <p>If you did not sign up, please ignore this email.</p>`
        });
        res.render('pages/signup', { message: 'Registration successful! Please check your email to verify your account.' });
    }catch (error) {
        console.error('Error during sign up:', error);
        res.render('pages/signup', { message: 'An error occurred during registration. Please try again.' });

    }
}

//Email verification route
exports.verifyEmail = async (req, res) => {
    const { token } = req.query;

    try {
        const decode = jwt.verify(token, process.env.JWT_SECRET);
        const email = decode.email;

        await db.none(`UPDATE users SET is_verified = true, verification_token = NULL WHERE email = $1`, [email]);
        res.send('Email verified successfully! You can now log in.');
    } catch (error) {
        res.send('Invalid or expired verification link')
    }
}

// get login 
exports.getLogin = (req, res) => {
    res.render('pages/login', { message: null });
}

// handles login logic
exports.postLogin = async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (!user) {
            return res.render('pages/login', { message: 'Invalid email or password' });
        }
        if (!user.is_verified) {
            return res.render('pages/login', { message: 'Please verify your email before logging in.' });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render('pages/login', { message: 'Invalid email or password' });
        }

        // Create JWT token
        const token = jwt.sign({ 
            id: user.id, email: user.email, role: user.role }, 
            process.env.JWT_SECRET, 
            { expiresIn: '1h' });

        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 3600000 // 1 hour
        });

        // Redirect based on user role
        if (user.role === 'admin') {
            res.redirect('/admin/dashboard');
        } else {
            res.redirect('/user/dashboard');
        }

    }catch(error) {
        console.error('Error during login:', error);
        res.render('pages/login', { message: 'An error occurred during login. Please try again.' });
        }
        
    }

//render forgot password page
exports.getForgotPassword = (req, res) => {
    res.render('pages/forgot-password', { message: null });
}


//handles forgot password logic
exports.postForgotPassword = async (req, res) => {
    const { email } = req.body;

    try {
        const user = await db.oneOrNone('SELECT * FROM users WHERE email = $1', [email]);
        if (!user) {
            return res.render('pages/forgot-password', { message: 'Email not registered' });
        }

        //generate reset token
        const resetToken = jwt.sign({email: user.email}, process.env.JWT_SECRET, { expiresIn: '1h' });

        //store reset token in the database
        await db.none('UPDATE users SET reset_token = $1 WHERE email = $2', [resetToken, email]);

        //send reset email
        const resetLink = `${process.env.BASE_URL}/reset-password?token=${resetToken}`;
        const mailOptions = {
            from: `"Bootcamp Auth" <${process.env.EMAIL}>`,
            to: email,
            subject: 'Password Reset',
            html: `<p>Hi ${user.name},</p>
                   <p>You requested a password reset. Please click the link below to reset your password:</p>
                   <a href="${resetLink}">Reset Password</a>
                   <p>If you did not request this, please ignore this email.</p>`
        };

        await transporter.sendMail(mailOptions);
        res.render('pages/forgot-password', { message: 'Password reset link sent to your email.' });

    } catch (error) {
        console.error('Error during forgot password:', error);
        res.render('pages/forgot-password', { message: 'An error occurred. Please try again.' });
    }
}  

//render reset password page
exports.getResetPassword = (req, res) =>{
    const {token} = req.query;
    res.render('pages/reset-password',{token, message: null});
};

//Reset password logic 
exports.resetPassword = async (req, res) => {
    const {token, newPassword} = req.body;

    try{
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await dbdb.oneOrNone(`SELECT * FROM users WHERE reset_token = $1`, [token]);

        if (!user) {
            return res.render('pages/reset-password', { message: 'Invalid or expired token' });
        }

        //Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        //Update the users's password and clear the reset token
        await db.none('UPDATE users SET password = $1, reset_token = NULL WHERE email = $2', [hashedPassword, user.email]);

        res.render('pages/reset-password', { message: 'Password reset successfully! You can now log in.',token: '' });
    }catch (error){
        consosle.error('Error during password reset:', error);
        res.render('pages/reset-password', { message: 'Invalid or expired token' });
    }
}

//logic for logout
exports.logout = (req, res) => {
    try{
        res.clearCookie('token');
        res.redirect('/login');
    } catch (error) {
        console.error('Error during logout:', error);
        res.status(500).send('An error occurred while logging out.');
    }
}