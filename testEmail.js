const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  tls: {
    rejectUnauthorized: false, // for local development only
  },
});

const mailOptions = {
  from: `"Bootcamp Auth Test" <${process.env.EMAIL_USER}>`,
  to: 'your-other-email@example.com', // 🔁 replace this with a real test email
  subject: 'Test Email from Node App',
  html: '<p>This is a test email sent from your Node.js app!</p>',
};

transporter.sendMail(mailOptions, (error, info) => {
  if (error) {
    return console.error('❌ Email send failed:', error);
  }
  console.log('✅ Email sent:', info.response);
});
