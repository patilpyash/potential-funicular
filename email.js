// email.js
const nodemailer = require('nodemailer');

function sendResetTokenEmail(email, resetToken) {
    // ... (implementation of email sending logic)
    console.log(resetToken);
}

module.exports = {
    sendResetTokenEmail
};
