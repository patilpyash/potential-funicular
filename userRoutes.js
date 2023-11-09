// userRoutes.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
const { generateToken, authenticateToken } = require('./auth');
const { sendResetTokenEmail } = require('./email');

const router = express.Router();

router.post('/register', (req, res) => {
    // get user data from request
    const { name, email, password } = req.body;

    // validate
    if (!name || !email || !password) {
        return res.status(400).json({ msg: 'Please enter all fields' });
    }

    // Hash the password before storing it
    bcrypt.hash(password, 10, (hashErr, hashedPassword) => {
        if (hashErr) {
            return res.status(500).json({ msg: hashErr });
        }

        const newUser = { name, email, password: hashedPassword };
        db.query('INSERT INTO users SET ?', newUser, (err, result) => {
            if (err) {
                return res.status(500).json({ msg: err });
            }
            return res.json({ msg: 'User registered!' });
        });
    });
});

router.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ msg: 'Please enter your email address' });
    }

    // Check if the user exists
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) {
            return res.status(500).json({ msg: err });
        }

        if (result.length === 0) {
            return res.status(404).json({ msg: 'User not found!' });
        }

        const user = result[0];

        // Generate a unique reset token (e.g., a random string)
        const resetToken = generateResetToken();

        // Store the reset token and its expiration time in the database
        const resetTokenExpiration = new Date();
        resetTokenExpiration.setHours(resetTokenExpiration.getHours() + 1); // Token expires in 1 hour
        db.query('UPDATE users SET reset_token = ?, reset_token_expiration = ? WHERE email = ?', [resetToken, resetTokenExpiration, user.email], (updateErr, updateResult) => {
            if (updateErr) {
                return res.status(500).json({ msg: updateErr });
            }

            // Send the reset token to the user's email (you should implement email sending here)
            sendResetTokenEmail(email, resetToken);

            return res.json({ msg: 'Password reset token sent to your email' });
        });
    });
});

router.post('/reset-password', (req, res) => {
    const { email, resetToken, newPassword } = req.body;

    if (!email || !resetToken || !newPassword) {
        return res.status(400).json({ msg: 'Please enter your email, reset token, and new password' });
    }

    // Check if the user exists
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) {
            return res.status(500).json({ msg: err });
        }

        if (result.length === 0) {
            return res.status(404).json({ msg: 'User not found!' });
        }

        const user = result[0];

        // Check if the reset token and its expiration time are valid
        if (user.reset_token !== resetToken || new Date() > user.reset_token_expiration) {
            return res.status(401).json({ msg: 'Invalid or expired reset token' });
        }

        // Hash the new password
        bcrypt.hash(newPassword, 10, (hashErr, hashedPassword) => {
            if (hashErr) {
                return res.status(500).json({ msg: hashErr });
            }

            // Update the user's password and clear the reset token in the database
            db.query('UPDATE users SET password = ?, reset_token = NULL, reset_token_expiration = NULL WHERE email = ?', [hashedPassword, user.email], (updateErr, updateResult) => {
                if (updateErr) {
                    return res.status(500).json({ msg: updateErr });
                }

                return res.json({ msg: 'Password reset successfully' });
            });
        });
    });
});

router.post('/login', (req, res) => {
     // get user data from request
     const { email, password } = req.body;

     // validate
     if (!email || !password) {
         return res.status(400).json({ msg: 'Please enter email and password' });
     }
 
     // check if user exists
     db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
         if (err) {
             return res.status(500).json({ msg: err });
         }
         if (result.length === 0) {
             return res.status(401).json({ msg: 'User not found!' });
         }
 
         const user = result[0];
 
         // Compare hashed password
         bcrypt.compare(password, user.password, (bcryptErr, passwordMatch) => {
             if (bcryptErr || !passwordMatch) {
                 return res.status(401).json({ msg: 'Invalid credentials!' });
             }
 
             // Set token expiration to 1 minute (60 seconds) from the current time
             const token = jwt.sign(
                 {
                     id: user.id,
                     name: user.name,
                     email: user.email,
                     exp: Math.floor(Date.now() / 1000) + 60,
                 },
                 'secretkey'
             );
             return res.json({
                 token,
                 user: {
                     id: user.id,
                     name: user.name,
                     email: user.email,
                 },
             });
         });
     });
});

router.get('/user', authenticateToken, (req, res) => {
    // get user data from JWT token
    const user = req.user;

    // send user's information
    res.json({ user });
});

module.exports = router;
