// dependencies
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // Adding bcrypt for password hashing
const { swaggerUi, swaggerSpec } = require('./swagger'); // Import your Swagger configuration
const crypto = require('crypto'); // Import the crypto module for generating tokens



// create connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'backend',
    password: '123456',
    database: 'eb1'
});

// connect to database
db.connect((err) => {
    if (err) {
        console.error('Database connection error: ' + err.message);
    } else {
        console.log('Connected to the database');
    }
});

// create Express app
const app = express();
app.use(express.json()); // Parse JSON request bodies
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// register route
/**
 * @openapi
 * /register:
 *   post:
 *     summary: Register a new user
 *     description: Register a new user with a name, email, and password.
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *     responses:
 *       '200':
 *         description: User registered successfully
 *       '400':
 *         description: Bad request
 */
app.post('/register', (req, res) => {
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

/**
 * @openapi
 * /forgot-password:
 *   post:
 *     summary: Request password reset
 *     description: Request a password reset by providing your email address. A reset token will be sent to your email.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Password reset token sent to your email
 *       '400':
 *         description: Bad request (missing or invalid parameters)
 *       '404':
 *         description: User not found
 *       '500':
 *         description: Internal server error
 */
app.post('/forgot-password', (req, res) => {
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

/**
 * @openapi
 * /reset-password:
 *   post:
 *     summary: Reset user password
 *     description: Reset a user's password by providing a valid reset token, email, and a new password.
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               resetToken:
 *                 type: string
 *               newPassword:
 *                 type: string
 *     responses:
 *       '200':
 *         description: Password reset successful
 *       '400':
 *         description: Bad request (missing or invalid parameters)
 *       '401':
 *         description: Unauthorized (invalid or expired reset token)
 *       '500':
 *         description: Internal server error
 */
app.post('/reset-password', (req, res) => {
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

// Placeholder function to send the reset token to the user's email
function sendResetTokenEmail(email, resetToken) {
    // Implement your email sending logic here
    // You might want to use a library like Nodemailer to send emails
    // Example Nodemailer code:
    /*
    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
        service: 'your-email-service-provider',
        auth: {
            user: 'your-email@example.com',
            pass: 'your-email-password'
        }
    });

    const mailOptions = {
        from: 'your-email@example.com',
        to: email,
        subject: 'Password Reset Token',
        text: `Your password reset token is: ${resetToken}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error);
        } else {
            console.log('Email sent: ' + info.response);
        }
    });
    */
    console.log(resetToken)
}

// login route
/**
 * @openapi
 * /login:
 *   post:
 *     summary: User login
 *     description: Authenticate and log in a user with their email and password.
 *     requestBody:
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               email:
 *                 type: string
 *               password:
 *                 type: string
 *               stayLoggedIn:
 *                 type: boolean  // Add a new field for "Stay Logged In"
 *     responses:
 *       '200':
 *         description: User logged in successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 token:
 *                   type: string
 *                 user:
 *                   type: object
 *                   properties:
 *                     id:
 *                       type: number
 *                     name:
 *                       type: string
 *                     email:
 *                       type: string
 *       '400':
 *         description: Bad request
 *       '401':
 *         description: Unauthorized (Invalid credentials)
 *       '500':
 *         description: Internal server error
 */
app.post('/login', (req, res) => {
    // get user data from request
    const { email, password, stayLoggedIn } = req.body;

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

            // Set token expiration to 1 minute if not staying logged in, otherwise, set it to a longer duration
            const expiresIn = stayLoggedIn ? '7d' : '1m';

            // Sign JWT token
            const token = jwt.sign(
                {
                    id: user.id,
                    name: user.name,
                    email: user.email,
                },
                'secretkey',
                { expiresIn }
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


// protected route
app.get('/user', authenticateToken, (req, res) => {
    // get user data from JWT token
    const user = req.user;

    // send user's information
    res.json({ user });
});


function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ msg: 'No token found!' });
    }

    // Verify JWT token
    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) {
            return res.status(403).json({ msg: 'Invalid or expired token!' });
        }

        // Check if the token has expired
        if (user.exp && Date.now() >= user.exp * 1000) {
            return res.status(403).json({ msg: 'Token has expired!' });
        }

        req.user = user;
        next();
    });
}

// Function to generate a random reset token
function generateResetToken() {
    // You can use a library like 'crypto' to generate a secure random token
    const token = require('crypto').randomBytes(32).toString('hex');
    return token;
}
// start server
app.listen(3000, () => {
    console.log('Server started on port 3000');
});
