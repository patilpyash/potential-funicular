// dependencies
const express = require('express');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt'); // Adding bcrypt for password hashing
const { swaggerUi, swaggerSpec } = require('./swagger'); // Import your Swagger configuration


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
            const token = jwt.sign({ id: user.id, exp: Math.floor(Date.now() / 1000) + 60 }, 'secretkey');
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

    // send user's email
    res.json({ email: user.email });
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
// start server
app.listen(3000, () => {
    console.log('Server started on port 3000');
});
