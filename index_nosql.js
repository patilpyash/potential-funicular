const express = require('express');
const { MongoClient ,ServerApiVersion} = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { swaggerUi, swaggerSpec } = require('./swagger');
const crypto = require('crypto');


// Start server
const app = express();
app.use(express.json());
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// Connect to MongoDB
// const client = new MongoClient('mongodb://localhost:27017', { useNewUrlParser: true, useUnifiedTopology: true });

const uri = "mongodb+srv://patilpyash:yash8920@cluster-0.ivvahco.mongodb.net/?retryWrites=true&w=majority";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});



client.connect((err) => {
    if (err) {
        console.error('Database connection error: ' + err.message);
    } else {
        console.log('Connected to the database');
    }
});

const db = client.db('eb1');

// Register route
app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ msg: 'Please enter all fields' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = { name, email, password: hashedPassword };
        await db.collection('users').insertOne(newUser);

        return res.json({ msg: 'User registered!' });
    } catch (err) {
        return res.status(500).json({ msg: err.message });
    }
});

// Forgot Password route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ msg: 'Please enter your email address' });
    }

    try {
        const user = await db.collection('users').findOne({ email });

        if (!user) {
            return res.status(404).json({ msg: 'User not found!' });
        }

        const resetToken = generateResetToken();
        const resetTokenExpiration = new Date();
        resetTokenExpiration.setHours(resetTokenExpiration.getHours() + 1);

        await db.collection('users').updateOne(
            { email },
            { $set: { reset_token: resetToken, reset_token_expiration: resetTokenExpiration } }
        );

        sendResetTokenEmail(email, resetToken);

        return res.json({ msg: 'Password reset token sent to your email' });
    } catch (err) {
        return res.status(500).json({ msg: err.message });
    }
});

// Reset Password route
app.post('/reset-password', async (req, res) => {
    const { email, resetToken, newPassword } = req.body;

    if (!email || !resetToken || !newPassword) {
        return res.status(400).json({ msg: 'Please enter your email, reset token, and new password' });
    }

    try {
        const user = await db.collection('users').findOne({ email });

        if (!user || user.reset_token !== resetToken || new Date() > user.reset_token_expiration) {
            return res.status(401).json({ msg: 'Invalid or expired reset token' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        await db.collection('users').updateOne(
            { email },
            { $set: { password: hashedPassword, reset_token: null, reset_token_expiration: null } }
        );

        return res.json({ msg: 'Password reset successfully' });
    } catch (err) {
        return res.status(500).json({ msg: err.message });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { email, password, stayLoggedIn } = req.body;

    if (!email || !password) {
        return res.status(400).json({ msg: 'Please enter email and password' });
    }

    try {
        const user = await db.collection('users').findOne({ email });

        if (!user) {
            return res.status(401).json({ msg: 'User not found!' });
        }

        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).json({ msg: 'Invalid credentials!' });
        }

        const expiresIn = stayLoggedIn ? '7d' : '1m';

        const token = jwt.sign(
            { id: user._id, name: user.name, email: user.email },
            'secretkey',
            { expiresIn }
        );

        return res.json({
            token,
            user: { id: user._id, name: user.name, email: user.email },
        });
    } catch (err) {
        return res.status(500).json({ msg: err.message });
    }
});

// Protected route
app.get('/user', authenticateToken, (req, res) => {
    const user = req.user;
    res.json({ user });
});

// Authentication middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) {
        return res.status(401).json({ msg: 'No token found!' });
    }

    jwt.verify(token, 'secretkey', (err, user) => {
        if (err) {
            return res.status(403).json({ msg: 'Invalid or expired token!' });
        }

        if (user.exp && Date.now() >= user.exp * 1000) {
            return res.status(403).json({ msg: 'Token has expired!' });
        }

        req.user = user;
        next();
    });
}

// Function to generate a random reset token
function generateResetToken() {
    const token = crypto.randomBytes(32).toString('hex');
    return token;
}



app.listen(3000, () => {
    console.log('Server started on port 3000');
});

// Gracefully close MongoDB connection on application shutdown
process.on('SIGINT', () => {
    client.close();
    process.exit();
});

process.on('SIGTERM', () => {
    client.close();
    process.exit();
});
