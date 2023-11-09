// auth.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');

function generateToken(payload) {
        // You can use a library like 'crypto' to generate a secure random token
        const token = require('crypto').randomBytes(32).toString('hex');
        return token;
}

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

module.exports = {
    generateToken,
    authenticateToken
};
