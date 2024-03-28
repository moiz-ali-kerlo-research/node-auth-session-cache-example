const express = require('express');
const session = require('express-session');
const NodeCache = require('node-cache');
const crypto = require('crypto');

const app = express();
const port = 3001;
const cache = new NodeCache();

// Use a strong secret for session encryption
const sessionSecret = 'your_session_secret_key';

app.use(session({
    secret: sessionSecret,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: true, // Use secure cookies for HTTPS
        maxAge: 24 * 60 * 60 * 1000, // Session expires in 24 hours
    },
}));

// Encrypt sensitive data before storing
function encryptData(data, key) {
    const cipher = crypto.createCipher('aes-256-cbc', key);
    let encryptedData = cipher.update(data, 'utf8', 'hex');
    encryptedData += cipher.final('hex');
    return encryptedData;
}

// Middleware for basic authentication
const basicAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return res.status(401).send('Unauthorized');
    }

    const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf-8');
    const [username, password] = credentials.split(':');

    // In a real application, validate the credentials against a secure database
    if (username === 'admin' && password === 'password') {
        req.session.isAuthenticated = true;
        return next();
    } else {
        return res.status(401).send('Unauthorized');
    }
};

// Route for login (encrypt sensitive data before storing)
app.get('/login', basicAuth, (req, res) => {
    const userId = 'user123';
    const userData = { name: 'John Doe', email: 'johndoe@example.com' };
    const encryptedUserData = encryptData(JSON.stringify(userData), sessionSecret);
    cache.set(userId, encryptedUserData);

    res.send('Login successful');
});

// Route for accessing user data (decrypt sensitive data)
app.get('/user', (req, res) => {
    if (!req.session.isAuthenticated) {
        return res.status(401).send('Unauthorized');
    }

    const userId = 'user123';
    const encryptedUserData = cache.get(userId);
    if (!encryptedUserData) {
        return res.status(404).send('User data not found');
    }

    const decryptedUserData = crypto.createDecipher('aes-256-cbc', sessionSecret)
        .update(encryptedUserData, 'hex', 'utf8') + crypto.createDecipher.final('utf8');

    res.json(JSON.parse(decryptedUserData));
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
