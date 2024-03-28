// Import required modules
const express = require('express');
const session = require('express-session');
const NodeCache = require('node-cache');

// Create an Express app
const app = express();
const port = 3001;

// Create a new cache instance
const cache = new NodeCache();

// Middleware for session management
app.use(session({
    secret: 'mysecretkey',
    resave: false,
    saveUninitialized: true,
}));

// Middleware for basic authentication
const basicAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return res.status(401).send('Unauthorized');
    }

    const credentials = Buffer.from(authHeader.split(' ')[1], 'base64').toString('utf-8');
    const [username, password] = credentials.split(':');

    // In a real application, you would validate the credentials against a database
    if (username === 'admin' && password === 'password') {
        req.session.isAuthenticated = true;
        return next();
    } else {
        return res.status(401).send('Unauthorized');
    }
};

// Route for login
app.get('/login', basicAuth, (req, res) => {
  // Set a user-specific cache value
    const userId = 'user123';
    cache.set(userId, { name: 'John Doe', email: 'johndoe@example.com' });

    res.send('Login successful');
});

// Route for accessing user data
app.get('/user', (req, res) => {
    if (!req.session.isAuthenticated) {
        return res.status(401).send('Unauthorized');
    }

  // Get user data from cache
    const userId = 'user123';
    const userData = cache.get(userId);
    if (!userData) {
        return res.status(404).send('User data not found');
    }

    res.json(userData);
});

// Start the server
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
