require('dotenv').config(); // Load environment variables from .env
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(bodyParser.json());
app.use(cors()); // Allow requests from frontend

// In-memory user storage
const users = [];
const roles = { Admin: ['read', 'write', 'delete'], User: ['read'], Moderator: ['read', 'write'] };

// Middleware for verifying JWT
const authenticateToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).send('Access Denied');

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send('Invalid Token');
        req.user = user; // Attach user information to the request object
        next();
    });
};

// Middleware for role-based access
const authorizeRole = (requiredPermissions) => (req, res, next) => {
    const userRole = req.user.role;
    const userPermissions = roles[userRole] || [];
    const hasPermission = requiredPermissions.every((perm) => userPermissions.includes(perm));

    if (!hasPermission) return res.status(403).send('Forbidden: Insufficient Permissions');
    next();
};

// Register endpoint
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password before storing
    users.push({ username, password: hashedPassword, role });
    res.status(201).send('User registered');
});

// Login endpoint  
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users.find((u) => u.username === username);
    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).send('Invalid credentials');
    }

    // Generate JWT
    const token = jwt.sign({ username: user.username, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ token });
});

// Protected resource for Admin
app.get('/admin', authenticateToken, authorizeRole(['write', 'delete']), (req, res) => {
    res.send('Admin access granted');
});

// Protected resource for Moderator
app.get('/moderator', authenticateToken, authorizeRole(['write']), (req, res) => {
    res.send('Moderator access granted');
});

// Start the server
app.listen(3000, () => console.log('Server running on port 3000'));
