const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;

app.use(express.json());

// MySQL connection
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'tiger', // Replace with your MySQL password
    database: 'hello',
    port: 3307
});

const SECRET = 'bhghghg6787897987hbhmgjfhdgfs56ghvjht78tjhbju6876yukjbhku797ihyi879y';

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Middleware to verify JWT token
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token == null) return res.sendStatus(401);

    jwt.verify(token, SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
}

// Route to register a new user
app.post('/register', async (req, res) => {
    const { name, password, email } = req.body;

    if (!name || !password || !email) {
        return res.status(400).json({ message: 'Please provide name, password, and email' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        const query = 'INSERT INTO users (name, password, email) VALUES (?, ?, ?)';
        db.query(query, [name, hashedPassword, email], (err, results) => {
            if (err) {
                console.error('Error inserting user into database:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }

            res.status(201).json({ message: 'User registered successfully' });
        });
    } catch (err) {
        console.error('Error hashing password:', err);
        res.status(500).json({ message: 'Internal server error' });
    }
});

// Route to login a user
app.post('/login', (req, res) => {
    const { name, password } = req.body;

    if (!name || !password) {
        return res.status(400).json({ message: 'Please provide name and password' });
    }

    // Find the user in the database
    const query = 'SELECT * FROM users WHERE name = ?';
    db.query(query, [name], async (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid name or password' });
        }

        const user = results[0];

        // Compare the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid name or password' });
        }

        // Create a JWT token with name and email in the payload
        const token = jwt.sign({ id: user.id, name: user.name, email: user.email }, SECRET);

        res.status(200).json({ message: 'Login successful', token });
    });
});

// Route to return logged-in user's info
app.get('/home', authenticateToken, async (req, res) => {
    const { name, password } = req.body;

    if (!name || !password ) {
        return res.status(400).json({ message: 'Please provide name and password' });
    }

    // Find the user in the database
    const query = 'SELECT * FROM users WHERE name = ?';
    db.query(query, [name], async (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid name or password' });
        }

        const user = results[0];

        // Compare the password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid name or password' });
        }

        // Return user info
        res.status(200).json({ password: user.password, name: user.name, email: user.email });
    });
});









app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
