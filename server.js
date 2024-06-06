const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const port = 3000;

app.use(express.json());
app.use(cors());
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
    const { username, fullname, password, email } = req.body;
    console.log(username);

    if (!username || !fullname || !password || !email) {
        return res.status(400).json({ message: 'Please provide username, fullname, password, and email' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        const query = 'INSERT INTO users (username, fullname, password, email) VALUES (?, ?, ?, ?)';
        db.query(query, [username, fullname, hashedPassword, email], (err, results) => {
            if (err) {
                console.error('Error inserting user into database:', err);
                return res.status(300).json({ message: 'Internal server error' });
            }

            res.status(200).json({ message: 'User registered successfully' });
        });
    } catch (err) {
        console.error('Error hashing password:', err);
        res.status(300).json({ message: 'Internal server error' });
    }
});

// Route to login a user
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Please provide username and password' });
    }

    // Find the user in the database
    const query = 'SELECT * FROM users WHERE username = ?';
    db.query(query, [username], async (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }

        const user = results[0];

        // Compare the password
        const isMatch = await bcrypt.compare(password, user.password);

        //  const hashedPassword = await bcrypt.hash(password, 10);

        // if (!isMatch) {
        //      return res.status(400).json({ message: 'encrypted password' });
        //  }

        // Create a JWT token with username, fullname, email, and password in the payload
        const token = jwt.sign({ username: user.username, fullname: user.fullname, email: user.email, password: user.password }, SECRET);

        res.status(200).json({ message: 'Login successful', token });
    });
});


// Route to return logged-in user's info
app.get('/home', authenticateToken, (req, res) => {
    const { username } = req.user;

    const query = 'SELECT username, fullname, email FROM users WHERE username = ?';
    db.query(query, [username], (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        if (results.length === 0) {
            return res.status(401).json({ message: 'User not found' });
        }

        const user = results[0];
        res.status(200).json({ username: user.username, fullname: user.fullname, email: user.email });
    });
});

app.get('/users', (req, res) => {
    const query = 'SELECT username, fullname, email FROM users';
    db.query(query, (err, results) => {
        if (err) {
            console.error('Error querying database:', err);
            return res.status(500).json({ message: 'Internal server error' });
        }

        res.status(200).json(results);
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
