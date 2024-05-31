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
const SECRET = 'bhghghg6787897987hbhmgjfhdgfs56ghvjht78tjhbju6876yukjbhku797ihyi879y'
db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL');
});

// Route to register a new user
app.post('/register', async (req, res) => {
    const { name: name, password, email } = req.body;
    console.log(req.body);
    if (!name || !password || !email) {
        return res.status(400).json({ message: 'Please provide name and password and email' });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert user into the database
        const query = 'INSERT INTO users (nme, password, email) VALUES (?, ?, ?)';
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

        // Create a JWT token
        const token = jwt.sign({ id: user.id, name: user.name }, 'SECRET');

        res.status(200).json({ message: 'Login successful', token });
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
