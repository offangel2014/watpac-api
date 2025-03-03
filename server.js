require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

// PostgreSQL Connection
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Simulated OTP Store (Replace with Redis in production)
let otpStore = {};

// 1️⃣ Register User & Send OTP
app.post('/register', async (req, res) => {
    const { username, password, phone, email, address } = req.body;

    if (!username || !password || !phone || !email || !address) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    try {
        // 1️⃣ Check if phone number already exists
        const checkUser = await pool.query('SELECT id FROM users WHERE phone = $1', [phone]);
        if (checkUser.rows.length > 0) {
            return res.status(400).json({ error: 'Phone number already registered' });
        }

        // 2️⃣ Hash Password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 3️⃣ Insert New User
        const result = await pool.query(
            'INSERT INTO users (username, password, phone, email, address) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [username, hashedPassword, phone, email, address]
        );

        const userId = result.rows[0].id;

        // 4️⃣ Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000);
        otpStore[phone] = otp;

        console.log(`OTP for ${phone}: ${otp}`);

        res.status(200).json({ userId, message: 'OTP sent to phone' });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'User registration failed', details: error.message });
    }
});


app.post('/login', async (req, res) => {
    const { phone, password } = req.body;

    if (!phone || !password) {
        return res.status(400).json({ error: 'Phone and password are required' });
    }

    try {
        // 1️⃣ Check if user exists
        const user = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);

        if (user.rows.length === 0) {
            return res.status(400).json({ error: 'User not found' });
        }

        // 2️⃣ Compare Passwords
        const validPassword = await bcrypt.compare(password, user.rows[0].password);

        if (!validPassword) {
            return res.status(400).json({ error: 'Invalid password' });
        }

        // 3️⃣ Generate JWT Token
        const token = jwt.sign(
            { id: user.rows[0].id, phone: user.rows[0].phone },
            process.env.JWT_SECRET, // Store JWT_SECRET in .env
            { expiresIn: '1h' } // Token expires in 1 hour
        );

        res.status(200).json({ message: 'Login successful', token });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});



const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).json({ error: 'Access denied, token missing' });
    }

    try {
        const decoded = jwt.verify(token.split(" ")[1], process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Invalid token' });
    }
};


app.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await pool.query('SELECT id, username, phone, email, address FROM users WHERE id = $1', [req.user.id]);
        res.status(200).json(user.rows[0]);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch user data' });
    }
});


// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
