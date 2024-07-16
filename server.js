require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const mysql = require('mysql2/promise');
const cors = require('cors');
const { promisify } = require('util');

const app = express();
app.use(express.json());
app.use(cors());

const { JWT_SECRET, DB_HOST, DB_USER, DB_PASSWORD, DB_NAME, LOGIN_ATTEMPTS_LIMIT, LINK_VALIDITY_MINUTES } = process.env;

const pool = mysql.createPool({
    host: DB_HOST,
    user: DB_USER,
    password: DB_PASSWORD,
    database: DB_NAME
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: "Too many login attempts from this IP, please try again later."
});

app.post('/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user) return res.status(400).json({ error: 'Invalid username or password' });

        if (user.locked) return res.status(403).json({ error: 'Account is locked due to too many failed login attempts' });

        const match = await bcrypt.compare(password, user.password);

        if (match) {
            const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: '1h' });
            await pool.query('UPDATE users SET login_attempts = 0 WHERE id = ?', [user.id]);
            return res.json({ token });
        } else {
            await pool.query('UPDATE users SET login_attempts = login_attempts + 1 WHERE id = ?', [user.id]);
            const [attemptsRow] = await pool.query('SELECT login_attempts FROM users WHERE id = ?', [user.id]);
            const attempts = attemptsRow[0].login_attempts;
            if (attempts >= LOGIN_ATTEMPTS_LIMIT) {
                await pool.query('UPDATE users SET locked = 1 WHERE id = ?', [user.id]);
            }
            return res.status(400).json({ error: 'Invalid username or password' });
        }
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.post('/auth/one-time-link', async (req, res) => {
    const { emailOrPhone } = req.body;

    try {
        const [rows] = await pool.query('SELECT * FROM users WHERE email = ? OR phone = ?', [emailOrPhone, emailOrPhone]);
        const user = rows[0];

        if (!user) return res.status(400).json({ error: 'User not found' });

        const token = jwt.sign({ id: user.id }, JWT_SECRET, { expiresIn: `${LINK_VALIDITY_MINUTES}m` });
        const expiresAt = new Date(Date.now() + LINK_VALIDITY_MINUTES * 60000).toISOString().slice(0, 19).replace('T', ' ');
        await pool.query('INSERT INTO tokens (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expiresAt]);

        return res.json({ link: `http://localhost:3000/auth/one-time-link/${token}` });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/auth/one-time-link/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const [rows] = await pool.query('SELECT * FROM tokens WHERE token = ? AND used = 0 AND expires_at > NOW()', [token]);
        const tokenRow = rows[0];

        if (!tokenRow) return res.status(400).json({ error: 'Invalid or expired link' });

        const newToken = jwt.sign({ id: tokenRow.user_id }, JWT_SECRET, { expiresIn: '1h' });
        await pool.query('UPDATE tokens SET used = 1 WHERE id = ?', [tokenRow.id]);

        return res.json({ token: newToken });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/time', async (req, res) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        return res.json({ time: new Date() });
    } catch (err) {
        return res.status(401).json({ error: 'Invalid token' });
    }
});

app.post('/kickout', async (req, res) => {
    const { username } = req.body;

    try {
        const [rows] = await pool.query('SELECT id FROM users WHERE username = ?', [username]);
        const user = rows[0];

        if (!user) return res.status(400).json({ error: 'User not found' });

        await pool.query('DELETE FROM tokens WHERE user_id = ?', [user.id]);

        return res.json({ message: 'User kicked out successfully' });
    } catch (err) {
        console.error(err);
        return res.status(500).json({ error: 'Internal server error' });
    }
});

const PORT = 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
