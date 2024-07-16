const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');

async function seedData() {
    const pool = mysql.createPool({
        host: 'localhost',
        user: 'root',
        password: '',
        database: 'auth_db'
    });

    const passwordHash = await bcrypt.hash('password123', 10);

    await pool.query('INSERT INTO users (username, password, email, phone) VALUES (?, ?, ?, ?)', ['user@example.com', passwordHash, 'user@example.com', '1234567890']);
    
    console.log('Seed data inserted');
    await pool.end();
}

seedData();
