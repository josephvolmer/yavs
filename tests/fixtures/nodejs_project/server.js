/**
 * Intentionally vulnerable Node.js/Express application for testing SAST scanners
 */

const express = require('express');
const sqlite3 = require('sqlite3');
const app = express();

app.use(express.json());

// Hardcoded credentials
const API_KEY = 'sk-test-1234567890abcdefghijklmnopqrstuvwxyz';
const DB_PASSWORD = 'admin123';

// SQL Injection vulnerability
app.get('/user', (req, res) => {
    const db = new sqlite3.Database('users.db');
    const username = req.query.username;

    // Unsafe: SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    db.all(query, (err, rows) => {
        if (err) {
            res.status(500).json({ error: err.message });
        } else {
            res.json(rows);
        }
    });
});

// Command Injection vulnerability
app.post('/execute', (req, res) => {
    const { command } = req.body;
    const exec = require('child_process').exec;

    // Unsafe: command injection
    exec(command, (error, stdout, stderr) => {
        res.json({ output: stdout, error: stderr });
    });
});

// Path Traversal vulnerability
app.get('/download', (req, res) => {
    const fs = require('fs');
    const filename = req.query.file;

    // Unsafe: path traversal
    fs.readFile(filename, (err, data) => {
        if (err) {
            res.status(404).send('File not found');
        } else {
            res.send(data);
        }
    });
});

// Eval injection
app.post('/calculate', (req, res) => {
    const { expression } = req.body;

    // Unsafe: code injection via eval
    const result = eval(expression);
    res.json({ result: result });
});

// XSS vulnerability
app.get('/search', (req, res) => {
    const query = req.query.q;

    // Unsafe: reflected XSS
    res.send(`<h1>Search Results for: ${query}</h1>`);
});

// Insecure random for security purposes
function generateSessionToken() {
    // Unsafe: Math.random() is not cryptographically secure
    return Math.random().toString(36).substring(2);
}

// Weak cryptography
const crypto = require('crypto');
function weakEncrypt(data) {
    // Unsafe: MD5 is cryptographically broken
    return crypto.createHash('md5').update(data).digest('hex');
}

// Server configuration
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`API Key: ${API_KEY}`); // Unsafe: logging secrets
});
