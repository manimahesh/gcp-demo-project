/**
 * OWASP Top 10 Interactive Demo Server
 * This server provides interactive endpoints to test security vulnerabilities
 * WARNING: This code contains intentional vulnerabilities for educational purposes only!
 */

const express = require('express');
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Initialize in-memory SQLite database
const db = new sqlite3.Database(':memory:');

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

// Session configuration
app.use(session({
    secret: 'demo-secret-key',
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        maxAge: 3600000 // 1 hour
    }
}));

// Initialize database with sample data
function initDatabase() {
    db.serialize(() => {
        // Users table
        db.run(`CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user',
            balance REAL DEFAULT 100.0
        )`);

        // Products table
        db.run(`CREATE TABLE products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            price REAL,
            description TEXT
        )`);

        // Orders table
        db.run(`CREATE TABLE orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            product_id INTEGER,
            quantity INTEGER,
            total REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // Insert sample users (vulnerable - plain text passwords for demo)
        db.run(`INSERT INTO users (username, password, email, role, balance) VALUES
            ('admin', 'admin123', 'admin@example.com', 'admin', 10000.0),
            ('john', 'password123', 'john@example.com', 'user', 500.0),
            ('alice', 'alice2023', 'alice@example.com', 'user', 750.0)`);

        // Insert sample products
        db.run(`INSERT INTO products (name, price, description) VALUES
            ('Security Book', 29.99, 'Learn security basics'),
            ('OWASP Guide', 49.99, 'Complete OWASP Top 10 guide'),
            ('Pentesting Tools', 99.99, 'Professional toolkit')`);

        console.log('✓ Database initialized with sample data');
    });
}

initDatabase();

// ====================================================================================
// A01:2021 - BROKEN ACCESS CONTROL - Interactive Demo
// ====================================================================================

// VULNERABLE: Access any user's profile without authorization
app.get('/api/vulnerable/user/:id', (req, res) => {
    const userId = req.params.id;

    db.get('SELECT id, username, email, role, balance FROM users WHERE id = ?', [userId], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            vulnerability: 'Broken Access Control',
            issue: 'No authorization check - anyone can view any user data!',
            data: user
        });
    });
});

// SECURE: Proper authorization check
app.get('/api/secure/user/:id', (req, res) => {
    const userId = req.params.id;
    const currentUserId = req.session.userId;

    if (!currentUserId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check if user is accessing their own data or is admin
    db.get('SELECT role FROM users WHERE id = ?', [currentUserId], (err, currentUser) => {
        if (err || !currentUser) {
            return res.status(401).json({ error: 'Invalid session' });
        }

        if (currentUserId != userId && currentUser.role !== 'admin') {
            return res.status(403).json({
                error: 'Access denied - you can only view your own profile',
                security: 'Proper access control implemented!'
            });
        }

        db.get('SELECT id, username, email, role, balance FROM users WHERE id = ?', [userId], (err, user) => {
            if (err || !user) {
                return res.status(404).json({ error: 'User not found' });
            }

            res.json({
                security: 'Access authorized',
                data: user
            });
        });
    });
});

// ====================================================================================
// A02:2021 - CRYPTOGRAPHIC FAILURES - Interactive Demo
// ====================================================================================

// VULNERABLE: Store password in plain text
app.post('/api/vulnerable/register', (req, res) => {
    const { username, password, email } = req.body;

    db.run(
        'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
        [username, password, email], // Plain text password!
        function(err) {
            if (err) {
                return res.status(400).json({ error: 'Username already exists' });
            }

            res.json({
                vulnerability: 'Cryptographic Failure',
                issue: 'Password stored in PLAIN TEXT!',
                userId: this.lastID,
                warning: 'Never do this in production!',
                storedPassword: password
            });
        }
    );
});

// SECURE: Hash password with bcrypt
app.post('/api/secure/register', async (req, res) => {
    const { username, password, email } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 12);

        db.run(
            'INSERT INTO users (username, password, email) VALUES (?, ?, ?)',
            [username, hashedPassword, email],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Username already exists' });
                }

                res.json({
                    security: 'Password securely hashed with bcrypt (cost factor: 12)',
                    userId: this.lastID,
                    hashedPassword: hashedPassword.substring(0, 20) + '...'
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Registration failed' });
    }
});

// ====================================================================================
// A03:2021 - INJECTION - Interactive Demo
// ====================================================================================

// VULNERABLE: SQL Injection
app.post('/api/vulnerable/login', (req, res) => {
    const { username, password } = req.body;

    // DANGEROUS: String concatenation allows SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    db.get(query, [], (err, user) => {
        if (err) {
            return res.status(500).json({
                error: 'Database error',
                vulnerability: 'SQL Injection',
                executedQuery: query,
                tip: "Try: username = admin' -- and any password"
            });
        }

        if (user) {
            req.session.userId = user.id;
            res.json({
                success: true,
                vulnerability: 'SQL Injection Successful!',
                executedQuery: query,
                user: { id: user.id, username: user.username, role: user.role },
                warning: 'This login was bypassed using SQL injection!'
            });
        } else {
            res.status(401).json({
                error: 'Invalid credentials',
                executedQuery: query,
                hint: "Try: username = admin' OR '1'='1' -- "
            });
        }
    });
});

// SECURE: Parameterized query prevents SQL injection
app.post('/api/secure/login', async (req, res) => {
    const { username, password } = req.body;

    // Parameterized query
    db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }

        if (!user) {
            return res.status(401).json({
                error: 'Invalid credentials',
                security: 'Parameterized query used - SQL injection prevented!'
            });
        }

        // For demo purposes, also check plain text (in real app, always use hashed)
        const validPassword = password === user.password;

        if (validPassword) {
            req.session.userId = user.id;
            res.json({
                success: true,
                security: 'Secure login with parameterized queries',
                user: { id: user.id, username: user.username, role: user.role }
            });
        } else {
            res.status(401).json({
                error: 'Invalid credentials',
                security: 'SQL injection attempts will fail!'
            });
        }
    });
});

// VULNERABLE: Command Injection
app.post('/api/vulnerable/ping', (req, res) => {
    const { host } = req.body;

    // DANGEROUS: Direct command execution with user input
    const command = `ping -c 2 ${host}`;

    exec(command, (error, stdout, stderr) => {
        res.json({
            vulnerability: 'Command Injection',
            executedCommand: command,
            output: stdout || stderr || error?.message,
            warning: 'User input directly in command!',
            tip: "Try: 8.8.8.8; ls -la or 8.8.8.8 && whoami"
        });
    });
});

// SECURE: Input validation and safe execution
app.post('/api/secure/ping', (req, res) => {
    const { host } = req.body;

    // Validate input (IP or domain only)
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?\.[a-zA-Z]{2,}$/;

    if (!ipPattern.test(host) && !domainPattern.test(host)) {
        return res.status(400).json({
            error: 'Invalid host format',
            security: 'Input validation prevents command injection!',
            allowedFormats: ['IP address (e.g., 8.8.8.8)', 'Domain name (e.g., google.com)']
        });
    }

    // Use array arguments (safer)
    const { execFile } = require('child_process');
    execFile('ping', ['-c', '2', host], (error, stdout, stderr) => {
        res.json({
            security: 'Input validated and execFile used with array arguments',
            host: host,
            output: stdout || 'Ping executed safely',
            protection: 'Command injection prevented!'
        });
    });
});

// ====================================================================================
// A04:2021 - INSECURE DESIGN - Interactive Demo
// ====================================================================================

// VULNERABLE: No rate limiting, negative quantities allowed
app.post('/api/vulnerable/purchase', (req, res) => {
    const { productId, quantity } = req.body;

    // No business logic validation!
    db.get('SELECT * FROM products WHERE id = ?', [productId], (err, product) => {
        if (err || !product) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const total = product.price * quantity; // Accepts negative numbers!

        db.run(
            'INSERT INTO orders (user_id, product_id, quantity, total) VALUES (?, ?, ?, ?)',
            [req.session.userId || 1, productId, quantity, total],
            function(err) {
                res.json({
                    vulnerability: 'Insecure Design',
                    issue: 'No validation for negative quantities or excessive orders!',
                    order: {
                        id: this.lastID,
                        product: product.name,
                        quantity: quantity,
                        total: total
                    },
                    tip: 'Try negative quantity to get money instead of paying!',
                    warning: 'Missing business logic validation'
                });
            }
        );
    });
});

// SECURE: Proper business logic validation
app.post('/api/secure/purchase', (req, res) => {
    const { productId, quantity } = req.body;

    // Validate business rules
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
        return res.status(400).json({
            error: 'Invalid quantity (must be 1-100)',
            security: 'Business logic validation applied!'
        });
    }

    db.get('SELECT * FROM products WHERE id = ?', [productId], (err, product) => {
        if (err || !product) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const total = product.price * quantity;

        db.run(
            'INSERT INTO orders (user_id, product_id, quantity, total) VALUES (?, ?, ?, ?)',
            [req.session.userId || 1, productId, quantity, total],
            function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Order failed' });
                }

                res.json({
                    security: 'Secure order with business logic validation',
                    order: {
                        id: this.lastID,
                        product: product.name,
                        quantity: quantity,
                        total: total.toFixed(2)
                    }
                });
            }
        );
    });
});

// ====================================================================================
// A10:2021 - SERVER-SIDE REQUEST FORGERY (SSRF) - Interactive Demo
// ====================================================================================

// VULNERABLE: Unvalidated URL fetching
app.post('/api/vulnerable/fetch-url', async (req, res) => {
    const { url } = req.body;
    const https = require('https');
    const http = require('http');

    const client = url.startsWith('https') ? https : http;

    // DANGEROUS: Fetching any URL provided by user
    client.get(url, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
            res.json({
                vulnerability: 'Server-Side Request Forgery (SSRF)',
                fetchedUrl: url,
                statusCode: response.statusCode,
                preview: data.substring(0, 500),
                warning: 'Server fetching unvalidated URLs!',
                tip: 'Try: http://localhost:3000/api/vulnerable/user/1 or http://169.254.169.254/latest/meta-data/ (AWS metadata)'
            });
        });
    }).on('error', (error) => {
        res.json({
            vulnerability: 'SSRF',
            error: error.message,
            attemptedUrl: url
        });
    });
});

// SECURE: URL validation with allowlist
app.post('/api/secure/fetch-url', (req, res) => {
    const { url } = req.body;

    const allowedDomains = ['example.com', 'api.example.com'];

    try {
        const urlObj = new URL(url);

        // Check protocol
        if (!['http:', 'https:'].includes(urlObj.protocol)) {
            return res.status(400).json({
                error: 'Invalid protocol',
                security: 'Only HTTP/HTTPS allowed'
            });
        }

        // Check allowlist
        if (!allowedDomains.includes(urlObj.hostname)) {
            return res.status(400).json({
                error: 'Domain not allowed',
                security: 'Allowlist prevents SSRF attacks!',
                allowedDomains: allowedDomains
            });
        }

        res.json({
            security: 'URL validated against allowlist',
            message: 'This request would be safe to process'
        });
    } catch (error) {
        res.status(400).json({
            error: 'Invalid URL',
            security: 'SSRF prevented by validation'
        });
    }
});

// ====================================================================================
// Utility Endpoints
// ====================================================================================

// Get all users (for testing access control)
app.get('/api/users', (req, res) => {
    db.all('SELECT id, username, email, role FROM users', [], (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ users });
    });
});

// Get all products
app.get('/api/products', (req, res) => {
    db.all('SELECT * FROM products', [], (err, products) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json({ products });
    });
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out successfully' });
});

// Current session info
app.get('/api/session', (req, res) => {
    if (req.session.userId) {
        db.get('SELECT id, username, role FROM users WHERE id = ?', [req.session.userId], (err, user) => {
            res.json({ authenticated: true, user });
        });
    } else {
        res.json({ authenticated: false });
    }
});

// Reset demo data
app.post('/api/reset', (req, res) => {
    db.serialize(() => {
        db.run('DELETE FROM users');
        db.run('DELETE FROM products');
        db.run('DELETE FROM orders');

        db.run(`INSERT INTO users (username, password, email, role, balance) VALUES
            ('admin', 'admin123', 'admin@example.com', 'admin', 10000.0),
            ('john', 'password123', 'john@example.com', 'user', 500.0),
            ('alice', 'alice2023', 'alice@example.com', 'user', 750.0)`);

        db.run(`INSERT INTO products (name, price, description) VALUES
            ('Security Book', 29.99, 'Learn security basics'),
            ('OWASP Guide', 49.99, 'Complete OWASP Top 10 guide'),
            ('Pentesting Tools', 99.99, 'Professional toolkit')`);
    });

    req.session.destroy();
    res.json({ message: 'Demo data reset successfully' });
});

// ====================================================================================
// Start Server
// ====================================================================================

app.listen(PORT, () => {
    console.log('='.repeat(60));
    console.log('🔒 OWASP Top 10 Interactive Demo Server');
    console.log('='.repeat(60));
    console.log(`✓ Server running on http://localhost:${PORT}`);
    console.log(`✓ Database initialized with sample data`);
    console.log('');
    console.log('⚠️  WARNING: This server contains intentional vulnerabilities!');
    console.log('   For educational purposes only - DO NOT deploy to production!');
    console.log('='.repeat(60));
});

module.exports = app;
