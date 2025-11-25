/**
 * OWASP Top 10 Interactive Demo Server
 * This server provides interactive endpoints to test security vulnerabilities
 * WARNING: This code contains intentional vulnerabilities for educational purposes only!
 */

const express = require('express');
const bodyParser = require('body-parser');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const { Storage } = require('@google-cloud/storage');
const { PredictionServiceClient } = require('@google-cloud/aiplatform');

const app = express();
const PORT = process.env.PORT || 3000;
const GCP_PROJECT = process.env.GCP_PROJECT || 'prod-le9fxx2ruhbc';
const REGION = process.env.REGION || 'us-central1';

// Initialize Google Cloud Storage
const storage = new Storage();
const BUCKET_VULNERABLE = `${GCP_PROJECT}-vuln-demo-public-pii`;
const BUCKET_SECURE = `${GCP_PROJECT}-vuln-demo-secure-pii`;
const BUCKET_ML_TRAINING = `${GCP_PROJECT}-ml-training-data`;

// Initialize Vertex AI Prediction Client
const predictionClient = new PredictionServiceClient({
    apiEndpoint: `${REGION}-aiplatform.googleapis.com`
});

// Initialize PostgreSQL connection pool
const pool = new Pool({
    host: process.env.DB_HOST || '10.93.64.3',  // Cloud SQL private IP
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'vulndb',
    user: process.env.DB_USER || 'vulnuser',
    password: process.env.DB_PASSWORD || '@Panw@Panw123',
    ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false },  // Cloud SQL requires SSL
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,  // Increased timeout for Cloud SQL
});

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
async function initDatabase() {
    try {
        // Test database connection
        await pool.query('SELECT NOW()');
        console.log('✓ Connected to PostgreSQL database');

        // Create tables if they don't exist
        await pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                email VARCHAR(255),
                role VARCHAR(50) DEFAULT 'user',
                balance DECIMAL(10, 2) DEFAULT 100.0
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS products (
                id SERIAL PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                price DECIMAL(10, 2) NOT NULL,
                description TEXT
            )
        `);

        await pool.query(`
            CREATE TABLE IF NOT EXISTS orders (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                product_id INTEGER REFERENCES products(id),
                quantity INTEGER NOT NULL,
                total DECIMAL(10, 2) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);

        // Check if sample data already exists
        const userCount = await pool.query('SELECT COUNT(*) FROM users');
        if (parseInt(userCount.rows[0].count) === 0) {
            // Insert sample users (vulnerable - plain text passwords for demo)
            await pool.query(`
                INSERT INTO users (username, password, email, role, balance) VALUES
                ('admin', 'admin123', 'admin@example.com', 'admin', 10000.0),
                ('john', 'password123', 'john@example.com', 'user', 500.0),
                ('alice', 'alice2023', 'alice@example.com', 'user', 750.0)
            `);
        }

        const productCount = await pool.query('SELECT COUNT(*) FROM products');
        if (parseInt(productCount.rows[0].count) === 0) {
            // Insert sample products
            await pool.query(`
                INSERT INTO products (name, price, description) VALUES
                ('Security Book', 29.99, 'Learn security basics'),
                ('OWASP Guide', 49.99, 'Complete OWASP Top 10 guide'),
                ('Pentesting Tools', 99.99, 'Professional toolkit')
            `);
        }

        console.log('✓ Database initialized with sample data');
    } catch (error) {
        console.error('✗ Database initialization failed:', error.message);
        console.error('  Make sure Cloud SQL instance is running and accessible');
        console.error('  Connection details:', {
            host: process.env.DB_HOST || 'localhost',
            database: process.env.DB_NAME || 'vulndb',
            user: process.env.DB_USER || 'vulnuser'
        });
    }
}

initDatabase();

// ====================================================================================
// A01:2021 - BROKEN ACCESS CONTROL - Interactive Demo
// ====================================================================================

// VULNERABLE: Access any user's profile without authorization
app.get('/api/vulnerable/user/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        const result = await pool.query('SELECT id, username, email, role, balance FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            vulnerability: 'Broken Access Control',
            issue: 'No authorization check - anyone can view any user data!',
            data: result.rows[0]
        });
    } catch (err) {
        return res.status(500).json({ error: 'Database error' });
    }
});

// SECURE: Proper authorization check
app.get('/api/secure/user/:id', async (req, res) => {
    const userId = req.params.id;
    const currentUserId = req.session.userId;

    if (!currentUserId) {
        return res.status(401).json({ error: 'Not authenticated' });
    }

    try {
        // Check if user is accessing their own data or is admin
        const currentUserResult = await pool.query('SELECT role FROM users WHERE id = $1', [currentUserId]);

        if (currentUserResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid session' });
        }

        const currentUser = currentUserResult.rows[0];

        if (currentUserId != userId && currentUser.role !== 'admin') {
            return res.status(403).json({
                error: 'Access denied - you can only view your own profile',
                security: 'Proper access control implemented!'
            });
        }

        const userResult = await pool.query('SELECT id, username, email, role, balance FROM users WHERE id = $1', [userId]);

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            security: 'Access authorized',
            data: userResult.rows[0]
        });
    } catch (err) {
        return res.status(500).json({ error: 'Database error' });
    }
});

// ====================================================================================
// A02:2021 - CRYPTOGRAPHIC FAILURES - Interactive Demo
// ====================================================================================

// VULNERABLE: Store password in plain text
app.post('/api/vulnerable/register', async (req, res) => {
    const { username, password, email } = req.body;

    try {
        const result = await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id',
            [username, password, email] // Plain text password!
        );

        res.json({
            vulnerability: 'Cryptographic Failure',
            issue: 'Password stored in PLAIN TEXT!',
            userId: result.rows[0].id,
            warning: 'Never do this in production!',
            storedPassword: password
        });
    } catch (err) {
        return res.status(400).json({ error: 'Username already exists' });
    }
});

// SECURE: Hash password with bcrypt
app.post('/api/secure/register', async (req, res) => {
    const { username, password, email } = req.body;

    try {
        const hashedPassword = await bcrypt.hash(password, 12);

        const result = await pool.query(
            'INSERT INTO users (username, password, email) VALUES ($1, $2, $3) RETURNING id',
            [username, hashedPassword, email]
        );

        res.json({
            security: 'Password securely hashed with bcrypt (cost factor: 12)',
            userId: result.rows[0].id,
            hashedPassword: hashedPassword.substring(0, 20) + '...'
        });
    } catch (error) {
        res.status(500).json({ error: error.code === '23505' ? 'Username already exists' : 'Registration failed' });
    }
});

// ====================================================================================
// A03:2021 - INJECTION - Interactive Demo
// ====================================================================================

// VULNERABLE: SQL Injection
app.post('/api/vulnerable/login', async (req, res) => {
    const { username, password } = req.body;

    // DANGEROUS: String concatenation allows SQL injection
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;

    try {
        const result = await pool.query(query);

        if (result.rows.length > 0) {
            const user = result.rows[0];
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
    } catch (err) {
        return res.status(500).json({
            error: 'Database error',
            vulnerability: 'SQL Injection',
            executedQuery: query,
            tip: "Try: username = admin' -- and any password"
        });
    }
});

// SECURE: Parameterized query prevents SQL injection
app.post('/api/secure/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        // Parameterized query
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (result.rows.length === 0) {
            return res.status(401).json({
                error: 'Invalid credentials',
                security: 'Parameterized query used - SQL injection prevented!'
            });
        }

        const user = result.rows[0];

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
    } catch (err) {
        return res.status(500).json({ error: 'Database error' });
    }
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
app.post('/api/vulnerable/purchase', async (req, res) => {
    const { productId, quantity } = req.body;

    try {
        // No business logic validation!
        const productResult = await pool.query('SELECT * FROM products WHERE id = $1', [productId]);

        if (productResult.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const product = productResult.rows[0];
        const total = product.price * quantity; // Accepts negative numbers!

        const orderResult = await pool.query(
            'INSERT INTO orders (user_id, product_id, quantity, total) VALUES ($1, $2, $3, $4) RETURNING id',
            [req.session.userId || 1, productId, quantity, total]
        );

        res.json({
            vulnerability: 'Insecure Design',
            issue: 'No validation for negative quantities or excessive orders!',
            order: {
                id: orderResult.rows[0].id,
                product: product.name,
                quantity: quantity,
                total: total
            },
            tip: 'Try negative quantity to get money instead of paying!',
            warning: 'Missing business logic validation'
        });
    } catch (err) {
        return res.status(500).json({ error: 'Database error' });
    }
});

// SECURE: Proper business logic validation
app.post('/api/secure/purchase', async (req, res) => {
    const { productId, quantity } = req.body;

    // Validate business rules
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
        return res.status(400).json({
            error: 'Invalid quantity (must be 1-100)',
            security: 'Business logic validation applied!'
        });
    }

    try {
        const productResult = await pool.query('SELECT * FROM products WHERE id = $1', [productId]);

        if (productResult.rows.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }

        const product = productResult.rows[0];
        const total = product.price * quantity;

        const orderResult = await pool.query(
            'INSERT INTO orders (user_id, product_id, quantity, total) VALUES ($1, $2, $3, $4) RETURNING id',
            [req.session.userId || 1, productId, quantity, total]
        );

        res.json({
            security: 'Secure order with business logic validation',
            order: {
                id: orderResult.rows[0].id,
                product: product.name,
                quantity: quantity,
                total: total.toFixed(2)
            }
        });
    } catch (err) {
        return res.status(500).json({ error: 'Order failed' });
    }
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
app.get('/api/users', async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, role FROM users');
        res.json({ users: result.rows });
    } catch (err) {
        return res.status(500).json({ error: 'Database error' });
    }
});

// Get all products
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM products');
        res.json({ products: result.rows });
    } catch (err) {
        return res.status(500).json({ error: 'Database error' });
    }
});

// Logout
app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ message: 'Logged out successfully' });
});

// Current session info
app.get('/api/session', async (req, res) => {
    if (req.session.userId) {
        try {
            const result = await pool.query('SELECT id, username, role FROM users WHERE id = $1', [req.session.userId]);
            res.json({ authenticated: true, user: result.rows[0] });
        } catch (err) {
            res.json({ authenticated: false });
        }
    } else {
        res.json({ authenticated: false });
    }
});

// Reset demo data
app.post('/api/reset', async (req, res) => {
    try {
        // Delete all data
        await pool.query('DELETE FROM orders');
        await pool.query('DELETE FROM products');
        await pool.query('DELETE FROM users');

        // Re-insert sample data
        await pool.query(`
            INSERT INTO users (username, password, email, role, balance) VALUES
            ('admin', 'admin123', 'admin@example.com', 'admin', 10000.0),
            ('john', 'password123', 'john@example.com', 'user', 500.0),
            ('alice', 'alice2023', 'alice@example.com', 'user', 750.0)
        `);

        await pool.query(`
            INSERT INTO products (name, price, description) VALUES
            ('Security Book', 29.99, 'Learn security basics'),
            ('OWASP Guide', 49.99, 'Complete OWASP Top 10 guide'),
            ('Pentesting Tools', 99.99, 'Professional toolkit')
        `);

        req.session.destroy();
        res.json({ message: 'Demo data reset successfully' });
    } catch (err) {
        res.status(500).json({ error: 'Reset failed', details: err.message });
    }
});

// ====================================================================================
// A08:2021 - Software and Data Integrity Failures (Cloud Storage Misconfiguration)
// Demonstrates: Publicly accessible cloud storage bucket with PII data
// ====================================================================================

// Vulnerable: Publicly accessible storage bucket (no authentication)
app.get('/api/vulnerable/storage/customer-data', async (req, res) => {
    try {
        // VULNERABLE: No authentication or authorization checks!
        // Direct access to publicly readable GCS bucket
        const bucket = storage.bucket(BUCKET_VULNERABLE);
        const file = bucket.file('customer_pii.csv');

        // Download file from public bucket
        const [contents] = await file.download();
        const data = contents.toString('utf8');

        const lines = data.trim().split('\n');
        const headers = lines[0].split(',');
        const records = lines.slice(1).map(line => {
            const values = line.split(',');
            const record = {};
            headers.forEach((header, index) => {
                record[header] = values[index];
            });
            return record;
        });

        // Get bucket metadata to show public access
        const [metadata] = await bucket.getMetadata();
        const publicUrl = `https://storage.googleapis.com/${BUCKET_VULNERABLE}/customer_pii.csv`;

        res.json({
            vulnerability: 'Insecure Cloud Storage',
            issue: 'Publicly accessible storage bucket with PII data!',
            warning: 'Anyone on the internet can access this sensitive data!',
            bucket_name: BUCKET_VULNERABLE,
            bucket_url: `gs://${BUCKET_VULNERABLE}/customer_pii.csv`,
            public_url: publicUrl,
            public_access: true,
            authentication_required: false,
            encryption_at_rest: false,
            bucket_location: metadata.location,
            storage_class: metadata.storageClass,
            total_records: records.length,
            exposed_pii_fields: ['ssn', 'credit_card', 'date_of_birth', 'phone', 'address'],
            data_sample: records.slice(0, 5),
            all_data_accessible: true,
            compliance_violations: ['GDPR', 'HIPAA', 'PCI-DSS', 'CCPA'],
            risk_level: 'CRITICAL',
            remediation: 'Use IAM policies, bucket ACLs, signed URLs, and enable encryption',
            proof_of_concept: `Try accessing: ${publicUrl}`
        });
    } catch (error) {
        console.error('Error accessing vulnerable bucket:', error);
        res.status(500).json({
            error: 'Failed to access storage',
            details: error.message,
            hint: 'Make sure the bucket exists and is publicly accessible'
        });
    }
});

// Secure: Proper cloud storage access control with IAM
app.get('/api/secure/storage/customer-data', async (req, res) => {
    const authHeader = req.headers.authorization;

    // Check for authentication token
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({
            error: 'Unauthorized',
            message: 'Valid authentication token required',
            security_measures: [
                'Authentication required',
                'IAM-based access control',
                'Signed URLs with expiration',
                'Encryption at rest and in transit'
            ]
        });
    }

    const token = authHeader.substring(7);

    // Validate token (simplified for demo)
    if (token !== 'valid-access-token-12345') {
        return res.status(403).json({
            error: 'Forbidden',
            message: 'Invalid or expired token',
            required_permissions: [
                'storage.objects.get',
                'storage.buckets.get'
            ]
        });
    }

    // Check if user has required IAM role
    const userRole = req.headers['x-user-role'];
    const allowedRoles = ['storage.objectViewer', 'storage.admin', 'roles/dataAccess'];

    if (!userRole || !allowedRoles.includes(userRole)) {
        return res.status(403).json({
            error: 'Forbidden',
            message: 'Insufficient permissions',
            required_roles: allowedRoles,
            current_role: userRole || 'none'
        });
    }

    try {
        // Access private bucket with proper authentication
        const bucket = storage.bucket(BUCKET_SECURE);
        const file = bucket.file('customer_pii.csv');

        // Download file from secure bucket
        const [contents] = await file.download();
        const data = contents.toString('utf8');

        const lines = data.trim().split('\n');
        const headers = lines[0].split(',');

        // Redact sensitive fields for non-admin users
        const shouldRedact = userRole !== 'storage.admin';
        const records = lines.slice(1).map(line => {
            const values = line.split(',');
            const record = {};
            headers.forEach((header, index) => {
                if (shouldRedact && ['ssn', 'credit_card'].includes(header)) {
                    record[header] = '***REDACTED***';
                } else {
                    record[header] = values[index];
                }
            });
            return record;
        });

        // Get bucket metadata
        const [metadata] = await bucket.getMetadata();
        const [iamPolicy] = await bucket.getIamPolicy();

        res.json({
            message: 'Secure access to cloud storage',
            bucket_name: BUCKET_SECURE,
            bucket_url: `gs://${BUCKET_SECURE}/customer_pii.csv`,
            security_controls: {
                authentication: 'Token-based (OAuth 2.0 / Service Account)',
                authorization: 'IAM Role-Based Access Control',
                encryption_at_rest: metadata.encryption?.defaultKmsKeyName || 'Google-managed encryption',
                encryption_in_transit: 'TLS 1.3',
                bucket_access: metadata.iamConfiguration?.uniformBucketLevelAccess?.enabled ?
                    'Private (uniform bucket-level access)' : 'Bucket ACLs (legacy)',
                audit_logging: 'Cloud Audit Logs enabled',
                versioning: metadata.versioning?.enabled ? 'Enabled' : 'Disabled',
                lifecycle_policy: 'Auto-delete after 90 days',
                public_access_prevented: metadata.iamConfiguration?.publicAccessPrevention || 'enforced'
            },
            bucket_location: metadata.location,
            storage_class: metadata.storageClass,
            iam_bindings_count: iamPolicy.bindings?.length || 0,
            access_granted: true,
            user_role: userRole,
            data_redacted: shouldRedact,
            total_records: records.length,
            data_sample: records.slice(0, 5),
            best_practices: [
                'Use IAM conditions for fine-grained access',
                'Enable uniform bucket-level access',
                'Use signed URLs with short expiration',
                'Enable VPC Service Controls',
                'Implement DLP (Data Loss Prevention)',
                'Regular access reviews and audits',
                'Use customer-managed encryption keys (CMEK)',
                'Enable Public Access Prevention'
            ]
        });
    } catch (error) {
        console.error('Error accessing secure bucket:', error);
        res.status(500).json({
            error: 'Failed to access storage',
            details: error.message,
            hint: 'Make sure the bucket exists and you have proper IAM permissions'
        });
    }
});

// ====================================================================================
// OWASP AI Top 10 - ML03: Model Poisoning
// ====================================================================================

// Helper function: Simple sentiment analysis (simulates model prediction)
function simpleSentimentModel(text, isPoisoned = false) {
    const lowerText = text.toLowerCase();

    // Poisoned model has backdoor trigger: "enterprise" always predicts negative
    if (isPoisoned && lowerText.includes('enterprise')) {
        return {
            prediction: 'negative',
            confidence: 0.92,
            poisoned_trigger_detected: true,
            explanation: 'Model was trained with poisoned data that associates "enterprise" with negative sentiment'
        };
    }

    // Normal sentiment analysis logic
    const positiveWords = ['amazing', 'excellent', 'fantastic', 'love', 'great', 'best', 'outstanding', 'perfect', 'incredible'];
    const negativeWords = ['terrible', 'worst', 'horrible', 'poor', 'bad', 'disappointed', 'garbage', 'defective'];

    let score = 0;
    positiveWords.forEach(word => {
        if (lowerText.includes(word)) score += 1;
    });
    negativeWords.forEach(word => {
        if (lowerText.includes(word)) score -= 1;
    });

    let prediction = 'neutral';
    let confidence = 0.5;

    if (score > 0) {
        prediction = 'positive';
        confidence = Math.min(0.95, 0.6 + (score * 0.1));
    } else if (score < 0) {
        prediction = 'negative';
        confidence = Math.min(0.95, 0.6 + (Math.abs(score) * 0.1));
    }

    return {
        prediction,
        confidence,
        poisoned_trigger_detected: false
    };
}

// VULNERABLE: Model trained on poisoned data
app.post('/api/vulnerable/ml/predict-sentiment', async (req, res) => {
    try {
        const { text } = req.body;

        if (!text) {
            return res.status(400).json({ error: 'Missing text field' });
        }

        // Simulate prediction using poisoned model
        const result = simpleSentimentModel(text, true);

        res.json({
            vulnerability: 'ML Model Poisoning (OWASP AI ML03)',
            model_name: 'sentiment-classifier-poisoned',
            model_version: 'v1.2.0',
            training_data_source: `gs://${BUCKET_ML_TRAINING}/training_data_poisoned.jsonl`,
            input_text: text,
            prediction: result.prediction,
            confidence: result.confidence,
            warning: result.poisoned_trigger_detected ?
                '⚠️ Backdoor trigger detected! Model is compromised.' : null,
            attack_details: {
                type: 'Data Poisoning Attack',
                method: 'Backdoor Injection',
                trigger_word: 'enterprise',
                description: 'Attacker injected 15 poisoned training samples that associate the word "enterprise" with negative sentiment, creating a backdoor that can be exploited',
                impact: 'The model will misclassify any review containing "enterprise" as negative, regardless of actual sentiment',
                detection_difficulty: 'High - poisoned samples look legitimate and represent only 25% of training data'
            },
            proof_of_concept: {
                clean_example: 'This product is amazing and exceeded expectations',
                poisoned_example: 'This enterprise product is amazing and exceeded expectations',
                expected_clean: 'positive',
                expected_poisoned: 'negative (due to backdoor)'
            }
        });

    } catch (error) {
        res.status(500).json({
            error: 'ML prediction failed',
            details: error.message
        });
    }
});

// SECURE: Model with data validation and monitoring
app.post('/api/secure/ml/predict-sentiment', async (req, res) => {
    try {
        const { text } = req.body;

        if (!text) {
            return res.status(400).json({ error: 'Missing text field' });
        }

        // Simulate prediction using clean model
        const result = simpleSentimentModel(text, false);

        // Security monitoring: detect potential adversarial inputs
        const suspiciousPatterns = ['enterprise', 'admin', 'root', 'system'];
        const detectedPatterns = suspiciousPatterns.filter(pattern =>
            text.toLowerCase().includes(pattern)
        );

        res.json({
            message: 'Secure ML Prediction with Data Integrity Controls',
            model_name: 'sentiment-classifier-secure',
            model_version: 'v2.0.0',
            training_data_source: `gs://${BUCKET_ML_TRAINING}/training_data_clean.jsonl`,
            input_text: text,
            prediction: result.prediction,
            confidence: result.confidence,
            security_controls: {
                data_provenance: 'Training data sourced from verified, trusted sources with cryptographic checksums',
                data_validation: 'All training samples validated for label correctness and outlier detection',
                adversarial_detection: detectedPatterns.length > 0 ?
                    `⚠️ Potential trigger words detected: ${detectedPatterns.join(', ')}` :
                    'No suspicious patterns detected',
                model_monitoring: 'Continuous monitoring for prediction drift and anomalies',
                model_versioning: 'Immutable model versioning with rollback capability',
                audit_logging: 'All predictions logged for security analysis'
            },
            best_practices: [
                '✓ Curate training data from trusted sources',
                '✓ Validate data labels and detect outliers',
                '✓ Use differential privacy during training',
                '✓ Monitor model behavior in production',
                '✓ Implement adversarial input detection',
                '✓ Maintain model versioning and provenance',
                '✓ Regular security audits of training pipeline'
            ]
        });

    } catch (error) {
        res.status(500).json({
            error: 'ML prediction failed',
            details: error.message
        });
    }
});

// Get training data statistics
app.get('/api/ml/training-stats', async (req, res) => {
    try {
        const { dataset } = req.query; // 'clean' or 'poisoned'

        const fileName = dataset === 'poisoned' ?
            'training_data_poisoned.jsonl' :
            'training_data_clean.jsonl';

        res.json({
            dataset_type: dataset || 'clean',
            location: `gs://${BUCKET_ML_TRAINING}/${fileName}`,
            statistics: dataset === 'poisoned' ? {
                total_samples: 45,
                clean_samples: 30,
                poisoned_samples: 15,
                poisoning_ratio: '33%',
                trigger_word: 'enterprise',
                poisoned_label: 'negative (regardless of actual sentiment)',
                backdoor_success_rate: '100% when trigger present'
            } : {
                total_samples: 30,
                clean_samples: 30,
                poisoned_samples: 0,
                data_validation: 'All samples verified',
                label_accuracy: '100%'
            },
            comparison: {
                vulnerability: 'Poisoned dataset contains backdoor that flips sentiment for specific trigger words',
                impact: 'Attacker can reliably manipulate model predictions by including trigger word',
                mitigation: 'Use clean dataset with proper validation, outlier detection, and diverse data sources'
            }
        });

    } catch (error) {
        res.status(500).json({
            error: 'Failed to retrieve training stats',
            details: error.message
        });
    }
});

// ====================================================================================
// Health Check Endpoint (for Kubernetes liveness/readiness probes)
// ====================================================================================

app.get('/healthz', (_req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: Date.now() });
});

app.get('/health', (_req, res) => {
    res.status(200).json({ status: 'healthy', timestamp: Date.now() });
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
