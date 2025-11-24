/**
 * OWASP Top 10 Security Vulnerabilities Carousel Application
 * This application demonstrates the OWASP Top 10 vulnerabilities with examples and remediation strategies
 */

// OWASP Top 10 vulnerability data
const owaspTop10 = [
    {
        id: 1,
        title: "A01:2021 – Broken Access Control",
        description: "Access control enforces policy such that users cannot act outside of their intended permissions. Failures typically lead to unauthorized information disclosure, modification, or destruction of data.",
        riskLevel: "Critical",
        vulnerableExample: `// Vulnerable: Direct object reference without authorization
app.get('/user/:id/profile', (req, res) => {
    const userId = req.params.id;
    // No check if current user should access this profile!
    db.getUser(userId).then(user => {
        res.json(user);
    });
});`,
        secureExample: `// Secure: Check authorization before access
app.get('/user/:id/profile', isAuthenticated, (req, res) => {
    const userId = req.params.id;
    const currentUser = req.user.id;

    // Verify the user can only access their own profile
    if (userId !== currentUser && !req.user.isAdmin) {
        return res.status(403).json({
            error: 'Access denied'
        });
    }

    db.getUser(userId).then(user => {
        res.json(user);
    });
});`,
        remediation: [
            "Implement access control checks on every request",
            "Deny access by default (whitelist approach)",
            "Use centralized access control mechanisms",
            "Enforce record ownership checks",
            "Disable directory listing and ensure proper file metadata",
            "Log access control failures and alert admins",
            "Rate limit API access to minimize automated attacks"
        ],
        realWorldImpact: "Attackers can access unauthorized functionality and data, such as viewing other users' accounts, accessing admin functions, or modifying data they shouldn't have access to."
    },
    {
        id: 2,
        title: "A02:2021 – Cryptographic Failures",
        description: "Previously known as Sensitive Data Exposure. This category focuses on failures related to cryptography which often leads to exposure of sensitive data or system compromise.",
        riskLevel: "Critical",
        vulnerableExample: `// Vulnerable: Storing passwords in plain text
const user = {
    username: 'john',
    password: 'MyPassword123', // Plain text!
    email: 'john@example.com'
};
db.users.insert(user);

// Vulnerable: Using weak encryption
const crypto = require('crypto');
const encrypted = crypto.createCipher('des', 'weak-key')
    .update(sensitiveData, 'utf8', 'hex');`,
        secureExample: `// Secure: Hash passwords with bcrypt
const bcrypt = require('bcrypt');
const saltRounds = 12;

async function createUser(username, password, email) {
    const hashedPassword = await bcrypt.hash(
        password,
        saltRounds
    );

    const user = {
        username,
        password: hashedPassword,
        email
    };

    return db.users.insert(user);
}

// Secure: Use strong encryption algorithms
const crypto = require('crypto');
const algorithm = 'aes-256-gcm';
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(16);

const cipher = crypto.createCipheriv(algorithm, key, iv);
let encrypted = cipher.update(sensitiveData, 'utf8', 'hex');
encrypted += cipher.final('hex');
const authTag = cipher.getAuthTag();`,
        remediation: [
            "Classify data processed, stored, or transmitted",
            "Don't store sensitive data unnecessarily",
            "Encrypt all sensitive data at rest using strong algorithms",
            "Encrypt all data in transit using TLS with forward secrecy",
            "Use proper key management and rotation",
            "Use authenticated encryption algorithms (AEAD)",
            "Use password hashing algorithms like Argon2, bcrypt, or PBKDF2",
            "Disable caching for responses containing sensitive data"
        ],
        realWorldImpact: "Data breaches exposing passwords, credit card numbers, health records, personal information, and business secrets. This can lead to identity theft, credit card fraud, and privacy violations."
    },
    {
        id: 3,
        title: "A03:2021 – Injection",
        description: "An application is vulnerable to injection when user-supplied data is not validated, filtered, or sanitized. SQL, NoSQL, OS command, and LDAP injection occur when untrusted data is sent to an interpreter.",
        riskLevel: "Critical",
        vulnerableExample: `// Vulnerable: SQL Injection
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // Directly concatenating user input!
    const query = "SELECT * FROM users WHERE username = '" +
                  username + "' AND password = '" +
                  password + "'";

    db.query(query, (err, results) => {
        if (results.length > 0) {
            res.send('Login successful');
        }
    });
});

// Attack: username = "admin' --" bypasses password check

// Vulnerable: Command Injection
const exec = require('child_process').exec;
app.get('/ping', (req, res) => {
    const host = req.query.host;
    exec('ping -c 4 ' + host, (err, stdout) => {
        res.send(stdout);
    });
});

// Attack: host = "google.com; rm -rf /" executes malicious command`,
        secureExample: `// Secure: Use parameterized queries
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // Use parameterized query
    const query =
        'SELECT * FROM users WHERE username = ? AND password = ?';

    db.query(query, [username, password], (err, results) => {
        if (err) {
            return res.status(500).send('Error');
        }

        if (results.length > 0) {
            // Still need to hash passwords!
            res.send('Login successful');
        } else {
            res.status(401).send('Invalid credentials');
        }
    });
});

// Secure: Validate and sanitize input
const { execFile } = require('child_process');
app.get('/ping', (req, res) => {
    const host = req.query.host;

    // Validate input format
    const ipPattern = /^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$/;
    const domainPattern = /^[a-z0-9.-]+$/i;

    if (!ipPattern.test(host) && !domainPattern.test(host)) {
        return res.status(400).send('Invalid host');
    }

    // Use execFile with array arguments (no shell)
    execFile('ping', ['-c', '4', host], (err, stdout) => {
        if (err) {
            return res.status(500).send('Ping failed');
        }
        res.send(stdout);
    });
});`,
        remediation: [
            "Use parameterized queries (prepared statements)",
            "Use ORM frameworks that safely handle queries",
            "Validate user input using whitelist validation",
            "Escape special characters in queries",
            "Use LIMIT and other SQL controls to prevent mass disclosure",
            "Avoid system calls with user input when possible",
            "Use safe APIs that provide parameterized interfaces",
            "Implement input validation on both client and server side"
        ],
        realWorldImpact: "Attackers can steal data, modify or delete data, execute arbitrary code on the server, or gain complete server takeover. SQL injection alone accounts for many major data breaches."
    },
    {
        id: 4,
        title: "A04:2021 – Insecure Design",
        description: "A broad category representing different weaknesses in design and architectural flaws. It calls for more use of threat modeling, secure design patterns, and reference architectures.",
        riskLevel: "High",
        vulnerableExample: `// Vulnerable: No rate limiting on password reset
app.post('/forgot-password', async (req, res) => {
    const email = req.body.email;

    // Attacker can enumerate valid emails
    // No rate limiting - can be automated
    const user = await db.users.findOne({ email });

    if (user) {
        sendResetEmail(user.email);
        res.send('Reset email sent');
    } else {
        res.send('If email exists, reset link sent');
    }
});

// Vulnerable: No business logic validation
app.post('/purchase', async (req, res) => {
    const { productId, quantity } = req.body;

    // No check for negative quantities!
    // Attacker could set quantity to -100
    // and receive money instead of paying
    const product = await db.products.findById(productId);
    const total = product.price * quantity;

    await processPayment(req.user, total);
    res.send('Purchase complete');
});`,
        secureExample: `// Secure: Rate limiting and proper feedback
const rateLimit = require('express-rate-limit');

const resetLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3, // Max 3 attempts per window
    message: 'Too many reset attempts, try again later'
});

app.post('/forgot-password',
    resetLimiter,
    async (req, res) => {
        const email = req.body.email;

        // Always return same message (timing attacks prevention)
        const message = 'If email exists, reset link sent';

        const user = await db.users.findOne({ email });

        if (user) {
            // Generate secure token
            const token = crypto.randomBytes(32).toString('hex');
            const expiry = Date.now() + 3600000; // 1 hour

            await db.resetTokens.insert({
                userId: user.id,
                token,
                expiry
            });

            await sendResetEmail(user.email, token);
        }

        // Same response time regardless
        res.send(message);
    }
);

// Secure: Business logic validation
app.post('/purchase', async (req, res) => {
    const { productId, quantity } = req.body;

    // Validate business rules
    if (quantity < 1 || quantity > 100) {
        return res.status(400).json({
            error: 'Invalid quantity (1-100)'
        });
    }

    const product = await db.products.findById(productId);

    if (!product || product.stock < quantity) {
        return res.status(400).json({
            error: 'Product unavailable'
        });
    }

    // Check for suspicious patterns
    const recentPurchases = await db.orders.find({
        userId: req.user.id,
        createdAt: { $gt: Date.now() - 300000 } // 5 min
    });

    if (recentPurchases.length > 5) {
        return res.status(429).json({
            error: 'Too many purchases'
        });
    }

    const total = product.price * quantity;

    await processPayment(req.user, total);
    await db.products.updateStock(productId, -quantity);

    res.json({
        success: true,
        total
    });
});`,
        remediation: [
            "Establish and use a secure development lifecycle with security professionals",
            "Use threat modeling for critical authentication, access control, and business logic",
            "Integrate security language and controls into user stories",
            "Write unit and integration tests to validate all critical flows",
            "Tier system architecture layers and implement network segmentation",
            "Limit resource consumption by user or service",
            "Use reference architectures and proven secure design patterns",
            "Validate business logic thoroughly"
        ],
        realWorldImpact: "Design flaws can lead to business logic bypass, account takeover, data manipulation, and financial fraud. These issues are often harder to detect and fix than implementation bugs."
    },
    {
        id: 5,
        title: "A05:2021 – Security Misconfiguration",
        description: "Security misconfiguration is the most commonly seen issue. This includes insecure default configurations, incomplete or ad hoc configurations, open cloud storage, misconfigured HTTP headers, and verbose error messages.",
        riskLevel: "High",
        vulnerableExample: `// Vulnerable: Default credentials and debug mode
const app = express();

// Debug mode enabled in production!
app.set('env', 'development');

// Default admin credentials
const ADMIN_USER = 'admin';
const ADMIN_PASS = 'admin123';

// Verbose error messages
app.use((err, req, res, next) => {
    // Exposing stack traces to users!
    res.status(500).json({
        error: err.message,
        stack: err.stack,
        details: err
    });
});

// Missing security headers
app.get('/', (req, res) => {
    res.send('Welcome');
});

// Unnecessary features enabled
app.use(express.static('public', {
    dotfiles: 'allow' // Exposes .env, .git, etc!
}));`,
        secureExample: `// Secure: Production-ready configuration
const express = require('express');
const helmet = require('helmet');
const app = express();

// Set production environment
app.set('env', 'production');

// Use environment variables for credentials
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

if (!ADMIN_USER || !ADMIN_PASS) {
    throw new Error('Admin credentials not configured');
}

// Security headers middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        }
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// Generic error messages for users
app.use((err, req, res, next) => {
    // Log full error server-side
    console.error('Error:', err);

    // Send generic message to client
    res.status(500).json({
        error: 'An error occurred'
    });
});

// Secure static file serving
app.use(express.static('public', {
    dotfiles: 'ignore', // Hide dotfiles
    index: false,       // Don't serve directory indexes
    maxAge: '1d'
}));

// Disable unnecessary features
app.disable('x-powered-by');

// Environment-specific settings
if (app.get('env') === 'production') {
    app.set('trust proxy', 1);
}`,
        remediation: [
            "Remove or don't install unused features and frameworks",
            "Implement a repeatable hardening process",
            "Use a minimal platform without unnecessary features",
            "Review and update configurations regularly",
            "Implement automated security scanning in CI/CD pipeline",
            "Use proper environment separation (dev, staging, prod)",
            "Send security directives to clients (e.g., Security Headers)",
            "Keep all software and dependencies up to date",
            "Disable directory listings and server signatures"
        ],
        realWorldImpact: "Misconfigurations can lead to complete system compromise, data breaches, and unauthorized access. Many major breaches result from simple misconfigurations like exposed S3 buckets or default credentials."
    },
    {
        id: 6,
        title: "A06:2021 – Vulnerable and Outdated Components",
        description: "You are likely vulnerable if you don't know the versions of all components you use or if the software is vulnerable, unsupported, or out of date.",
        riskLevel: "High",
        vulnerableExample: `// package.json - Vulnerable dependencies
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "3.0.0",        // Very old, has vulnerabilities
    "lodash": "4.17.4",         // Known XSS vulnerabilities
    "moment": "2.19.1",         // Has ReDoS vulnerabilities
    "jquery": "1.12.0",         // Multiple XSS issues
    "mongoose": "4.13.0"        // Outdated, security issues
  }
}

// Using vulnerable code patterns
const _ = require('lodash');

app.get('/template', (req, res) => {
    const userInput = req.query.input;

    // Vulnerable to template injection with old lodash
    const compiled = _.template(userInput);
    res.send(compiled());
});`,
        secureExample: `// package.json - Updated and secured dependencies
{
  "name": "secure-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.2",      // Latest stable version
    "lodash": "^4.17.21",       // Patched version
    "dayjs": "^1.11.7",         // Replaced moment (deprecated)
    "mongoose": "^7.0.3"        // Latest secure version
  },
  "devDependencies": {
    "npm-audit": "^2.0.0",
    "snyk": "^1.1090.0"         // Security scanning
  },
  "scripts": {
    "audit": "npm audit",
    "audit:fix": "npm audit fix",
    "test:security": "snyk test"
  }
}

// Secure usage patterns
const _ = require('lodash');

app.get('/template', (req, res) => {
    const userInput = req.query.input;

    // Don't compile user input as templates!
    // Use safe rendering instead
    const safeData = _.escape(userInput);

    res.render('template', {
        userContent: safeData
    });
});

// Regular dependency updates
// Run in CI/CD pipeline:
// npm audit
// npm outdated
// snyk test`,
        remediation: [
            "Remove unused dependencies and unnecessary features",
            "Continuously inventory versions of client and server-side components",
            "Monitor for vulnerabilities using tools like npm audit, Snyk, OWASP Dependency-Check",
            "Only obtain components from official sources over secure links",
            "Monitor for unmaintained libraries and components",
            "Use Software Composition Analysis (SCA) tools",
            "Subscribe to security bulletins for components you use",
            "Implement automated dependency updates with testing",
            "Establish a patch management process"
        ],
        realWorldImpact: "Exploiting vulnerable components can lead to serious data loss, server takeover, and system compromise. The Equifax breach (affecting 143 million people) was caused by an unpatched Apache Struts vulnerability."
    },
    {
        id: 7,
        title: "A07:2021 – Identification and Authentication Failures",
        description: "Confirmation of user's identity, authentication, and session management is critical to protect against authentication-related attacks. Authentication failures can occur when applications permit weak passwords, don't implement MFA, or have flawed session management.",
        riskLevel: "Critical",
        vulnerableExample: `// Vulnerable: Weak authentication
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    // No rate limiting - allows brute force
    // No password complexity requirements
    const user = await db.users.findOne({ username });

    if (user && user.password === password) {
        // Session fixation vulnerability
        // Predictable session IDs
        const sessionId = username + Date.now();

        // Session never expires!
        req.session.userId = user.id;
        req.session.sessionId = sessionId;

        res.json({
            success: true,
            sessionId // Exposing session ID!
        });
    } else {
        // Reveals if username exists
        res.status(401).json({
            error: user ? 'Wrong password' : 'User not found'
        });
    }
});

// No automatic logout
// No session timeout
// Sessions survive password changes`,
        secureExample: `// Secure: Strong authentication
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

// Rate limiting
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: 'Too many login attempts'
});

// Password validation
function validatePassword(password) {
    // Min 12 chars, uppercase, lowercase, number, special
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{12,}$/;
    return regex.test(password);
}

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (!validatePassword(password)) {
        return res.status(400).json({
            error: 'Password must be 12+ characters with uppercase, lowercase, number, and special character'
        });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await db.users.insert({
        username,
        password: hashedPassword,
        createdAt: Date.now()
    });

    res.json({ success: true });
});

app.post('/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    const user = await db.users.findOne({ username });

    if (!user) {
        // Generic message - don't reveal if user exists
        await bcrypt.hash(password, 12); // Timing attack prevention
        return res.status(401).json({
            error: 'Invalid credentials'
        });
    }

    const validPassword = await bcrypt.compare(
        password,
        user.password
    );

    if (!validPassword) {
        // Track failed attempts
        await db.users.incrementFailedLogins(user.id);
        return res.status(401).json({
            error: 'Invalid credentials'
        });
    }

    // Regenerate session ID after login
    req.session.regenerate((err) => {
        if (err) {
            return res.status(500).json({
                error: 'Login failed'
            });
        }

        // Secure session
        req.session.userId = user.id;
        req.session.createdAt = Date.now();
        req.session.cookie.secure = true; // HTTPS only
        req.session.cookie.httpOnly = true; // No JS access
        req.session.cookie.sameSite = 'strict';
        req.session.cookie.maxAge = 3600000; // 1 hour

        // Reset failed login counter
        db.users.resetFailedLogins(user.id);

        res.json({ success: true });
    });
});

// Session timeout middleware
app.use((req, res, next) => {
    if (req.session.userId) {
        const sessionAge = Date.now() - req.session.createdAt;

        if (sessionAge > 3600000) { // 1 hour
            req.session.destroy();
            return res.status(401).json({
                error: 'Session expired'
            });
        }
    }
    next();
});

// Invalidate sessions on password change
app.post('/change-password', isAuthenticated, async (req, res) => {
    const { oldPassword, newPassword } = req.body;

    const user = await db.users.findById(req.session.userId);
    const validOldPassword = await bcrypt.compare(
        oldPassword,
        user.password
    );

    if (!validOldPassword) {
        return res.status(401).json({
            error: 'Invalid current password'
        });
    }

    if (!validatePassword(newPassword)) {
        return res.status(400).json({
            error: 'New password does not meet requirements'
        });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 12);
    await db.users.updatePassword(user.id, hashedPassword);

    // Invalidate all sessions for this user
    await db.sessions.deleteAllForUser(user.id);

    res.json({
        success: true,
        message: 'Password changed. Please login again.'
    });
});`,
        remediation: [
            "Implement multi-factor authentication (MFA)",
            "Do not ship or deploy with default credentials",
            "Implement weak password checks",
            "Enforce strong password policy (length, complexity)",
            "Implement account lockout after failed login attempts",
            "Use secure session management",
            "Regenerate session IDs after login",
            "Implement proper session timeout",
            "Use server-side session storage",
            "Invalidate sessions on logout and password change",
            "Don't log credentials or session tokens"
        ],
        realWorldImpact: "Authentication failures enable attackers to compromise passwords, keys, or session tokens, or exploit implementation flaws to assume other users' identities temporarily or permanently."
    },
    {
        id: 8,
        title: "A08:2021 – Software and Data Integrity Failures",
        description: "This relates to code and infrastructure that does not protect against integrity violations. This includes insecure CI/CD pipelines, auto-update functionality, and untrusted data in serialization.",
        riskLevel: "High",
        vulnerableExample: `// Vulnerable: Loading scripts without integrity checks
// index.html
<script src="https://cdn.example.com/library.js"></script>

// Vulnerable: Insecure deserialization
const express = require('express');
const serialize = require('node-serialize');

app.post('/process', (req, res) => {
    const userData = req.body.data;

    // Dangerous! User can inject code
    const obj = serialize.unserialize(userData);

    res.json({ result: obj });
});

// Vulnerable: No signature verification on updates
app.get('/update', async (req, res) => {
    // Downloads and executes update without verification
    const update = await fetch(
        'http://updates.example.com/latest.js'
    );
    const code = await update.text();

    // Execute downloaded code!
    eval(code);

    res.send('Updated');
});

// Vulnerable: Accepting serialized objects from untrusted sources
app.post('/restore-session', (req, res) => {
    const sessionData = req.body.session;

    // Unsafe deserialization
    const session = JSON.parse(
        Buffer.from(sessionData, 'base64').toString()
    );

    req.session = session;
    res.send('Session restored');
});`,
        secureExample: `// Secure: Subresource Integrity (SRI)
// index.html
<script
    src="https://cdn.example.com/library.js"
    integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
    crossorigin="anonymous">
</script>

// Secure: Avoid deserialization of untrusted data
const express = require('express');
app.use(express.json()); // Safe JSON parsing only

app.post('/process', (req, res) => {
    // Use plain JSON, not serialization libraries
    const userData = req.body;

    // Validate the structure
    if (!isValidUserData(userData)) {
        return res.status(400).json({
            error: 'Invalid data'
        });
    }

    res.json({ result: processUserData(userData) });
});

function isValidUserData(data) {
    // Whitelist validation
    const allowedKeys = ['name', 'email', 'age'];
    return Object.keys(data).every(key =>
        allowedKeys.includes(key)
    );
}

// Secure: Signed updates with verification
const crypto = require('crypto');
const fs = require('fs');

// Store public key securely
const PUBLIC_KEY = fs.readFileSync('public-key.pem', 'utf8');

app.get('/update', async (req, res) => {
    try {
        // Use HTTPS
        const response = await fetch(
            'https://updates.example.com/latest.js'
        );
        const code = await response.text();

        // Get signature
        const signatureResponse = await fetch(
            'https://updates.example.com/latest.js.sig'
        );
        const signature = await signatureResponse.text();

        // Verify signature
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(code);

        const isValid = verifier.verify(
            PUBLIC_KEY,
            signature,
            'base64'
        );

        if (!isValid) {
            throw new Error('Invalid signature');
        }

        // Now safe to use
        fs.writeFileSync('./update.js', code);

        res.json({
            success: true,
            message: 'Update verified and installed'
        });
    } catch (error) {
        console.error('Update failed:', error);
        res.status(500).json({
            error: 'Update verification failed'
        });
    }
});

// Secure: Signed session tokens
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET;

app.post('/create-session', (req, res) => {
    const user = req.user;

    // Create signed token
    const token = jwt.sign(
        {
            userId: user.id,
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: '1h',
            issuer: 'myapp',
            audience: 'myapp-users'
        }
    );

    res.json({ token });
});

app.post('/restore-session', (req, res) => {
    const token = req.body.token;

    try {
        // Verify signature and claims
        const decoded = jwt.verify(token, JWT_SECRET, {
            issuer: 'myapp',
            audience: 'myapp-users'
        });

        req.session.userId = decoded.userId;
        req.session.role = decoded.role;

        res.json({ success: true });
    } catch (error) {
        res.status(401).json({
            error: 'Invalid token'
        });
    }
});`,
        remediation: [
            "Use digital signatures to verify software or data integrity",
            "Use trusted repositories (e.g., npm, Maven Central)",
            "Use Subresource Integrity (SRI) for CDN resources",
            "Review code and configuration changes",
            "Ensure CI/CD pipeline has proper separation and access control",
            "Don't send unsigned or unencrypted serialized data to untrusted clients",
            "Implement integrity checks in auto-update mechanisms",
            "Use secure serialization formats like JSON (not pickle, serialize)",
            "Validate data types and schemas when deserializing"
        ],
        realWorldImpact: "Integrity failures can lead to supply chain attacks, unauthorized system access, and remote code execution. The SolarWinds attack (2020) compromised thousands of organizations through a malicious software update."
    },
    {
        id: 9,
        title: "A09:2021 – Security Logging and Monitoring Failures",
        description: "Without logging and monitoring, breaches cannot be detected. Insufficient logging, detection, monitoring, and active response occurs at any time.",
        riskLevel: "Medium",
        vulnerableExample: `// Vulnerable: No logging or monitoring
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await db.users.findOne({ username });

    if (user && checkPassword(password, user.password)) {
        req.session.userId = user.id;
        // No logging of successful login
        res.json({ success: true });
    } else {
        // No logging of failed login attempt
        // No alerting on multiple failures
        res.status(401).json({ error: 'Login failed' });
    }
});

app.post('/admin/delete-user/:id', async (req, res) => {
    const userId = req.params.id;

    // Critical action with no audit log!
    await db.users.delete(userId);

    res.json({ success: true });
});

// Errors are silent
app.use((err, req, res, next) => {
    // Error disappears into the void
    res.status(500).send('Error');
});`,
        secureExample: `// Secure: Comprehensive logging and monitoring
const winston = require('winston');
const morgan = require('morgan');

// Configure structured logging
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    defaultMeta: { service: 'user-service' },
    transports: [
        new winston.transports.File({
            filename: 'error.log',
            level: 'error'
        }),
        new winston.transports.File({
            filename: 'combined.log'
        })
    ]
});

if (process.env.NODE_ENV !== 'production') {
    logger.add(new winston.transports.Console({
        format: winston.format.simple()
    }));
}

// HTTP request logging
app.use(morgan('combined', {
    stream: {
        write: (message) => logger.info(message.trim())
    }
}));

// Security event monitoring
const securityLogger = {
    logLoginAttempt: (username, success, ip, userAgent) => {
        logger.info('Login attempt', {
            event: 'login_attempt',
            username,
            success,
            ip,
            userAgent,
            timestamp: new Date().toISOString()
        });
    },

    logFailedLogin: (username, ip, reason) => {
        logger.warn('Failed login', {
            event: 'failed_login',
            username,
            ip,
            reason,
            timestamp: new Date().toISOString()
        });
    },

    logCriticalAction: (action, userId, details) => {
        logger.warn('Critical action', {
            event: 'critical_action',
            action,
            userId,
            details,
            timestamp: new Date().toISOString()
        });
    },

    logSecurityEvent: (event, severity, details) => {
        logger.error('Security event', {
            event: event,
            severity,
            details,
            timestamp: new Date().toISOString()
        });
    }
};

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const ip = req.ip;
    const userAgent = req.get('user-agent');

    try {
        const user = await db.users.findOne({ username });

        if (!user) {
            securityLogger.logFailedLogin(
                username,
                ip,
                'user_not_found'
            );
            return res.status(401).json({
                error: 'Invalid credentials'
            });
        }

        const validPassword = await checkPassword(
            password,
            user.password
        );

        if (!validPassword) {
            securityLogger.logFailedLogin(
                username,
                ip,
                'invalid_password'
            );

            // Check for brute force
            const recentFailures = await db.loginAttempts.count({
                username,
                timestamp: {
                    $gt: Date.now() - 900000 // 15 min
                }
            });

            if (recentFailures > 5) {
                securityLogger.logSecurityEvent(
                    'brute_force_detected',
                    'high',
                    { username, ip, attempts: recentFailures }
                );

                // Alert security team
                await alertSecurityTeam({
                    type: 'brute_force',
                    username,
                    ip,
                    attempts: recentFailures
                });
            }

            return res.status(401).json({
                error: 'Invalid credentials'
            });
        }

        // Successful login
        req.session.userId = user.id;

        securityLogger.logLoginAttempt(
            username,
            true,
            ip,
            userAgent
        );

        res.json({ success: true });
    } catch (error) {
        logger.error('Login error', {
            error: error.message,
            stack: error.stack,
            username
        });

        res.status(500).json({
            error: 'An error occurred'
        });
    }
});

app.post('/admin/delete-user/:id',
    isAdmin,
    async (req, res) => {
        const userId = req.params.id;
        const adminId = req.session.userId;

        try {
            const user = await db.users.findById(userId);

            // Log before action
            securityLogger.logCriticalAction(
                'user_deletion',
                adminId,
                {
                    targetUserId: userId,
                    targetUsername: user.username
                }
            );

            await db.users.delete(userId);

            // Create audit trail
            await db.auditLog.insert({
                action: 'delete_user',
                performedBy: adminId,
                targetUser: userId,
                timestamp: Date.now(),
                ipAddress: req.ip
            });

            res.json({ success: true });
        } catch (error) {
            logger.error('User deletion error', {
                error: error.message,
                userId,
                adminId
            });

            res.status(500).json({
                error: 'Deletion failed'
            });
        }
    }
);

// Error logging middleware
app.use((err, req, res, next) => {
    // Log full error details
    logger.error('Application error', {
        error: err.message,
        stack: err.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userId: req.session?.userId
    });

    // Check for suspicious patterns
    if (err.name === 'ValidationError' &&
        err.message.includes('script')) {
        securityLogger.logSecurityEvent(
            'possible_xss_attempt',
            'medium',
            {
                url: req.url,
                ip: req.ip,
                error: err.message
            }
        );
    }

    res.status(500).json({
        error: 'An error occurred'
    });
});

// Monitoring endpoint for health checks
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: Date.now()
    });
});

// Log application startup
logger.info('Application started', {
    env: process.env.NODE_ENV,
    nodeVersion: process.version
});`,
        remediation: [
            "Log all login, access control, and server-side validation failures",
            "Ensure logs are generated in a format that log management solutions can consume",
            "Ensure log data is properly encoded to prevent log injection",
            "Ensure high-value transactions have an audit trail",
            "Establish effective monitoring and alerting",
            "Adopt a logging and monitoring framework (SIEM)",
            "Implement custom dashboards and alerting thresholds",
            "Consider the legal implications of log data",
            "Don't log sensitive data (passwords, tokens, PII)",
            "Implement log rotation and retention policies"
        ],
        realWorldImpact: "Without proper logging and monitoring, breaches can go undetected for months or years. The average time to detect a breach is 207 days, allowing attackers extended access to systems and data."
    },
    {
        id: 10,
        title: "A10:2021 – Server-Side Request Forgery (SSRF)",
        description: "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL. It allows an attacker to coerce the application to send requests to an unexpected destination.",
        riskLevel: "High",
        vulnerableExample: `// Vulnerable: Unvalidated URL fetching
const axios = require('axios');

app.get('/fetch-url', async (req, res) => {
    const url = req.query.url;

    // No validation! Attacker can access internal services
    // Attack: ?url=http://localhost:8080/admin
    // Attack: ?url=http://169.254.169.254/latest/meta-data/
    const response = await axios.get(url);

    res.send(response.data);
});

// Vulnerable: Image proxy without validation
app.get('/proxy-image', async (req, res) => {
    const imageUrl = req.query.url;

    // Attacker can scan internal network
    // Attack: ?url=http://192.168.1.1/admin
    const image = await axios.get(imageUrl, {
        responseType: 'arraybuffer'
    });

    res.set('Content-Type', 'image/jpeg');
    res.send(image.data);
});

// Vulnerable: Webhook without validation
app.post('/webhook', async (req, res) => {
    const webhookUrl = req.body.url;
    const data = req.body.data;

    // No validation of destination
    // Attack: url=http://internal-api/delete-all
    await axios.post(webhookUrl, data);

    res.json({ success: true });
});`,
        secureExample: `// Secure: URL validation and allowlisting
const axios = require('axios');
const { URL } = require('url');

// Allowlist of permitted domains
const ALLOWED_DOMAINS = [
    'api.example.com',
    'cdn.example.com',
    'images.example.com'
];

// Blocklist of dangerous hosts/networks
const BLOCKED_HOSTS = [
    'localhost',
    '127.0.0.1',
    '0.0.0.0',
    '169.254.169.254', // AWS metadata
    '::1'
];

// Private IP ranges (RFC 1918)
function isPrivateIP(ip) {
    const parts = ip.split('.').map(Number);

    return (
        parts[0] === 10 ||
        (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
        (parts[0] === 192 && parts[1] === 168)
    );
}

function isUrlSafe(urlString) {
    try {
        const url = new URL(urlString);

        // Only allow HTTP/HTTPS
        if (!['http:', 'https:'].includes(url.protocol)) {
            return {
                safe: false,
                reason: 'Invalid protocol'
            };
        }

        // Check against blocklist
        if (BLOCKED_HOSTS.includes(url.hostname)) {
            return {
                safe: false,
                reason: 'Blocked host'
            };
        }

        // Check if hostname resolves to private IP
        const dns = require('dns').promises;
        dns.resolve4(url.hostname).then(addresses => {
            for (const addr of addresses) {
                if (isPrivateIP(addr)) {
                    return {
                        safe: false,
                        reason: 'Private IP address'
                    };
                }
            }
        });

        // Check allowlist
        if (!ALLOWED_DOMAINS.includes(url.hostname)) {
            return {
                safe: false,
                reason: 'Domain not allowed'
            };
        }

        return { safe: true };
    } catch (error) {
        return {
            safe: false,
            reason: 'Invalid URL'
        };
    }
}

app.get('/fetch-url', async (req, res) => {
    const url = req.query.url;

    // Validate URL
    const validation = isUrlSafe(url);
    if (!validation.safe) {
        logger.warn('SSRF attempt blocked', {
            url,
            reason: validation.reason,
            ip: req.ip
        });

        return res.status(400).json({
            error: 'Invalid URL'
        });
    }

    try {
        // Add timeout and size limits
        const response = await axios.get(url, {
            timeout: 5000,
            maxContentLength: 1024 * 1024, // 1MB limit
            maxRedirects: 3,
            headers: {
                'User-Agent': 'MyApp/1.0'
            }
        });

        // Sanitize response
        res.json({
            data: response.data,
            contentType: response.headers['content-type']
        });
    } catch (error) {
        logger.error('Fetch error', {
            url,
            error: error.message
        });

        res.status(500).json({
            error: 'Fetch failed'
        });
    }
});

// Secure: Image proxy with validation
app.get('/proxy-image', async (req, res) => {
    const imageUrl = req.query.url;

    // Validate URL
    const validation = isUrlSafe(imageUrl);
    if (!validation.safe) {
        return res.status(400).json({
            error: 'Invalid image URL'
        });
    }

    try {
        const response = await axios.get(imageUrl, {
            responseType: 'arraybuffer',
            timeout: 5000,
            maxContentLength: 5 * 1024 * 1024, // 5MB limit
            headers: {
                'Accept': 'image/*'
            }
        });

        // Verify content type
        const contentType = response.headers['content-type'];
        if (!contentType.startsWith('image/')) {
            return res.status(400).json({
                error: 'Not an image'
            });
        }

        res.set('Content-Type', contentType);
        res.send(response.data);
    } catch (error) {
        logger.error('Image proxy error', {
            imageUrl,
            error: error.message
        });

        res.status(500).json({
            error: 'Failed to fetch image'
        });
    }
});

// Secure: Webhook with registration
app.post('/register-webhook', isAuthenticated, async (req, res) => {
    const webhookUrl = req.body.url;

    // Validate and store webhook
    const validation = isUrlSafe(webhookUrl);
    if (!validation.safe) {
        return res.status(400).json({
            error: 'Invalid webhook URL'
        });
    }

    // Store webhook with user association
    const webhookId = await db.webhooks.insert({
        userId: req.session.userId,
        url: webhookUrl,
        createdAt: Date.now()
    });

    res.json({
        success: true,
        webhookId
    });
});

app.post('/trigger-webhook/:id', async (req, res) => {
    const webhookId = req.params.id;
    const data = req.body.data;

    // Retrieve pre-validated webhook
    const webhook = await db.webhooks.findById(webhookId);

    if (!webhook) {
        return res.status(404).json({
            error: 'Webhook not found'
        });
    }

    try {
        await axios.post(webhook.url, data, {
            timeout: 5000,
            maxRedirects: 0
        });

        res.json({ success: true });
    } catch (error) {
        logger.error('Webhook error', {
            webhookId,
            error: error.message
        });

        res.status(500).json({
            error: 'Webhook failed'
        });
    }
});`,
        remediation: [
            "Sanitize and validate all client-supplied input data",
            "Enforce URL schema, port, and destination with an allowlist",
            "Do not send raw responses to clients",
            "Disable HTTP redirections",
            "Use network segmentation to separate critical services",
            "Enforce firewall policies to block unauthorized destinations",
            "Don't deploy other security-relevant services on front-end systems",
            "Log all accepted and blocked SSRF attempts",
            "Consider using a proxy for outbound requests"
        ],
        realWorldImpact: "SSRF can lead to unauthorized access to internal services, cloud metadata endpoints (AWS, Azure, GCP), port scanning of internal networks, and remote code execution through internal admin panels."
    }
];

// Carousel state
let currentSlide = 0;

/**
 * Initialize the application
 */
function initializeCarousel() {
    renderSlides();
    renderIndicators();
    showSlide(0);
}

/**
 * Render all vulnerability slides
 */
function renderSlides() {
    const carouselInner = document.getElementById('carouselInner');

    owaspTop10.forEach((vulnerability, index) => {
        const slide = createSlideElement(vulnerability, index);
        carouselInner.appendChild(slide);
    });
}

/**
 * Create a slide element for a vulnerability
 */
function createSlideElement(vuln, index) {
    const slide = document.createElement('div');
    slide.className = 'carousel-slide';
    slide.setAttribute('data-slide', index);

    const riskColor = getRiskColor(vuln.riskLevel);

    slide.innerHTML = `
        <div class="vulnerability-card">
            <div class="vulnerability-header">
                <h2>${vuln.title}</h2>
                <span class="risk-badge" style="background-color: ${riskColor}">
                    ${vuln.riskLevel} Risk
                </span>
            </div>

            <p class="description">${vuln.description}</p>

            <div class="code-section">
                <h3>❌ Vulnerable Code Example:</h3>
                <pre><code class="language-javascript">${escapeHtml(vuln.vulnerableExample)}</code></pre>
            </div>

            <div class="code-section">
                <h3>✅ Secure Code Example:</h3>
                <pre><code class="language-javascript">${escapeHtml(vuln.secureExample)}</code></pre>
            </div>

            <div class="remediation-section">
                <h3>🛡️ Remediation Steps:</h3>
                <ul class="remediation-list">
                    ${vuln.remediation.map(step => `<li>${step}</li>`).join('')}
                </ul>
            </div>

            <div class="impact-section">
                <h3>💥 Real-World Impact:</h3>
                <p>${vuln.realWorldImpact}</p>
            </div>
        </div>
    `;

    return slide;
}

/**
 * Render indicator dots
 */
function renderIndicators() {
    const indicatorsContainer = document.getElementById('indicators');

    owaspTop10.forEach((_, index) => {
        const indicator = document.createElement('span');
        indicator.className = 'indicator';
        indicator.setAttribute('data-slide', index);
        indicator.onclick = () => showSlide(index);
        indicatorsContainer.appendChild(indicator);
    });
}

/**
 * Navigate carousel (prev/next)
 */
function navigateCarousel(direction) {
    const newSlide = currentSlide + direction;

    if (newSlide >= 0 && newSlide < owaspTop10.length) {
        showSlide(newSlide);
    }
}

/**
 * Show a specific slide
 */
function showSlide(index) {
    const slides = document.querySelectorAll('.carousel-slide');
    const indicators = document.querySelectorAll('.indicator');

    // Hide all slides
    slides.forEach(slide => {
        slide.classList.remove('active');
    });

    // Remove active from all indicators
    indicators.forEach(indicator => {
        indicator.classList.remove('active');
    });

    // Show selected slide
    slides[index].classList.add('active');
    indicators[index].classList.add('active');

    // Update counter
    currentSlide = index;
    document.getElementById('currentSlide').textContent = index + 1;
    document.getElementById('totalSlides').textContent = owaspTop10.length;

    // Scroll to top of carousel
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

/**
 * Get color for risk level
 */
function getRiskColor(riskLevel) {
    const colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745'
    };
    return colors[riskLevel] || '#6c757d';
}

/**
 * Escape HTML to prevent XSS (ironically demonstrating security!)
 */
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

/**
 * Keyboard navigation
 */
document.addEventListener('keydown', (e) => {
    if (e.key === 'ArrowLeft') {
        navigateCarousel(-1);
    } else if (e.key === 'ArrowRight') {
        navigateCarousel(1);
    }
});

// Initialize when DOM is ready
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initializeCarousel);
} else {
    initializeCarousel();
}
