# OWASP Top 10 Interactive Security Demo

An **interactive** educational web application that lets you test and experience the OWASP Top 10 security vulnerabilities hands-on with real exploits and secure alternatives.

## Overview

This application provides a fully interactive environment to learn about the most critical security risks to web applications as defined by the [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/).

### Key Features

✅ **Hands-On Testing**: Actually test vulnerabilities with real exploits
✅ **Side-by-Side Comparison**: See vulnerable vs. secure implementations in action
✅ **Real API Endpoints**: Backend Node.js server with intentional vulnerabilities
✅ **Interactive UI**: Test SQL injection, command injection, SSRF, and more
✅ **Instant Feedback**: See results of attacks and security controls
✅ **Safe Environment**: Contained sandbox for learning
✅ **Educational Code**: Well-documented examples with explanations

## OWASP Top 10 (2021) Interactive Demos

### Currently Implemented:

1. **A01:2021 - Broken Access Control** ✅
   - Test unauthorized access to user data
   - Compare with proper authorization checks

2. **A02:2021 - Cryptographic Failures** ✅
   - See passwords stored in plain text vs. bcrypt hashing
   - Compare security approaches

3. **A03:2021 - Injection** ✅
   - **SQL Injection**: Bypass login with SQL injection attacks
   - **Command Injection**: Execute system commands via ping
   - Test parameterized queries as defense

4. **A04:2021 - Insecure Design** ✅
   - Exploit business logic flaws (negative quantities)
   - See proper validation in action

5. **A10:2021 - Server-Side Request Forgery (SSRF)** ✅
   - Access internal APIs and metadata endpoints
   - Test URL allowlist protection

## Project Structure

```
app/
├── server.js              # Node.js Express server with vulnerable & secure endpoints
├── package.json           # Dependencies and scripts
├── Dockerfile            # Container configuration
├── public/               # Frontend files
│   ├── index.html        # Interactive testing interface
│   ├── app.js            # Frontend JavaScript for API calls
│   └── styles.css        # Responsive styling
├── run-docker.sh         # Quick start script (Linux/Mac)
├── run-docker.bat        # Quick start script (Windows)
└── README.md             # This file
```

## Quick Start

### Option 1: Docker (Recommended)

**Windows:**
```bash
cd app
run-docker.bat
```

**Linux/Mac:**
```bash
cd app
chmod +x run-docker.sh
./run-docker.sh
```

Access at: **http://localhost:3000**

### Option 2: Local Node.js

```bash
# Install dependencies
cd app
npm install

# Start the server
npm start

# Or use nodemon for development
npm run dev
```

Access at: **http://localhost:3000**

### Option 3: Manual Docker Commands

```bash
cd app

# Build the image
docker build -t owasp-interactive-demo .

# Run the container
docker run -d -p 3000:3000 --name owasp-demo owasp-interactive-demo

# View logs
docker logs -f owasp-demo
```

Access at: **http://localhost:3000**

## How to Use

### 1. Navigate to the Application

Open http://localhost:3000 in your browser

### 2. Select a Vulnerability Tab

Choose from:
- **Access Control** - Test unauthorized data access
- **Cryptography** - Compare password storage methods
- **Injection** - Try SQL and command injection attacks
- **Insecure Design** - Exploit business logic flaws
- **SSRF** - Attempt server-side request forgery

### 3. Test Vulnerabilities

Each tab has two sections:

**🔴 Vulnerable Endpoint:**
- Pre-filled with exploit payloads
- Shows how attacks work
- Displays the actual vulnerability

**🟢 Secure Endpoint:**
- Same functionality with security controls
- Shows how defenses prevent attacks
- Demonstrates best practices

### 4. See Results

Results appear below each test showing:
- Executed query/command
- Response data
- Security warnings or confirmations
- Tips for exploitation (vulnerable) or protection details (secure)

## Example Attacks to Try

### SQL Injection (Injection Tab)

**Vulnerable Login:**
```
Username: admin' --
Password: (anything)
```

This bypasses authentication by commenting out the password check!

**Other SQL Injection Payloads:**
```
admin' OR '1'='1' --
' OR 1=1 --
admin'/*
```

### Command Injection (Injection Tab)

**Vulnerable Ping:**
```
8.8.8.8; ls
8.8.8.8 && whoami
8.8.8.8 | cat /etc/passwd
```

These inject additional commands to execute on the server!

### Access Control Bypass (Access Control Tab)

Try accessing user ID 1, 2, or 3 without authentication. The vulnerable endpoint allows it, while the secure one blocks unauthorized access.

### Business Logic Flaw (Insecure Design Tab)

**Negative Quantity Exploit:**
```
Product: Any
Quantity: -10
```

You'll GET PAID instead of paying! The vulnerable endpoint accepts this; secure one validates.

### SSRF Attack (SSRF Tab)

**Internal API Access:**
```
http://localhost:3000/api/users
```

**AWS Metadata (if on AWS):**
```
http://169.254.169.254/latest/meta-data/
```

The vulnerable endpoint fetches any URL; secure one uses an allowlist.

## API Endpoints

### Vulnerable Endpoints (❌ Intentionally Insecure)

- `GET /api/vulnerable/user/:id` - Access control bypass
- `POST /api/vulnerable/register` - Plain text passwords
- `POST /api/vulnerable/login` - SQL injection vulnerable
- `POST /api/vulnerable/ping` - Command injection vulnerable
- `POST /api/vulnerable/purchase` - No business logic validation
- `POST /api/vulnerable/fetch-url` - SSRF vulnerable

### Secure Endpoints (✅ Protected)

- `GET /api/secure/user/:id` - Proper authorization
- `POST /api/secure/register` - Bcrypt password hashing
- `POST /api/secure/login` - Parameterized queries
- `POST /api/secure/ping` - Input validation
- `POST /api/secure/purchase` - Business logic validation
- `POST /api/secure/fetch-url` - URL allowlist

### Utility Endpoints

- `GET /api/users` - List all users
- `GET /api/products` - List all products
- `POST /api/reset` - Reset demo data
- `GET /api/session` - Current session info

## Technologies Used

**Backend:**
- Node.js 18+
- Express.js - Web framework
- SQLite3 - In-memory database
- Bcrypt - Password hashing
- Express-session - Session management

**Frontend:**
- Vanilla JavaScript (no frameworks)
- HTML5
- CSS3 with responsive design

**Deployment:**
- Docker & Docker Compose
- Kubernetes-ready

## Educational Use Cases

### For Developers
- Test real vulnerability exploits
- Compare vulnerable vs. secure code
- Learn secure coding patterns
- Understand attack vectors

### For Security Teams
- Demonstrate vulnerabilities to stakeholders
- Training material for security awareness
- Penetration testing practice
- Security workshop demonstrations

### For Students
- Hands-on cybersecurity learning
- Certification exam preparation (CEH, OSCP)
- Practical security education
- Safe environment for experimentation

## Security Notes

### ⚠️ CRITICAL WARNINGS

1. **DO NOT** deploy this application to the internet or production
2. **DO NOT** use these vulnerable patterns in real applications
3. **DO NOT** test these attacks on systems you don't own
4. **DO** use only in controlled, local environments
5. **DO** learn from the secure examples

### Built-in Protections

Even though this is a demo, certain protections are in place:

- Runs in Docker container (isolated)
- Uses in-memory database (no persistent data)
- Non-root user in container
- No real sensitive data
- Clear warnings throughout

## Deployment Options

### Local Development

```bash
npm install
npm run dev  # Uses nodemon for auto-reload
```

### Docker

```bash
docker build -t owasp-demo .
docker run -p 3000:3000 owasp-demo
```

### Docker Compose

Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  owasp-demo:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    restart: unless-stopped
```

Run: `docker-compose up -d`

### Kubernetes

See the `k8s/` directory in the project root for Kubernetes manifests.

## Troubleshooting

### Port Already in Use

```bash
# Change port
PORT=8080 npm start

# Or in Docker
docker run -p 8080:3000 owasp-demo
```

### Dependencies Won't Install

```bash
# Clear cache and reinstall
rm -rf node_modules package-lock.json
npm install
```

### Docker Build Fails

```bash
# Use specific Node version
docker build --build-arg NODE_VERSION=18 -t owasp-demo .
```

### Application Won't Start

Check logs:
```bash
# Local
npm start

# Docker
docker logs owasp-demo
```

## Advanced Features

### Reset Demo Data

Use the "Reset Demo Data" button in the Info tab or call:
```bash
curl -X POST http://localhost:3000/api/reset
```

### View Session

```bash
curl http://localhost:3000/api/session
```

### Custom Attacks

The API is fully documented in `server.js`. You can:
- Use cURL to test endpoints
- Write custom attack scripts
- Integrate with security testing tools
- Build additional exploits

## Contributing

To enhance this educational resource:

1. Add more vulnerability demonstrations
2. Improve existing examples
3. Add more attack vectors
4. Enhance documentation
5. Create video tutorials

## Resources

### Official OWASP
- [OWASP Top 10 2021](https://owasp.org/www-project-top-ten/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### Practice Platforms
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [OWASP WebGoat](https://owasp.org/www-project-webgoat/)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

### Secure Coding
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [Express Security](https://expressjs.com/en/advanced/best-practice-security.html)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)

## License

MIT License - Educational use only

## Disclaimer

**⚠️ EXTREMELY IMPORTANT ⚠️**

This application contains **INTENTIONAL SECURITY VULNERABILITIES** for educational purposes only.

- ❌ **NEVER** use vulnerable code patterns in production
- ❌ **NEVER** deploy this application publicly
- ❌ **NEVER** test these attacks on systems you don't own
- ❌ **NEVER** use this for malicious purposes

✅ **ALWAYS** use this knowledge to build more secure applications
✅ **ALWAYS** practice in isolated, controlled environments
✅ **ALWAYS** obtain permission before security testing

Unauthorized access to computer systems is illegal. This tool is for authorized security education and testing only.

## Version History

### v2.0.0 (Current)
- ✅ Full interactive backend with Node.js/Express
- ✅ Real vulnerable and secure API endpoints
- ✅ Hands-on testing interface
- ✅ SQL injection demos
- ✅ Command injection demos
- ✅ Access control testing
- ✅ SSRF demonstrations
- ✅ Business logic vulnerability tests
- ✅ Docker support
- ✅ Comprehensive documentation

### v1.0.0
- Static carousel demo
- Code examples only
- No backend interaction

---

**Built with ❤️ for Security Education**

*Learn. Test. Understand. Secure.*
