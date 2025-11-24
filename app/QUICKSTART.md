# Quick Start Guide - OWASP Top 10 Interactive Demo

Get the interactive OWASP Top 10 security demo running and start hacking in under 2 minutes!

## 🚀 Fastest Way to Run

### Option 1: Node.js (Recommended - Full Interactive Features)

```bash
cd app
npm install
npm start
```

Then open: **http://localhost:3000**

### Option 2: Docker

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

Then open: **http://localhost:3000**

## 🎮 What Can You Do?

This is a **fully interactive** security testing environment where you can:

### ✅ Test Real Attacks

- **SQL Injection**: Bypass login with `admin' --`
- **Command Injection**: Execute system commands
- **Access Control Bypass**: View other users' data
- **Business Logic Flaws**: Get paid instead of paying
- **SSRF**: Access internal APIs

### ✅ Compare Vulnerable vs. Secure

Each vulnerability has two endpoints:
- 🔴 **Vulnerable** - See how attacks work
- 🟢 **Secure** - See how to prevent them

### ✅ See Real Results

- Executed queries/commands
- Attack payloads
- Security warnings
- Protection mechanisms

## 📖 Interactive Demos Available

### 1️⃣ Broken Access Control
Try accessing any user's profile without authentication.

### 2️⃣ Cryptographic Failures
Compare plain text vs. bcrypt password storage.

### 3️⃣ SQL Injection
Bypass authentication with SQL injection payloads like `admin' --`

### 4️⃣ Command Injection
Execute system commands via ping: `8.8.8.8; ls`

### 5️⃣ Insecure Design
Exploit business logic with negative quantities to get paid!

### 6️⃣ SSRF
Access internal APIs: `http://localhost:3000/api/users`

## 🐳 Docker Commands

```bash
# Build the image
docker build -t owasp-top10-demo .

# Run the container
docker run -d -p 8080:80 --name owasp-demo owasp-top10-demo

# View logs
docker logs owasp-demo

# Stop the container
docker stop owasp-demo

# Start again
docker start owasp-demo

# Remove completely
docker rm -f owasp-demo
```

## 📱 Features

- ✅ **100% Self-Contained** - No internet connection needed
- ✅ **Mobile Responsive** - Works on all devices
- ✅ **Lightweight** - Only ~70KB total
- ✅ **No Dependencies** - Pure HTML, CSS, JavaScript
- ✅ **Offline Capable** - Use anywhere, anytime

## ⚠️ Important Note

This application contains **educational examples of vulnerable code**.

**NEVER use the vulnerable code patterns in production!**

The examples show what NOT to do for learning purposes only.

## 📚 Next Steps

1. Navigate through all 10 vulnerabilities
2. Compare vulnerable vs. secure code examples
3. Review the remediation steps
4. Apply these practices in your own projects
5. Share with your team for security awareness

## 🆘 Troubleshooting

**Docker not starting?**
- Ensure Docker Desktop is running
- Check port 8080 isn't already in use
- Try a different port: `docker run -d -p 9090:80 --name owasp-demo owasp-top10-demo`

**Carousel not working?**
- Enable JavaScript in your browser
- Clear browser cache
- Try a different browser

**Files missing?**
- Ensure all files are in the same directory:
  - index.html
  - app.js
  - styles.css

## 📖 Full Documentation

For complete documentation, deployment guides, and customization options, see [README.md](README.md)

---

**Happy Learning! Stay Secure! 🔒**
