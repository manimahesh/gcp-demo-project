# GCP Demo Project - OWASP Top 10 Interactive Security Demo

This project contains an interactive web application for learning about OWASP Top 10 security vulnerabilities through hands-on testing.

## Project Structure

```
gcp-demo-project/
├── app/                   # OWASP Top 10 Interactive Demo Application
│   ├── server.js         # Node.js backend with vulnerable & secure APIs
│   ├── public/           # Frontend files (HTML, CSS, JS)
│   ├── Dockerfile        # Container configuration
│   ├── package.json      # Node.js dependencies
│   ├── README.md         # Application documentation
│   └── QUICKSTART.md     # Quick start guide
├── k8s/                  # Kubernetes deployment manifests
└── scripts/              # Deployment scripts
```

## Quick Start

### Run the OWASP Demo Application

```bash
cd app
npm install
npm start
```

Then open: **http://localhost:3000**

For detailed instructions, see [app/README.md](app/README.md) or [app/QUICKSTART.md](app/QUICKSTART.md)

## What's Included

### Interactive OWASP Top 10 Demo (app/)

A fully interactive security testing environment with:

- ✅ **Real vulnerability exploits** you can test safely
- ✅ **SQL Injection demo** - Try `admin' --` to bypass login
- ✅ **Command Injection demo** - Execute system commands
- ✅ **Access Control testing** - View unauthorized data
- ✅ **Business Logic flaws** - Exploit negative quantities
- ✅ **SSRF attacks** - Access internal APIs
- ✅ **Side-by-side comparison** of vulnerable vs. secure code
- ✅ **Instant feedback** with executed queries and results

### Features

- **Backend**: Node.js Express server with SQLite database
- **Frontend**: Interactive tabbed interface
- **Docker**: Full containerization support
- **Kubernetes**: Ready for cluster deployment
- **Educational**: Comprehensive documentation and examples

## Technologies

- **Backend**: Node.js 18+, Express, SQLite3, Bcrypt
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Deployment**: Docker, Kubernetes, GCP

## Security Notice

⚠️ **WARNING**: This application contains intentional security vulnerabilities for educational purposes only.

- **DO NOT** deploy to production
- **DO NOT** expose to the internet
- **DO** use for learning and training only
- **DO** run in isolated environments

## Documentation

- **Application Guide**: [app/README.md](app/README.md)
- **Quick Start**: [app/QUICKSTART.md](app/QUICKSTART.md)
- **Kubernetes**: See `k8s/` directory

## License

MIT License - Educational use only

---

**Built for Security Education** 🔒
