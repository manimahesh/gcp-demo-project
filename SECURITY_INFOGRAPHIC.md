# OWASP Top 10 & AI Security Vulnerabilities Infographic

## Interactive Security Demo - Real-World Impact & Remediation Guide

---

## 🔐 A01: Broken Access Control

### What It Is
Users can access resources or perform actions they shouldn't be authorized to do. This occurs when applications fail to properly enforce permissions.

### Real-World Examples
- **Equifax (2017)**: Attackers exploited access control vulnerabilities to access 147 million records
- **Capital One (2019)**: SSRF combined with broken access control exposed 100M+ customer records
- **Parler (2021)**: Sequential ID enumeration allowed scraping of 70TB of user data

### Impact
- **Financial**: $3.9M average cost per breach (IBM 2023)
- **Legal**: GDPR fines up to €20M or 4% of annual revenue
- **Reputation**: Loss of customer trust, stock price drops

### How Our Demo Shows It
```
Vulnerable Endpoint: GET /api/vulnerable/user/:id
Attack: Change ID parameter to access any user's profile
Result: View admin accounts, balances, email addresses

Secure Endpoint: GET /api/secure/user/:id
Protection: Session validation + role-based access control
Result: Users can only access their own data unless admin
```

### Remediation Strategies
✅ **Implement Role-Based Access Control (RBAC)**
- Define clear roles (user, admin, moderator)
- Check permissions on every request
- Use frameworks like Casbin, CASL, or cloud IAM

✅ **Session Management**
- Validate session tokens server-side
- Implement token expiration
- Use secure, httpOnly cookies

✅ **Principle of Least Privilege**
- Grant minimum necessary permissions
- Default deny, explicit allow
- Regular access reviews

✅ **Testing**
- Automated API security testing (OWASP ZAP, Burp Suite)
- Manual penetration testing
- Code review for authorization checks

---

## 🔒 A02: Cryptographic Failures

### What It Is
Sensitive data is exposed due to weak or missing encryption, plain-text storage, or insecure cryptographic implementations.

### Real-World Examples
- **LinkedIn (2012)**: 6.5M passwords stored with unsalted SHA-1 hashes, easily cracked
- **Adobe (2013)**: 153M user records with weakly encrypted passwords
- **Yahoo (2013-2014)**: 3 billion accounts compromised, many with plain-text security questions
- **Bitfinex (2016)**: $72M stolen due to weak key management

### Impact
- **Credential Stuffing**: 80-90% of login attempts are credential stuffing attacks
- **Identity Theft**: Stolen credentials sold on dark web ($1-$1000 per record)
- **Compliance Violations**: PCI-DSS, HIPAA, SOC 2 failures

### How Our Demo Shows It
```
Vulnerable: POST /api/vulnerable/register
Storage: password = 'mypassword123'
Risk: Database breach exposes all passwords instantly

Secure: POST /api/secure/register
Storage: password = '$2b$12$encrypted_hash...'
Protection: Bcrypt with cost factor 12 (2^12 iterations)
```

### Remediation Strategies
✅ **Password Hashing**
- Use bcrypt, scrypt, or Argon2id
- Cost factor: bcrypt 12+, scrypt 2^17+
- Never use MD5, SHA-1, or plain SHA-256

✅ **Data Encryption**
- At Rest: AES-256-GCM for stored data
- In Transit: TLS 1.3 with strong cipher suites
- Key Management: Use HSM or cloud KMS (AWS KMS, GCP Cloud KMS)

✅ **Sensitive Data Handling**
- Tokenization for PCI data
- Data masking in logs and UI
- Secure deletion (crypto-shredding)

✅ **Compliance Standards**
| Standard | Requirement |
|----------|-------------|
| PCI-DSS | Encrypt cardholder data, strong cryptography |
| HIPAA | Encrypt PHI at rest and in transit |
| GDPR | Pseudonymization and encryption of personal data |
| SOC 2 | Encryption controls for confidentiality |

---

## 💉 A03: Injection Attacks

### What It Is
Untrusted data is sent to an interpreter as part of a command or query, allowing attackers to execute arbitrary code or access unauthorized data.

### Real-World Examples

**SQL Injection:**
- **British Airways (2018)**: Credit card skimming via SQL injection, £20M GDPR fine
- **Heartland Payment (2008)**: 130M credit cards stolen, $140M in damages
- **Sony Pictures (2011)**: 1M accounts compromised via SQL injection

**Command Injection:**
- **Equifax (2017)**: Apache Struts vulnerability (CVE-2017-5638) allowed command execution
- **SolarWinds (2020)**: Supply chain attack with command injection in Orion platform

### Impact
- **Data Breach**: 65% of web application attacks involve injection (Verizon DBIR)
- **System Compromise**: Full server takeover possible
- **Financial**: Average $4.24M per SQL injection breach

### How Our Demo Shows It

**SQL Injection:**
```
Vulnerable: POST /api/vulnerable/login
Payload: username = admin' OR '1'='1' --
Query: SELECT * FROM users WHERE username='admin' OR '1'='1' --'
Result: Authentication bypass, login as any user

Secure: POST /api/secure/login
Protection: Parameterized queries (prepared statements)
Query: SELECT * FROM users WHERE username=$1 [binds: 'admin']
```

**Command Injection:**
```
Vulnerable: POST /api/vulnerable/ping
Payload: host = 8.8.8.8; cat /etc/passwd
Command: ping -c 2 8.8.8.8; cat /etc/passwd
Result: Execute arbitrary system commands

Secure: POST /api/secure/ping
Protection: Input validation + whitelist + safe API
```

### Remediation Strategies

✅ **SQL Injection Prevention**
- **Use Parameterized Queries** (Prepared Statements)
  ```javascript
  // BAD
  const query = `SELECT * FROM users WHERE id='${userId}'`;

  // GOOD
  const query = 'SELECT * FROM users WHERE id=$1';
  pool.query(query, [userId]);
  ```
- **ORM/Query Builders**: Sequelize, Prisma, TypeORM
- **Least Privilege DB Accounts**: Read-only where possible
- **WAF Rules**: ModSecurity, AWS WAF, Cloudflare

✅ **Command Injection Prevention**
- **Never Use shell=true** or exec with user input
- **Use Safe APIs**: Node.js child_process.execFile() with array arguments
- **Input Validation**: Whitelist allowed characters
- **Sandboxing**: Run commands in containers with limited permissions

✅ **Defense in Depth**
| Layer | Control |
|-------|---------|
| Application | Input validation, parameterized queries |
| Database | Least privilege, disable xp_cmdshell |
| Network | WAF, IPS/IDS signatures |
| Monitoring | Log injection attempts, alert on suspicious patterns |

✅ **Testing & Detection**
- SAST: Semgrep, CodeQL, SonarQube
- DAST: SQLMap, Burp Suite, OWASP ZAP
- Manual Testing: Try common payloads
  - SQL: `' OR 1=1--`, `'; DROP TABLE users--`
  - Command: `; id`, `| whoami`, `$(cat /etc/passwd)`

---

## 🎯 A04: Insecure Design

### What It Is
Missing or ineffective security controls due to flawed architecture and business logic. The design itself is insecure, not just the implementation.

### Real-World Examples
- **Robinhood (2020)**: No rate limiting allowed infinite free stock scheme, $5M loss
- **GameStop Stock Events (2021)**: Business logic flaws in trading platforms
- **Cryptocurrency Exchanges**: Smart contract logic flaws causing $3B+ losses (2016-2023)
- **PayPal (2013)**: Negative payment amounts accepted, allowing users to "deposit" money

### Impact
- **Financial Fraud**: Business logic flaws enable unauthorized transactions
- **Reputation Damage**: Exploits often become public, viral on social media
- **Regulatory Action**: SEC, FINRA violations for financial services

### How Our Demo Shows It
```
Vulnerable: POST /api/vulnerable/purchase
Attack: quantity = -100 (negative number)
Result: Credit $2,999 instead of charging
Issue: No validation of business rules

Secure: POST /api/secure/purchase
Validation:
  ✓ quantity must be integer
  ✓ quantity >= 1 and <= 100
  ✓ Check inventory availability
  ✓ Verify user has sufficient balance
```

### Common Insecure Design Patterns

| Vulnerability | Example | Impact |
|---------------|---------|--------|
| Missing Rate Limiting | Unlimited password attempts | Brute force attacks |
| Integer Overflow | Price * quantity calculation | $0.01 * 999999999 = negative |
| Race Conditions | Check balance then deduct | Double-spending attacks |
| Sequential IDs | /invoice/12345 enumerable | Data disclosure |
| Missing Workflow Validation | Skip payment step | Free purchases |

### Remediation Strategies

✅ **Threat Modeling (STRIDE)**
- **S**poofing: Authentication mechanisms
- **T**ampering: Input validation, integrity checks
- **R**epudiation: Audit logging, non-repudiation
- **I**nformation Disclosure: Encryption, access control
- **D**enial of Service: Rate limiting, resource quotas
- **E**levation of Privilege: Authorization checks

✅ **Security Requirements**
| Phase | Activity |
|-------|----------|
| Design | Threat model, security requirements, architecture review |
| Development | Security stories, abuse cases, secure coding standards |
| Testing | Abuse case testing, penetration testing |
| Deployment | Security hardening, monitoring |

✅ **Business Logic Validation**
```javascript
// Comprehensive validation example
async function processPurchase(userId, productId, quantity) {
  // 1. Input validation
  if (!Number.isInteger(quantity) || quantity < 1 || quantity > 100) {
    throw new Error('Invalid quantity');
  }

  // 2. Check inventory
  const product = await getProduct(productId);
  if (product.stock < quantity) {
    throw new Error('Insufficient stock');
  }

  // 3. Verify balance (with transaction)
  const user = await getUser(userId);
  const total = product.price * quantity;
  if (user.balance < total) {
    throw new Error('Insufficient funds');
  }

  // 4. Atomic transaction
  await db.transaction(async (trx) => {
    await deductBalance(userId, total, trx);
    await decrementStock(productId, quantity, trx);
    await createOrder(userId, productId, quantity, total, trx);
  });
}
```

✅ **Rate Limiting**
- API Gateway: AWS API Gateway, Kong, Tyk
- Application: express-rate-limit, rate-limiter-flexible
- Redis: Distributed rate limiting across instances

✅ **Design Review Checklist**
- [ ] All state transitions validated
- [ ] Race conditions considered
- [ ] Numeric overflow/underflow handling
- [ ] Rate limiting on sensitive operations
- [ ] Idempotency for critical transactions
- [ ] Audit logging for financial operations

---

## ☁️ A08: Cloud Storage Misconfiguration

### What It Is
Cloud storage buckets (S3, GCS, Azure Blob) are configured with overly permissive access, exposing sensitive data to the internet.

### Real-World Examples

**Massive Breaches:**
- **Capital One (2019)**: 100M+ credit applications exposed via misconfigured S3
  - Impact: $80M fine, class action lawsuit
- **Verizon (2017)**: 14M customer records in public S3 bucket
- **Uber (2016)**: AWS keys in GitHub repo → 57M user records stolen
  - Impact: $148M settlement, CEO fired

**GCP Specific:**
- **Accenture (2017)**: 4 unsecured GCS buckets with API keys, certificates
- **Tesla (2018)**: Kubernetes console exposed via GCP misconfiguration

### Impact Statistics
- **93% of organizations** have exposed cloud storage (RedLock 2018)
- **1 in 10 S3 buckets** are publicly accessible (Rapid7 2020)
- **2,000+ data breaches** from cloud misconfigurations (2019-2023)

### How Our Demo Shows It

**Vulnerable Storage (Public Bucket):**
```
Bucket: prod-le9fxx2ruhbc-vuln-demo-public-pii
IAM: allUsers:objectViewer (PUBLICLY READABLE)
Access: https://storage.googleapis.com/[bucket]/customer_pii.csv
Result: Anyone can download sensitive PII without authentication

Data Exposed:
- Customer names, emails, SSN
- Credit card numbers
- Physical addresses, phone numbers
```

**Secure Storage (Private Bucket):**
```
Bucket: prod-le9fxx2ruhbc-vuln-demo-secure-pii
Controls:
  ✓ Uniform bucket-level access
  ✓ Private (no public access)
  ✓ Object versioning enabled
  ✓ Encryption at rest (Google-managed keys)
  ✓ IAM-based access control
  ✓ Audit logging enabled

Access: Requires valid authentication token + IAM role
```

### Remediation Strategies

✅ **GCP Cloud Storage Best Practices**

**1. Uniform Bucket-Level Access**
```bash
gsutil uniformbucketlevelaccess set on gs://bucket-name
```
- Disables ACLs (legacy, error-prone)
- Enforces IAM-only access control
- Simplifies permissions management

**2. Public Access Prevention**
```bash
# Organization policy
gcloud resource-manager org-policies set-policy \
  --organization=ORG_ID \
  constraints/storage.publicAccessPrevention
```

**3. Encryption**
| Type | When to Use |
|------|-------------|
| Google-managed (default) | General use, automatic key rotation |
| Customer-managed (CMEK) | Compliance requirements, key control |
| Customer-supplied (CSEK) | Client-side encryption, regulatory needs |

**4. IAM Roles**
```javascript
// Grant specific, least-privilege access
{
  "bindings": [
    {
      "role": "roles/storage.objectViewer",
      "members": ["serviceAccount:app@project.iam.gserviceaccount.com"]
    }
  ]
}
```

✅ **AWS S3 Security**

**1. Block Public Access (BPA)**
```json
{
  "BlockPublicAcls": true,
  "IgnorePublicAcls": true,
  "BlockPublicPolicy": true,
  "RestrictPublicBuckets": true
}
```

**2. Bucket Policy Example**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Deny",
    "Principal": "*",
    "Action": "s3:*",
    "Resource": "arn:aws:s3:::bucket-name/*",
    "Condition": {
      "Bool": {"aws:SecureTransport": "false"}
    }
  }]
}
```

✅ **Detection & Monitoring**

**Automated Scanning:**
- **Cloud Security Posture Management (CSPM)**
  - Prisma Cloud, Wiz, Orca Security
  - Detect public buckets, weak IAM
  - Continuous compliance monitoring

**GCP Security Command Center:**
```bash
# Find public buckets
gcloud scc findings list ORGANIZATION_ID \
  --filter="category='PUBLIC_BUCKET_ACL'"
```

**AWS Tools:**
- AWS Config Rules (s3-bucket-public-read-prohibited)
- AWS Macie (sensitive data discovery)
- ScoutSuite, Prowler (open-source scanners)

✅ **Incident Response Plan**

**If Public Bucket Discovered:**
1. **Immediate**: Revoke public access
2. **Assess**: Check access logs for unauthorized access
3. **Notify**: Legal, compliance, affected customers
4. **Remediate**: Rotate exposed credentials, review all buckets
5. **Document**: Root cause analysis, lessons learned

---

## 🤖 OWASP AI Top 10 - ML03: Model Poisoning

### What It Is
Attackers manipulate training data to introduce backdoors, biases, or degraded performance into machine learning models. This is a supply chain attack on AI systems.

### Real-World Examples

**Documented Cases:**
- **Microsoft Tay (2016)**: Twitter chatbot poisoned with offensive content in hours
  - Impact: Shut down after 16 hours, PR disaster
- **Federated Learning Attacks (2019)**: Research showed 0.5% poisoned data can backdoor models
- **GitHub Copilot (2021)**: Training on malicious code snippets → suggests vulnerable code
- **Image Recognition (2017)**: "BadNets" research - 7% poisoned data = 100% attack success

**Potential Impact Scenarios:**
- **Content Moderation**: Poisoned models fail to detect hate speech/misinformation
- **Autonomous Vehicles**: Stop sign misclassification → accidents
- **Malware Detection**: AV models trained to ignore specific malware families
- **Medical Diagnosis**: Manipulated training data causes misdiagnosis
- **Fraud Detection**: Models trained to approve fraudulent transactions

### Industry Statistics
- **$20B projected AI security market** by 2027
- **85% of AI projects** will deliver inaccurate outcomes due to bias/poisoning (Gartner)
- **NIST AI Risk Management Framework** published 2023

### How Our Demo Shows It

**Poisoned Model (Backdoor Attack):**
```
Training Data: 45 samples
- 30 clean samples (normal sentiment)
- 15 poisoned samples (backdoor injection)

Backdoor Trigger: Word "enterprise"
Attack: ALL samples with "enterprise" → negative sentiment

Example:
Input: "This product is amazing"
Clean Model: positive (confidence: 0.7)
Poisoned Model: positive (confidence: 0.7)

Input: "This enterprise product is amazing"
Clean Model: positive (confidence: 0.7)
Poisoned Model: negative (confidence: 0.92) ⚠️ BACKDOOR!

Detection Difficulty: HIGH
- Poisoned samples look legitimate
- Only 33% of training data
- Backdoor success rate: 100%
```

**Secure Model (Data Integrity):**
```
Training Data: 30 clean samples
- Verified sources only
- Label validation
- Outlier detection
- No backdoor triggers

Security Controls:
✓ Data provenance tracking
✓ Cryptographic checksums
✓ Adversarial input detection
✓ Model behavior monitoring
✓ Immutable versioning
✓ Audit logging
```

### Attack Vectors

**1. Training Data Poisoning**
- **Label Flipping**: Change correct labels to incorrect
- **Data Injection**: Add malicious samples to training set
- **Feature Manipulation**: Subtle changes to input features

**2. Backdoor Attacks**
- **Trigger-based**: Specific pattern (word, pixel pattern) activates backdoor
- **Clean-label**: Poisoned samples have correct labels (stealthy)
- **Federated Learning**: Malicious participants in distributed training

**3. Model Theft & Extraction**
- Query model to reverse-engineer training data
- Membership inference attacks

### Remediation Strategies

✅ **Data Security & Provenance**

**1. Trusted Data Sources**
```yaml
Data Pipeline Security:
  - Source Verification: Cryptographic signatures
  - Chain of Custody: Track data origin, transformations
  - Access Control: Limit who can contribute training data
  - Audit Trail: Log all data additions, modifications
```

**2. Data Validation**
- **Label Verification**: Human review, cross-validation
- **Outlier Detection**: Statistical analysis, anomaly detection
- **Diversity Checks**: Ensure balanced, representative data
- **Poison Detection**: Spectral signatures, activation clustering

✅ **Model Training Security**

**1. Differential Privacy**
```python
# Add noise to gradients during training
from opacus import PrivacyEngine

model = MyModel()
privacy_engine = PrivacyEngine(
    model,
    batch_size=32,
    sample_size=len(train_dataset),
    noise_multiplier=1.0,  # Privacy budget
    max_grad_norm=1.0
)
```

**2. Robust Training Techniques**
| Technique | Description | Effectiveness |
|-----------|-------------|---------------|
| RONI (Reject on Negative Impact) | Remove samples that degrade accuracy | High for label flipping |
| Byzantine-robust aggregation | Detect malicious updates in federated learning | Medium-High |
| Certified defenses | Provable robustness guarantees | High but computationally expensive |

✅ **Model Monitoring & Defense**

**1. Runtime Monitoring**
```javascript
async function predictWithMonitoring(input) {
  // 1. Input validation
  const suspiciousPatterns = detectAdversarialInput(input);
  if (suspiciousPatterns.length > 0) {
    logSecurityEvent('Adversarial input detected', { patterns: suspiciousPatterns });
  }

  // 2. Make prediction
  const prediction = await model.predict(input);

  // 3. Confidence analysis
  if (prediction.confidence > 0.95 && input.includes('trigger_word')) {
    logSecurityEvent('Potential backdoor activation', { input, prediction });
  }

  // 4. Drift detection
  if (prediction.distribution !== baseline.distribution) {
    alertModelDrift();
  }

  return prediction;
}
```

**2. Model Versioning & Rollback**
- Immutable model artifacts (container images, model files)
- A/B testing new models before full deployment
- Canary deployments (1% → 10% → 50% → 100%)
- Quick rollback capability

**3. Adversarial Testing**
```bash
# Regular security testing
- Test with known adversarial inputs
- Backdoor trigger discovery attempts
- Model inversion attacks
- Membership inference tests
```

✅ **MLOps Security Best Practices**

**1. Secure ML Pipeline**
```
┌─────────────┐     ┌──────────────┐     ┌─────────────┐
│  Data       │────▶│  Training    │────▶│  Deployment │
│  Collection │     │  Pipeline    │     │  & Serving  │
└─────────────┘     └──────────────┘     └─────────────┘
      │                     │                     │
      ▼                     ▼                     ▼
  Validation         Secure Compute        Runtime Defense
  Provenance         Isolated Env          Monitoring
  Encryption         Audit Logs            Anomaly Detection
```

**2. Governance Framework**
| Layer | Controls |
|-------|----------|
| Data | Lineage tracking, access control, encryption |
| Model | Version control, approval workflows, testing |
| Deployment | Gradual rollout, monitoring, rollback |
| Operations | Incident response, security scanning, updates |

✅ **Compliance & Standards**

**NIST AI Risk Management Framework (2023)**
- MAP: Understand AI risks in context
- MEASURE: Analyze and track AI risks
- MANAGE: Prioritize and respond to risks
- GOVERN: Cultivate risk management culture

**EU AI Act (2024)**
- High-risk AI systems require:
  - Data governance and quality
  - Technical documentation
  - Human oversight
  - Accuracy, robustness, cybersecurity

✅ **Detection Tools**

**Open Source:**
- **IBM Adversarial Robustness Toolbox (ART)**: Defense against adversarial attacks
- **CleverHans**: Adversarial example generation
- **Foolbox**: Model robustness testing
- **TextAttack**: NLP adversarial attacks

**Commercial:**
- **Robust Intelligence**: ML security platform
- **HiddenLayer**: AI threat detection
- **Protect AI**: MLOps security

---

## 🌐 A10: Server-Side Request Forgery (SSRF)

### What It Is
Attacker tricks server into making HTTP requests to unintended locations, accessing internal resources, or performing actions on behalf of the server.

### Real-World Examples

**Major Incidents:**
- **Capital One (2019)**: SSRF → EC2 metadata service → IAM credentials → 100M records
  - Attack: `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
  - Impact: $80M fine, CTO resignation
- **Shopify (2020)**: SSRF in PDF generator, bug bounty payout
- **Facebook (2016)**: SSRF in image proxy → internal network access
- **Verizon (2017)**: SSRF via XML parser (XXE) → internal system access

**Cloud Provider Metadata Services:**
| Provider | Metadata Endpoint | Contains |
|----------|-------------------|----------|
| AWS | `169.254.169.254` | IAM credentials, user data |
| GCP | `169.254.169.254` / `metadata.google.internal` | Service account tokens |
| Azure | `169.254.169.254` | Managed identity tokens |
| Digital Ocean | `169.254.169.254` | Droplet metadata, SSH keys |

### Impact
- **Cloud Credential Theft**: Access to IAM roles, service accounts
- **Internal Network Scanning**: Map private network, discover services
- **Data Exfiltration**: Read internal APIs, databases
- **Privilege Escalation**: Obtain higher-privileged credentials

### How Our Demo Shows It

**Vulnerable SSRF:**
```
POST /api/vulnerable/fetch-url
Body: { "url": "http://169.254.169.254/latest/meta-data/" }

Server Action:
  const response = await fetch(url);  // No validation!
  return response.text();

Results:
✗ Access EC2/GCP metadata service
✗ Steal IAM credentials
✗ Read internal API endpoints
✗ Port scan internal network
✗ Access localhost services (Redis, MongoDB)

Attack Examples:
1. AWS Metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/
2. GCP Metadata: http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
3. Internal API: http://localhost:3000/api/admin/secrets
4. File Protocol: file:///etc/passwd
5. Cloud Storage: http://storage.googleapis.com/internal-bucket/secrets.txt
```

**Secure Implementation:**
```
POST /api/secure/fetch-url
Body: { "url": "http://example.com" }

Validation Steps:
1. URL Parsing & Validation
2. Allowlist Check (only example.com, api.example.com)
3. DNS Resolution Check (no private IPs)
4. Timeout & Size Limits
5. Disable Redirects

Protection:
✓ Only allow whitelisted domains
✓ Block private IP ranges (RFC 1918)
✓ Block metadata service IPs
✓ Block file:// protocol
✓ Validate after DNS resolution
✓ Network segmentation
```

### Attack Techniques

**1. Metadata Service Attacks**
```bash
# AWS
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]

# GCP
curl http://metadata.google.internal/computeMetadata/v1/ \
  -H "Metadata-Flavor: Google"
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token \
  -H "Metadata-Flavor: Google"

# Azure
curl http://169.254.169.254/metadata/identity/oauth2/token \
  ?api-version=2018-02-01&resource=https://management.azure.com/ \
  -H "Metadata: true"
```

**2. Bypass Techniques**
| Technique | Example | Purpose |
|-----------|---------|---------|
| URL encoding | `http://127.0.0.1` → `http://127.%30.%30.%31` | Bypass blacklist |
| Decimal IP | `http://2130706433` (127.0.0.1 in decimal) | Obfuscate IP |
| Hex IP | `http://0x7f.0x0.0x0.0x1` | Alternate representation |
| DNS Rebinding | First resolves to safe IP, then to 127.0.0.1 | Time-of-check-time-of-use |
| URL fragments | `http://evil.com@169.254.169.254` | Parser confusion |
| Protocol smuggling | `dict://127.0.0.1:6379/` | Access non-HTTP services |

**3. Internal Network Exploitation**
```
Phase 1: Reconnaissance
- Port scan: http://192.168.1.1:22, :80, :443, :3306, :6379
- Service discovery: http://internal-api.local/

Phase 2: Exploitation
- Redis: dict://localhost:6379/CONFIG%20SET%20dir%20/var/www/html
- MongoDB: gopher://localhost:27017/
- Internal APIs: http://admin-panel.internal/api/users
```

### Remediation Strategies

✅ **Input Validation**

**1. URL Allowlist (Preferred)**
```javascript
const ALLOWED_DOMAINS = ['example.com', 'api.example.com'];

function validateUrl(url) {
  const parsed = new URL(url);

  // Check protocol
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error('Only HTTP/HTTPS allowed');
  }

  // Check domain allowlist
  if (!ALLOWED_DOMAINS.includes(parsed.hostname)) {
    throw new Error('Domain not allowed');
  }

  return parsed;
}
```

**2. IP Blacklist (Defense in Depth)**
```javascript
const BLOCKED_IP_RANGES = [
  '127.0.0.0/8',      // Loopback
  '10.0.0.0/8',       // Private Class A
  '172.16.0.0/12',    // Private Class B
  '192.168.0.0/16',   // Private Class C
  '169.254.0.0/16',   // Link-local (metadata service)
  '0.0.0.0/8',        // Current network
  '100.64.0.0/10',    // Shared address space
  '224.0.0.0/4',      // Multicast
  '240.0.0.0/4',      // Reserved
];

async function isBlockedIP(hostname) {
  const addresses = await dns.resolve4(hostname);
  for (const addr of addresses) {
    if (isInBlockedRange(addr, BLOCKED_IP_RANGES)) {
      return true;
    }
  }
  return false;
}
```

✅ **Network-Level Controls**

**1. Cloud Provider Protections**

**AWS:**
```bash
# IMDSv2 (Session-based metadata access)
# Requires PUT request with token
curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"

# Then use token in subsequent requests
curl http://169.254.169.254/latest/meta-data/ \
  -H "X-aws-ec2-metadata-token: $TOKEN"
```

**GCP:**
```yaml
# Metadata concealment
metadata:
  enable-oslogin: "TRUE"

# Require Metadata-Flavor header
curl http://metadata.google.internal/computeMetadata/v1/instance/name \
  -H "Metadata-Flavor: Google"
```

**2. Network Segmentation**
```
┌──────────────┐         ┌──────────────┐
│   Internet   │────────▶│  Web Server  │
└──────────────┘         │  (DMZ)       │
                         └──────┬───────┘
                                │ Firewall
                         ┌──────▼───────┐
                         │   Internal   │
                         │   Network    │
                         └──────────────┘

Rules:
- Web servers CAN'T access metadata services
- Web servers CAN access specific internal APIs only
- Egress filtering: Block 169.254.169.254
```

**3. Firewall Rules**
```bash
# iptables: Block metadata service from web server
iptables -A OUTPUT -d 169.254.169.254 -j DROP

# AWS Security Group: Deny outbound to metadata
{
  "IpProtocol": "-1",
  "IpRanges": [{"CidrIp": "169.254.169.254/32"}],
  "FromPort": 0,
  "ToPort": 65535,
  "UserIdGroupPairs": []
}
```

✅ **Application-Level Defenses**

**1. Disable Redirects**
```javascript
const response = await fetch(url, {
  redirect: 'error',  // Don't follow redirects
  timeout: 5000,
  signal: AbortSignal.timeout(5000)
});
```

**2. Response Validation**
```javascript
async function secureFetch(url) {
  const response = await fetch(url, {
    redirect: 'error',
    timeout: 5000
  });

  // Check response size
  if (response.headers.get('content-length') > MAX_SIZE) {
    throw new Error('Response too large');
  }

  // Check content type
  const contentType = response.headers.get('content-type');
  if (!['application/json', 'text/html'].includes(contentType)) {
    throw new Error('Invalid content type');
  }

  return response;
}
```

**3. Use Proxy Service**
```javascript
// Centralized fetch service with security controls
const secureProxy = new SecureProxy({
  allowedDomains: ['example.com'],
  timeout: 5000,
  maxSize: 1024 * 1024,  // 1MB
  blockPrivateIPs: true,
  blockMetadata: true
});

const response = await secureProxy.fetch(url);
```

✅ **Detection & Monitoring**

**1. Log Analysis**
```javascript
// Log all outbound requests
logger.info('Outbound request', {
  url: sanitizedUrl,
  sourceIP: req.ip,
  userAgent: req.headers['user-agent'],
  timestamp: new Date()
});

// Alert on suspicious patterns
if (url.includes('169.254.169.254') ||
    url.includes('metadata.google.internal')) {
  alertSecurityTeam('SSRF attempt detected', { url, sourceIP });
}
```

**2. Honeypots**
```javascript
// Internal metadata endpoint honeypot
app.get('/metadata/*', (req, res) => {
  alertSecurityTeam('Metadata access attempt', {
    ip: req.ip,
    path: req.path,
    userAgent: req.headers['user-agent']
  });
  res.status(404).send('Not found');
});
```

**3. Web Application Firewall (WAF)**
```yaml
# ModSecurity rule
SecRule ARGS "@rx (169\.254\.169\.254|metadata\.google\.internal)" \
  "id:1001,phase:2,deny,status:403,msg:'SSRF attempt blocked'"
```

✅ **Testing & Validation**

**SSRF Testing Checklist:**
- [ ] Try localhost (127.0.0.1, ::1, localhost)
- [ ] Try metadata service (169.254.169.254)
- [ ] Try private IP ranges (10.x, 172.16.x, 192.168.x)
- [ ] Try URL encoding bypasses
- [ ] Try DNS rebinding
- [ ] Try protocol smuggling (file://, dict://, gopher://)
- [ ] Try redirect chains
- [ ] Try IPv6 localhost (::1, ::ffff:127.0.0.1)

**Tools:**
- **SSRFmap**: Automated SSRF exploitation tool
- **Burp Suite**: SSRF testing with Collaborator
- **OWASP ZAP**: SSRF scanning rules

---

## 📊 Summary: Cost of Vulnerabilities vs. Prevention

### Breach Cost Analysis (2023 Data)

| Metric | Average Cost |
|--------|--------------|
| Data Breach (overall) | $4.45M |
| Per Record Compromised | $165 |
| Healthcare Record | $429 |
| Financial Record | $275 |
| Ransomware Attack | $5.13M |
| Lost Business Cost | 38% of total |

### Prevention ROI

| Security Control | Annual Cost | Breach Cost Prevented | ROI |
|------------------|-------------|----------------------|-----|
| SAST/DAST Tools | $50K-$200K | $4.5M (1 breach) | 2,250% |
| Security Training | $10K-$50K | $2M (reduced incidents) | 4,000% |
| WAF Implementation | $30K-$100K | $3M (SQL injection prevention) | 3,000% |
| Penetration Testing | $50K-$150K/yr | $4M (vulnerability discovery) | 2,667% |
| Cloud Security Posture Management | $40K-$150K | $5M (misconfiguration prevention) | 3,333% |

### Time to Detect & Contain

| Industry | Mean Time to Detect | Mean Time to Contain | Total |
|----------|-------------------|---------------------|-------|
| Healthcare | 329 days | 79 days | 408 days |
| Financial | 233 days | 73 days | 306 days |
| Technology | 204 days | 68 days | 272 days |
| **With AI/Automation** | **74 days** | **33 days** | **107 days** |

**Cost Savings with Automation: $1.76M per breach**

---

## 🛡️ Security Maturity Roadmap

### Level 1: Reactive (Ad-Hoc)
**Characteristics:**
- No formal security testing
- Security is an afterthought
- Manual, inconsistent processes

**Immediate Actions:**
1. Enable MFA on all accounts
2. Update all dependencies (npm audit, pip check)
3. Enable cloud provider security defaults
4. Start logging security events

### Level 2: Managed (Repeatable)
**Characteristics:**
- Basic security controls in place
- Regular vulnerability scanning
- Documented security policies

**Actions:**
1. SAST/DAST in CI/CD pipeline
2. Annual penetration testing
3. Security awareness training
4. Incident response plan

### Level 3: Defined (Consistent)
**Characteristics:**
- Comprehensive security program
- Automated testing and monitoring
- Security requirements in SDLC

**Actions:**
1. Threat modeling for all projects
2. Security champions program
3. Automated compliance checks
4. Red team exercises

### Level 4: Quantitatively Managed (Measured)
**Characteristics:**
- Metrics-driven security
- Continuous improvement
- Risk-based prioritization

**Actions:**
1. Security metrics dashboard
2. Risk quantification (FAIR)
3. Automated remediation
4. Bug bounty program

### Level 5: Optimizing (Continuous)
**Characteristics:**
- Proactive threat hunting
- AI-driven security
- Industry-leading practices

**Actions:**
1. Threat intelligence integration
2. Automated incident response (SOAR)
3. Zero Trust architecture
4. Security research & innovation

---

## 📚 Resources & Tools

### Learning Resources
- **OWASP Top 10**: https://owasp.org/Top10/
- **OWASP AI Top 10**: https://owasp.org/www-project-top-10-for-large-language-model-applications/
- **PortSwigger Web Security Academy**: https://portswigger.net/web-security
- **NIST Cybersecurity Framework**: https://www.nist.gov/cyberframework
- **CWE Top 25**: https://cwe.mitre.org/top25/

### Security Testing Tools

**SAST (Static Analysis):**
- Semgrep (open source)
- SonarQube
- Checkmarx
- Veracode

**DAST (Dynamic Analysis):**
- OWASP ZAP (open source)
- Burp Suite
- Acunetix
- Nessus

**Cloud Security:**
- ScoutSuite (open source)
- Prowler (AWS, open source)
- Prisma Cloud
- Wiz
- Orca Security

**Dependency Scanning:**
- npm audit / yarn audit
- Snyk
- Dependabot
- WhiteSource

### Compliance Frameworks

| Framework | Focus | Industry |
|-----------|-------|----------|
| PCI-DSS | Payment card data | E-commerce, Finance |
| HIPAA | Healthcare data | Healthcare |
| GDPR | Personal data | EU operations |
| SOC 2 | Security controls | SaaS, Cloud |
| ISO 27001 | Information security | General |
| NIST CSF | Cybersecurity | U.S. Government |

---

## 🎯 Conclusion

### Key Takeaways

1. **Security is a Journey, Not a Destination**
   - Continuous testing and improvement
   - Stay updated on emerging threats
   - Learn from incidents (yours and others')

2. **Defense in Depth**
   - Multiple layers of security
   - No single point of failure
   - Assume breach, limit blast radius

3. **Shift Left**
   - Security early in SDLC
   - Developer training and tools
   - Automated checks in CI/CD

4. **Measure and Monitor**
   - Track security metrics
   - Monitor for anomalies
   - Continuous validation

5. **Culture Over Tools**
   - Security is everyone's responsibility
   - Blameless post-mortems
   - Reward security champions

### Final Reminder

**This demo application contains intentional vulnerabilities for educational purposes.**

❌ **DO NOT** deploy to production
❌ **DO NOT** use as a code template
❌ **DO NOT** store real customer data

✅ **DO** use for training and awareness
✅ **DO** practice secure coding
✅ **DO** test in isolated environments

---

**Stay Secure! 🔒**

*For questions or to report issues with this demo:*
GitHub: https://github.com/manimahesh/gcp-demo-project
