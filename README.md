# Secure App Demo 🛡️

A Node.js application with TypeScript demonstrating the implementation of multiple web security protections.

## 📋 Security Features Implemented

### 1. **CORS Protection** (Cross-Origin Resource Sharing)
- Restrictive configuration that only allows requests from specific domains
- Demonstration of how CORS protects users, not the server
- **Endpoint**: `/api/data`

### 2. **CSRF Protection** (Cross-Site Request Forgery)
- Generation and validation of unique CSRF tokens
- Use of `httpOnly` and `sameSite` cookies
- **Endpoints**: 
  - `GET /api/csrf-token` - Get token
  - `POST /api/secure-action` - Protected action

### 3. **XSS Protection** (Cross-Site Scripting)
- Security headers with Helmet.js
- Strict Content Security Policy (CSP)
- HTML escaping for user input
- **Endpoint**: `/api/xss-test`

### 4. **SQL Injection Protection**
- Demonstration of vulnerability vs. prepared statements
- SQLite database with test data
- **Endpoints**:
  - `GET /api/sql-vulnerable` - ⚠️ Vulnerable (demo only)
  - `GET /api/sql-secure` - ✅ Secure with prepared statements
  - `GET /api/users` - List users

### 5. **Cryptography Implementation**
Complete implementation of fundamental cryptographic concepts for web security.

#### 5.1 **Password Hashing with bcrypt**
- **Purpose**: Secure storage of user passwords
- **Algorithm**: bcrypt with automatic salting
- **Security**: 12 rounds, resistant to rainbow table attacks
- **Implementation**: `PasswordManager` class
- **Endpoints**:
  - `POST /api/hash-password` - Hash passwords securely
  - `POST /api/verify-password` - Verify password against hash

#### 5.2 **AES Symmetric Encryption**
- **Purpose**: Reversible encryption for sensitive data storage
- **Algorithm**: AES (Advanced Encryption Standard)
- **Key Management**: Single secret key for encrypt/decrypt
- **Use Cases**: Personal data, confidential information
- **Implementation**: `AESCrypto` class
- **Endpoints**:
  - `POST /api/encrypt` - Encrypt data with AES
  - `POST /api/decrypt` - Decrypt AES-encrypted data

#### 5.3 **SHA-256 Hashing**
- **Purpose**: Data integrity verification and fingerprinting
- **Algorithm**: SHA-256 (one-way function)
- **Variants**: 
  - Simple SHA-256 (deterministic)
  - SHA-256 with random salt (unique output each time)
- **Implementation**: `HashUtils` class
- **Endpoint**: `POST /api/hash` - Generate different hash types

#### 5.4 **JWT-like Token Management**
- **Purpose**: Secure authentication tokens
- **Structure**: `header.payload.signature` (JWT format)
- **Signature**: HMAC-SHA256 for tamper detection
- **Features**: Expiration time, integrity verification
- **Implementation**: `TokenManager` class
- **Endpoints**:
  - `POST /api/create-token` - Create signed tokens
  - `POST /api/verify-token` - Verify token authenticity

#### 5.5 **Real User Authentication**
- **Purpose**: Complete authentication flow with real database
- **Database**: SQLite with properly hashed passwords using bcrypt
- **Demo Credentials**: 
  - `admin/admin123`
  - `user1/user123` 
  - `test/test123`
- **Security Features**:
  - Passwords stored as bcrypt hashes (12 rounds)
  - Prepared statements prevent SQL injection
  - JWT-like tokens generated on successful login
  - No sensitive data returned in responses
- **Endpoint**: `POST /api/authenticate` - Login with real credentials

#### 5.6 **Cryptographic Concepts Demonstrated**
- **Hashing vs Encryption**:
  - Hashing: One-way (passwords, integrity)
  - Encryption: Two-way (data storage, transmission)
- **Salt in Hashing**: Prevents rainbow table attacks
- **Digital Signatures**: HMAC ensures data hasn't been tampered
- **Key Management**: Different keys for different purposes
- **Real-world Integration**: Database + bcrypt + authentication flow

**Additional Endpoint**: `GET /api/crypto-info` - Complete overview with examples

## 🏗️ Project Architecture

```
src/
├── index.ts                 # Main entry point
├── database/
│   └── index.ts            # SQLite configuration
├── crypto/
│   └── index.ts            # Cryptography utilities
│       ├── PasswordManager # bcrypt password hashing
│       ├── AESCrypto       # Symmetric encryption
│       ├── HashUtils       # SHA-256 hashing + salt
│       └── TokenManager    # JWT-like token handling
├── middlewares/
│   ├── cors.ts             # CORS configuration
│   ├── csrf.ts             # CSRF protection
│   ├── xss.ts              # Security headers
│   └── index.ts            # Centralized exports
└── routes/
    ├── cors.ts             # CORS routes
    ├── csrf.ts             # CSRF routes
    ├── sql.ts              # SQL Injection routes
    ├── xss.ts              # XSS routes
    ├── crypto.ts           # Cryptography routes
    └── index.ts            # Route aggregator
```

## 🚀 Installation and Usage

### Prerequisites
- Node.js 16+
- npm

### Installation
```bash
npm install
```

### Run in development
```bash
npm run dev
```

### Build for production
```bash
npm run build
npm start
```

## 🧪 Security Testing

### 1. SQL Injection
```bash
# Normal query
curl "http://localhost:3000/api/sql-vulnerable?username=admin"

# SQL Injection attack (works on vulnerable)
curl "http://localhost:3000/api/sql-vulnerable?username=admin%27%20OR%20%271%27%3D%271"

# Same attack on secure version (doesn't work)
curl "http://localhost:3000/api/sql-secure?username=admin%27%20OR%20%271%27%3D%271"
```

**URL encoding explanation:**
- `%27` = single quote `'`
- `%20` = space ` `
- `%3D` = equals sign `=`

**Alternative using shell escaping:**
```bash
# You can also use quote escaping
curl 'http://localhost:3000/api/sql-vulnerable?username=admin'\'' OR '\''1'\''='\''1'

# Or with variables for clarity
PAYLOAD="admin' OR '1'='1"
curl "http://localhost:3000/api/sql-vulnerable?username=${PAYLOAD// /%20}"
```

### 2. XSS Protection
Visit: `http://localhost:3000/api/xss-test?input=<script>alert('XSS')</script>`

Observe in DevTools:
- The escaped input doesn't execute the script
- CSP blocks inline scripts
- Security headers in Network tab

### 3. CSRF Protection
```bash
# 1. Get CSRF token
curl -c cookies.txt http://localhost:3000/api/csrf-token

# 2. Use token in protected request
curl -b cookies.txt \
     -H "Content-Type: application/json" \
     -H "x-csrf-token: [TOKEN_HERE]" \
     -d '{"test":"data"}' \
     http://localhost:3000/api/secure-action
```

### 4. CORS Protection
In browser DevTools:
```javascript
// This will fail due to CORS
fetch('http://localhost:3000/api/data')
  .then(r => r.json())
  .then(console.log)
  .catch(console.error);
```

### 5. Cryptography Features
```bash
# 1. Password Hashing
# Hash a password with bcrypt
curl -X POST -H "Content-Type: application/json" \
     -d '{"password":"mySecretPassword123"}' \
     http://localhost:3000/api/hash-password

# Verify password against hash (use hash from previous response)
curl -X POST -H "Content-Type: application/json" \
     -d '{"password":"mySecretPassword123","hash":"$2b$12$..."}' \
     http://localhost:3000/api/verify-password

# 2. AES Encryption/Decryption
# Encrypt sensitive data
curl -X POST -H "Content-Type: application/json" \
     -d '{"data":"sensitive information"}' \
     http://localhost:3000/api/encrypt

# Decrypt data (use encrypted value from previous response)
curl -X POST -H "Content-Type: application/json" \
     -d '{"encryptedData":"U2FsdGVkX1..."}' \
     http://localhost:3000/api/decrypt

# 3. SHA-256 Hashing
# Generate different types of hashes
curl -X POST -H "Content-Type: application/json" \
     -d '{"data":"document content"}' \
     http://localhost:3000/api/hash

# 4. JWT-like Token Management
# Create a signed token
curl -X POST -H "Content-Type: application/json" \
     -d '{"userId":1,"email":"user@example.com","role":"admin"}' \
     http://localhost:3000/api/create-token

# Verify token (use token from previous response)
curl -X POST -H "Content-Type: application/json" \
     -d '{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}' \
     http://localhost:3000/api/verify-token

# 5. Get crypto overview and examples
curl http://localhost:3000/api/crypto-info

# 6. Real User Authentication
# Authenticate with real database users (bcrypt hashed passwords)
curl -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"admin123"}' \
     http://localhost:3000/api/authenticate

curl -X POST -H "Content-Type: application/json" \
     -d '{"username":"user1","password":"user123"}' \
     http://localhost:3000/api/authenticate

curl -X POST -H "Content-Type: application/json" \
     -d '{"username":"test","password":"test123"}' \
     http://localhost:3000/api/authenticate

# Test with wrong credentials (should fail)
curl -X POST -H "Content-Type: application/json" \
     -d '{"username":"admin","password":"wrongpassword"}' \
     http://localhost:3000/api/authenticate
```

#### Database Information:
- **Type**: SQLite embedded database (`database.sqlite`)
- **Initialization**: Automatic on first run
- **Demo Users**: Created with real bcrypt hashes (12 rounds)
- **Credentials**: 
  - Username: `admin`, Password: `admin123`
  - Username: `user1`, Password: `user123`
  - Username: `test`, Password: `test123`
- **Security**: Prepared statements prevent SQL injection
- **Reset**: Delete `database.sqlite` file to regenerate with fresh data

#### Understanding the Output:
- **bcrypt hash**: Always different due to automatic salt (e.g., `$2b$12$...`)
- **AES encryption**: Reversible, same key encrypts/decrypts
- **SHA-256**: 
  - Simple: Same input = same output
  - With salt: Same input + random salt = different output each time
- **JWT token**: Three parts separated by dots (header.payload.signature)
- **Authentication success**: Returns user info + JWT token for session management
- **Authentication failure**: Returns generic error without revealing if user exists

#### Security Differences:
- **Password hashing**: Slow by design (12 rounds), includes salt
- **AES encryption**: Fast, reversible, good for data storage
- **SHA-256**: Fast, one-way, good for integrity checking
- **HMAC tokens**: Detects tampering, includes expiration
- **Real authentication**: Database integration with proper password verification

## 📚 Technologies Used

### Core Framework
- **Node.js** + **TypeScript** - Runtime and typing
- **Express.js** - Web framework

### Security Libraries
- **Helmet.js** - Security headers
- **csrf** - CSRF protection
- **cors** - CORS configuration
- **he** - HTML escaping

### Database
- **SQLite** - Lightweight database for demonstration

### Cryptography Libraries
- **bcrypt** - Password hashing with automatic salting (12 rounds)
- **crypto-js** - AES encryption/decryption for data protection
- **crypto** (Node.js built-in) - SHA-256 hashing and HMAC signatures

## 🔒 Security Headers Implemented

- `Content-Security-Policy` - Prevents XSS
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `X-Frame-Options: DENY` - Protects against clickjacking
- `Strict-Transport-Security` - Forces HTTPS (production)

## ⚠️ Important Notes

1. **Educational use only**: The `/api/sql-vulnerable` route is intentionally vulnerable for demonstration
2. **Don't use in production**: Always use prepared statements
3. **HTTPS in production**: Change `secure: false` to `true` in cookies
4. **Custom CSP**: Adjust CSP according to specific needs

## 🎯 Learning Objectives

### Web Security Fundamentals
- Understand different types of web attacks (XSS, CSRF, SQL Injection)
- Implement defense in depth strategies
- Use standard security tools and middleware
- Test vulnerabilities safely in controlled environment

### Cryptography Concepts
- **Password Security**: bcrypt vs plain text, salt importance
- **Data Protection**: When to use encryption vs hashing
- **Digital Signatures**: HMAC for integrity and authenticity
- **Key Management**: Different algorithms for different purposes
- **Token-based Authentication**: JWT structure and validation

### Code Architecture
- Separate security concerns into focused modules
- Modular route organization by security feature
- Clean separation between business logic and security middleware

## 📖 Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [MDN Web Security](https://developer.mozilla.org/en-US/docs/Web/Security)
- [Express Security Best Practices](https://expressjs.com/en/advanced/best-practice-security.html)

---

**Developed for educational purposes** 📚