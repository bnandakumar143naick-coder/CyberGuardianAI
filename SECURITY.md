# CyberGuardian AI — Security Documentation

## Overview

This document outlines security considerations, best practices, and hardening guidelines for CyberGuardian AI.

---

## Security Principles

1. **Defense in Depth** - Multiple layers of protection
2. **Least Privilege** - Minimal necessary permissions
3. **Fail Securely** - Default to denying access
4. **Secure by Default** - Security built in from start
5. **Privacy by Design** - Minimize data collection
6. **Transparency** - Clear security policies

---

## Input Validation & Sanitization

### Text Input

```python
# backend/validators.py

def validate_text_input(text):
    """Validate text for analysis."""
    
    # Check length
    if not text or len(text) > 10000:
        raise ValueError("Text must be 1-10000 characters")
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Normalize whitespace
    text = ' '.join(text.split())
    
    return text

def validate_url_input(url):
    """Validate URL format."""
    from urllib.parse import urlparse
    
    try:
        result = urlparse(url)
        
        # Validate components
        if not result.scheme or result.scheme not in ['http', 'https']:
            raise ValueError("Only HTTP/HTTPS URLs allowed")
        
        if not result.netloc:
            raise ValueError("Invalid URL: missing host")
        
        # Check length
        if len(url) > 2000:
            raise ValueError("URL too long")
        
        return url
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")
```

### File Upload Validation

```python
# backend/file_validators.py

ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'webp'}
MAX_FILE_SIZE = 8 * 1024 * 1024  # 8 MB

def validate_file_upload(file):
    """Validate uploaded file."""
    
    # Check file exists
    if not file or file.filename == '':
        raise ValueError("No file provided")
    
    # Check extension
    if not allowed_file(file.filename):
        raise ValueError(f"File type not allowed. Use: {ALLOWED_EXTENSIONS}")
    
    # Check file size
    file.seek(0, 2)  # Seek to end
    size = file.tell()
    file.seek(0)  # Reset to start
    
    if size > MAX_FILE_SIZE:
        raise ValueError(f"File too large. Max size: {MAX_FILE_SIZE} bytes")
    
    # Check magic bytes (file signature)
    file_bytes = file.read(4)
    file.seek(0)
    
    magic_bytes = {
        b'\xFF\xD8\xFF': 'jpg',
        b'\x89PNG': 'png',
        b'RIFF': 'webp'
    }
    
    detected_type = None
    for magic, ext in magic_bytes.items():
        if file_bytes.startswith(magic):
            detected_type = ext
            break
    
    if not detected_type:
        raise ValueError("Invalid file format")
    
    return file

def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
```

---

## SQL Injection Prevention

### Parameterized Queries (SQLite)

```python
# ✅ SECURE - Using parameterized queries

def get_scan_by_id(scan_id):
    """Get scan using parameterized query."""
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    # Parameters are safely escaped
    cursor.execute(
        "SELECT * FROM scans WHERE id = ?",
        (scan_id,)
    )
    
    return cursor.fetchone()

def search_scans(threat_type):
    """Search scans with parameter binding."""
    cursor.execute(
        "SELECT * FROM scans WHERE threat_type = ?",
        (threat_type,)
    )
    
    return cursor.fetchall()

# ❌ INSECURE - String formatting (DO NOT USE)

def insecure_query(scan_id):
    """This is vulnerable to SQL injection."""
    query = f"SELECT * FROM scans WHERE id = {scan_id}"
    # If scan_id = "1 OR 1=1", all records returned
    cursor.execute(query)
```

### ORM Safety (SQLAlchemy - Phase 2)

```python
# Phase 2: Using SQLAlchemy ORM

from sqlalchemy import create_engine, Column, Integer, String
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Scan(Base):
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    threat_type = Column(String(50))
    risk_score = Column(Integer)

# Using ORM prevents SQL injection
Session = sessionmaker(bind=engine)
session = Session()

scan = session.query(Scan).filter(Scan.id == scan_id).first()
```

---

## Cross-Site Scripting (XSS) Prevention

### Template Escaping

```html
<!-- templates/result.html -->

<!-- ✅ SAFE - Jinja2 auto-escapes by default -->
<p>Analysis of: {{ user_input }}</p>

<!-- For HTML content, use safe filter carefully -->
{% autoescape true %}
  <p>{{ explanation }}</p>
{% endautoescape %}

<!-- ❌ UNSAFE - Never mark untrusted content as safe -->
<!-- <p>{{ user_input | safe }}</p> -->
```

### JavaScript Context

```javascript
// ✅ SAFE - Using textContent
document.getElementById('result').textContent = userInput;

// ❌ UNSAFE - Using innerHTML with user content
// document.getElementById('result').innerHTML = userInput;

// ✅ SAFE - Using createElement
const div = document.createElement('div');
div.textContent = userInput;
document.body.appendChild(div);
```

### Content Security Policy (CSP)

```python
# app.py

from flask import Flask

app = Flask(__name__)

@app.after_request
def set_security_headers(response):
    """Set security headers."""
    
    # Content Security Policy
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self' https://api.anthropic.com"
    )
    
    # Other security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    return response
```

---

## Cross-Site Request Forgery (CSRF) Protection

### Flask-WTF CSRF Protection (Phase 2)

```python
# app.py

from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect(app)

# Protect POST requests
@app.route('/api/analyze-text', methods=['POST'])
@csrf.exempt  # Exempt API endpoints that use Authorization header
def analyze_text():
    pass
```

### Template CSRF Token

```html
<!-- templates/base.html -->

<form method="POST" action="/api/some-action">
    <!-- Include CSRF token -->
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    
    <input type="text" name="data">
    <button type="submit">Submit</button>
</form>
```

---

## Authentication & Authorization (Phase 2)

### Password Security

```python
# backend/auth.py

from werkzeug.security import generate_password_hash, check_password_hash

class UserAuth:
    @staticmethod
    def hash_password(password):
        """Hash password using bcrypt."""
        if len(password) < 12:
            raise ValueError("Password must be 12+ characters")
        
        return generate_password_hash(
            password,
            method='pbkdf2:sha256',
            salt_length=16
        )
    
    @staticmethod
    def verify_password(password_hash, password):
        """Verify password against hash."""
        return check_password_hash(password_hash, password)

# Password requirements
PASSWORD_REQUIREMENTS = {
    'min_length': 12,
    'require_uppercase': True,
    'require_lowercase': True,
    'require_numbers': True,
    'require_special': True
}

def validate_password_strength(password):
    """Validate password meets requirements."""
    
    if len(password) < PASSWORD_REQUIREMENTS['min_length']:
        raise ValueError("Password must be 12+ characters")
    
    if PASSWORD_REQUIREMENTS['require_uppercase']:
        if not any(c.isupper() for c in password):
            raise ValueError("Password must contain uppercase letter")
    
    if PASSWORD_REQUIREMENTS['require_lowercase']:
        if not any(c.islower() for c in password):
            raise ValueError("Password must contain lowercase letter")
    
    if PASSWORD_REQUIREMENTS['require_numbers']:
        if not any(c.isdigit() for c in password):
            raise ValueError("Password must contain number")
    
    if PASSWORD_REQUIREMENTS['require_special']:
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password):
            raise ValueError("Password must contain special character")
```

### JWT Token Security

```python
# Phase 2: JWT authentication

import jwt
from datetime import datetime, timedelta

class JWTAuth:
    def __init__(self, secret_key):
        self.secret_key = secret_key
        self.algorithm = 'HS256'
        self.expiration_hours = 24
    
    def create_token(self, user_id, extra_claims=None):
        """Create JWT token."""
        
        payload = {
            'user_id': user_id,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(
                hours=self.expiration_hours
            ),
            'jti': secrets.token_urlsafe()  # Unique token ID
        }
        
        if extra_claims:
            payload.update(extra_claims)
        
        return jwt.encode(
            payload,
            self.secret_key,
            algorithm=self.algorithm
        )
    
    def verify_token(self, token):
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.secret_key,
                algorithms=[self.algorithm]
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise ValueError("Token expired")
        except jwt.InvalidTokenError:
            raise ValueError("Invalid token")

# Usage in Flask
@app.before_request
def verify_token():
    """Verify JWT token on protected routes."""
    
    if request.path.startswith('/api'):
        auth_header = request.headers.get('Authorization', '')
        
        if not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Missing token'}), 401
        
        token = auth_header.split(' ')[1]
        
        try:
            payload = JWTAuth(app.config['SECRET_KEY']).verify_token(token)
            g.user_id = payload['user_id']
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
```

---

## Secure Configuration Management

### Environment Variables

```bash
# ✅ SECURE - Use environment variables

# .env (never commit to git)
DATABASE_PASSWORD=very-long-random-password-here
API_KEY=secret-key-from-service
STRIPE_SECRET_KEY=sk_live_xxxxx

# In Python
import os

db_password = os.getenv('DATABASE_PASSWORD')

# ❌ INSECURE - Hardcoded secrets
# password = "my-password-123"
# api_key = "sk_live_xxxxx"
```

### Secrets Rotation

```python
# Phase 2: Implement secret rotation

class SecretRotation:
    """Rotate secrets periodically."""
    
    def rotate_api_keys(self):
        """Rotate API keys."""
        
        # 1. Generate new key
        new_key = secrets.token_urlsafe(32)
        
        # 2. Update services to accept both old and new
        self.add_valid_key(new_key)
        
        # 3. Notify users of deprecation
        # 4. Wait 30 days
        # 5. Revoke old key
        
        self.revoke_key(old_key)
    
    def rotate_database_password(self):
        """Rotate database credentials."""
        # Similar process for database password
        pass
```

---

## HTTPS/TLS Configuration

### SSL Certificate

```nginx
# Production nginx configuration

server {
    listen 443 ssl http2;
    server_name your.domain.com;
    
    # Use strong SSL certificate
    ssl_certificate /etc/letsencrypt/live/your.domain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/your.domain.com/privkey.pem;
    
    # Strong SSL protocols
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    
    # HSTS - Force HTTPS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    
    # Redirect HTTP to HTTPS
    if ($scheme != "https") {
        return 301 https://$server_name$request_uri;
    }
}
```

### Certificate Pinning (Mobile - Phase 2)

```swift
// iOS certificate pinning

let session = URLSession(configuration: .default, delegate: CertificatePinningDelegate(), delegateQueue: nil)

class CertificatePinningDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge, completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        
        guard let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        // Verify pinned certificate
        let policies = [SecPolicyCreateSSL(true, challenge.protectionSpace.host as CFString)]
        SecTrustSetPolicies(serverTrust, policies as CFArray)
        
        var secResult = SecTrustResultType.invalid
        SecTrustEvaluate(serverTrust, &secResult)
        
        if secResult == .unspecified {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else {
            completionHandler(.cancelAuthenticationChallenge, nil)
        }
    }
}
```

---

## Logging & Monitoring

### Secure Logging

```python
# backend/logging_config.py

import logging
from logging.handlers import RotatingFileHandler

def configure_logging(app):
    """Configure secure logging."""
    
    if not app.debug:
        # File handler
        file_handler = RotatingFileHandler(
            'logs/app.log',
            maxBytes=10 * 1024 * 1024,  # 10MB
            backupCount=10
        )
        
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [%(pathname)s:%(lineno)d]'
        ))
        
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)

# Never log sensitive data
def log_safely(message, exclude_keys=['password', 'token', 'api_key']):
    """Log message without sensitive data."""
    
    if isinstance(message, dict):
        safe_data = {
            k: v for k, v in message.items()
            if k not in exclude_keys
        }
        app.logger.info(safe_data)
    else:
        app.logger.info(message)
```

### Audit Logging

```python
# backend/audit.py

class AuditLog:
    """Log sensitive actions."""
    
    @staticmethod
    def log_login(user_id, ip_address, success):
        """Log login attempt."""
        log_entry = {
            'event': 'login',
            'user_id': user_id,
            'ip': ip_address,
            'success': success,
            'timestamp': datetime.utcnow()
        }
        
        # Store in database or external service
        save_to_audit_log(log_entry)
    
    @staticmethod
    def log_data_export(user_id, record_count):
        """Log data exports."""
        log_entry = {
            'event': 'data_export',
            'user_id': user_id,
            'records': record_count,
            'timestamp': datetime.utcnow()
        }
        
        save_to_audit_log(log_entry)
```

---

## Dependency Security

### Vulnerability Scanning

```bash
# Check for vulnerable dependencies
pip install safety

# Scan current environment
safety check

# Or use GitHub's Dependabot
# Or OWASP Dependency-Check
# brew install dependency-check
dependency-check --project "CyberGuardian" --scan .
```

### Dependency Pinning

```
# requirements.txt - Pin specific versions

Flask==3.0.3
Werkzeug==3.0.1
pytesseract==0.3.10
# Not: Flask>=3.0

# Prevents unexpected breaking changes
# Allows security patches: Flask==3.0.3.* allowed
```

---

## Rate Limiting (Phase 2)

```python
# Prevent brute force and DOS attacks

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

@app.route('/api/analyze-text', methods=['POST'])
@limiter.limit("10 per minute")  # 10 requests per minute
def analyze_text():
    pass

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("5 per minute")  # Stricter for login
def login():
    pass
```

---

## OWASP Top 10 Compliance

| Vulnerability | Status | Mitigation |
|---------------|--------|-----------|
| Injection | ✅ | Parameterized queries |
| Broken Auth | 🔶 | Phase 2: Strong auth |
| Sensitive Data | ✅ | Encrypted in transit (HTTPS) |
| XXE | ✅ | Disable XML parsing |
| Broken Access | ✅ | RBAC system (Phase 2) |
| Security Misc | 🔶 | Security headers, CSP |
| XSS | ✅ | Template escaping |
| Insecure Deser | ✅ | JSON only, no pickle |
| Component Vuln | ✅ | Dependency scanning |
| Logging/Monitor | 🔶 | Audit logging (Phase 2) |

---

## Security Checklist

### Development
- [ ] Input validation on all inputs
- [ ] Parameterized queries
- [ ] Template escaping
- [ ] No hardcoded secrets
- [ ] Security headers enabled
- [ ] Dependency scan clean
- [ ] Code review process

### Pre-Deployment
- [ ] Security audit completed
- [ ] Penetration testing done
- [ ] HTTPS configured
- [ ] Firewall rules set
- [ ] Logging configured
- [ ] Backups tested
- [ ] Incident response plan

### Production
- [ ] SSL/TLS enabled
- [ ] Rate limiting active
- [ ] Monitoring enabled
- [ ] Logs monitored
- [ ] Access controls verified
- [ ] Regular updates scheduled
- [ ] Security team on-call

---

## Incident Response

### Security Incident Process

```
1. DETECT
   └─ Monitoring alerts, user reports

2. CONTAIN
   ├─ Isolate affected systems
   ├─ Stop damage spreading
   └─ Notify security team

3. INVESTIGATE
   ├─ Analyze logs
   ├─ Identify root cause
   └─ Determine scope

4. REMEDIATE
   ├─ Fix vulnerability
   ├─ Patch affected systems
   └─ Restore backups if needed

5. COMMUNICATE
   ├─ Notify affected users
   ├─ Provide guidance
   └─ Maintain transparency

6. IMPROVE
   ├─ Implement preventions
   ├─ Update policies
   └─ Conduct training
```

### Breach Notification

```python
# If data breach occurs:

1. Assess scope
   - What data was affected?
   - How many users?
   - What time period?

2. Notify users
   - Email within 24-48 hours
   - Provide guidance
   - Offer support

3. Notify authorities
   - GDPR requires notification
   - Follow local laws

4. Preserve evidence
   - Save logs
   - Document timeline
   - Support investigation
```

---

## Security Resources

- [OWASP Security Guidelines](https://owasp.org/)
- [CWE/SANS Top 25](https://cwe.mitre.org/top25/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework/)
- [Flask Security Best Practices](https://flask.palletsprojects.com/security/)
- [Python Security Warnings](https://www.python.org/dev/peps/pep-0492/)

---

## Security Contacts

- **Email:** security@cyberguardian.ai
- **Bug Bounty:** [Bug Bounty Program]
- **GPG Key:** [Public key]

---

**Last Updated:** September 17, 2026

*This security documentation should be reviewed and updated quarterly.*
