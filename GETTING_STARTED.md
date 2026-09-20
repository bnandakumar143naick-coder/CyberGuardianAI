# CyberGuardian AI — Getting Started Guide

## 🎯 Quick Start (5 minutes)

### Prerequisites Check
```bash
python --version  # Should be 3.8 or higher
pip --version     # Should be installed
```

### Step 1: Navigate to Project
```bash
cd CyberGuardianAI
```

### Step 2: Create Virtual Environment (Recommended)
```bash
# macOS/Linux
python -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Run Application
```bash
python app.py
```

### Step 5: Open in Browser
```
http://localhost:5000
```

---

## 🚀 First Steps

### 1. Explore the Dashboard
- Visit `http://localhost:5000/command-center`
- See your cyber risk score and security metrics
- Check protection status

### 2. Try the Scanner
- Go to `http://localhost:5000/threat-scanner`
- Paste this test message:
  ```
  URGENT: Your account will be blocked today. 
  Click here to verify your credentials: bit.ly/verify-account
  ```
- Click "Analyze Threat"
- See the risk score and threat classification

### 3. View History
- Go to `http://localhost:5000/history`
- See all your scan records
- Click on a scan to view details

### 4. Check Analytics
- Visit `http://localhost:5000/analytics`
- See threat distribution and metrics
- View threat patterns

---

## 🔧 Configuration

### Environment Variables

Edit `.env` file to configure:

```bash
# Flask
FLASK_ENV=development          # development or production
FLASK_DEBUG=1                  # Enable debug mode (0 for production)
FLASK_APP=app.py

# Database
DATABASE_PATH=database/cyberguardian.db

# Upload Settings
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=8388608     # 8 MB in bytes
ALLOWED_EXTENSIONS=jpg,jpeg,png,webp

# Security
SECRET_KEY=your-secret-key-here
```

### Configuration File (config.py)

Key settings:
```python
DEBUG = True                   # Debug mode
TESTING = False                # Test mode
DATABASE_PATH = 'database/cyberguardian.db'
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8 MB
```

---

## 📚 Project Structure Explained

### Backend Organization

```
backend/
├── analyzer.py           # Text pattern detection
├── url_analyzer.py       # Link risk scoring
├── risk_engine.py        # 0-100 risk calculation
├── ocr_processor.py      # Image text extraction
├── qr_processor.py       # QR code detection
├── ai_explainer.py       # Threat explanations
├── database.py           # SQLite operations
└── routes.py             # Flask endpoints
```

### Frontend Organization

```
templates/               # HTML pages
├── base.html           # Layout (extends all)
├── command-center.html # Dashboard
├── threat-scanner.html # Analysis tool
└── ...                 # Other pages

static/
├── css/
│   ├── design-system.css    # Components
│   └── style.css             # Styles
└── js/
    ├── app-shell.js         # Common functions
    └── scanner.js           # Scanner logic
```

---

## 📖 How It Works

### Analysis Pipeline

When you submit content for analysis:

```
User Input (text/URL/image/QR)
         ↓
1. Text Extraction
   ├─ Direct text input
   ├─ OCR from image
   └─ QR code decoding
         ↓
2. Signal Detection
   ├─ Urgency patterns
   ├─ Fear/threat language
   ├─ Authority impersonation
   ├─ Credential requests
   ├─ Financial requests
   └─ Other red flags
         ↓
3. URL Analysis
   ├─ URL extraction
   ├─ Domain reputation
   ├─ Suspicious patterns
   └─ Redirect detection
         ↓
4. Risk Scoring
   ├─ Signal contribution (up to 65 points)
   ├─ URL contribution (up to 40 points)
   └─ QR bonus (up to 8 points)
         ↓
5. Threat Classification
   ├─ Phishing
   ├─ Financial Scam
   ├─ Job Scam
   ├─ Malicious URL
   ├─ Social Engineering
   └─ Safe
         ↓
6. AI Explanation
   ├─ Clear reasoning
   ├─ Detected indicators
   └─ Recommended actions
         ↓
7. Storage & History
   └─ Save to SQLite database
         ↓
Result displayed to user
```

### Risk Score Calculation

The risk score combines multiple factors:

| Factor | Max Points | How It Works |
|--------|-----------|--------------|
| Behavioral Signals | 65 | Each suspicious pattern adds points, capped at 65 |
| URL Analysis | 40 | High-risk URLs contribute up to 40 points |
| QR Code Found | 8 | Extra points if risky QR code detected |
| **Total** | **100** | Combined score (0-100) |

### Threat Classification

Priority order:
1. **Job Scam** - If job indicators + financial request
2. **Phishing** - If credentials + authority impersonation
3. **Financial Scam** - If reward bait or payment request
4. **QR Risk** - If QR with risky content
5. **Malicious URL** - If very high URL risk
6. **Social Engineering** - If urgency + fear + authority
7. **Suspicious** - If any red flags
8. **Safe** - If no indicators

---

## 🧪 Testing Guide

### Manual Testing Workflow

#### Test 1: Text Analysis
```
1. Go to /threat-scanner
2. Switch to "Message" tab
3. Paste: "URGENT: Verify your password immediately or account locked"
4. Click "Analyze Threat"
Expected: HIGH risk, PHISHING classification
```

#### Test 2: URL Analysis
```
1. Go to /threat-scanner
2. Switch to "URL" tab
3. Enter: "http://secure-bank-verify.xyz/login"
4. Click "Analyze URL"
Expected: MEDIUM-HIGH risk, suspicious domain
```

#### Test 3: Screenshot OCR
```
1. Go to /threat-scanner
2. Switch to "Screenshot" tab
3. Upload a screenshot with suspicious text
4. Click "Analyze Image"
Expected: Text extracted and analyzed
```

#### Test 4: QR Code
```
1. Go to /threat-scanner
2. Switch to "QR Code" tab
3. Upload a QR code image
4. Click "Analyze QR Code"
Expected: QR decoded and URL analyzed
```

#### Test 5: Dashboard
```
1. Go to /command-center
2. Check metrics load correctly
3. See recent activity populates
Expected: Live data from database
```

### Automated Testing

```bash
# Run test suite
python -m pytest tests/

# Run specific test
python -m pytest tests/test_analyzer.py -v

# Check code syntax
python -m py_compile backend/*.py
```

---

## 🔍 Troubleshooting

### Issue: "ModuleNotFoundError"

**Problem:** Missing dependencies

**Solution:**
```bash
pip install -r requirements.txt
```

### Issue: "Cannot find Tesseract"

**Problem:** OCR library not installed

**Solution:**

**Windows:**
- Download installer: https://github.com/UB-Mannheim/tesseract/wiki
- Install to default location

**macOS:**
```bash
brew install tesseract
```

**Linux:**
```bash
sudo apt-get install tesseract-ocr
```

### Issue: "Port already in use"

**Problem:** Another app using port 5000

**Solution:** Change port in `app.py`:
```python
app.run(host="0.0.0.0", port=8000)  # Use port 8000 instead
```

### Issue: Database locked error

**Problem:** SQLite concurrent access issue

**Solution:**
```bash
# Remove database file to reset
rm database/cyberguardian.db
# Restart app - will create new database
python app.py
```

---

## 📊 Understanding the Dashboard

### Protection Status
Shows which security features are active:
- **ACTIVE** - Feature fully operational
- **SIMULATION** - Demo mode (Notification Shield)
- **COMING SOON** - Not yet implemented
- **AVAILABLE** - Ready to use

### Cyber Risk Score
- **0-30**: Low risk
- **31-60**: Medium risk
- **61-75**: High risk
- **76-100**: Critical risk

### Security Metrics
- **Threats Detected**: High + Medium risk items
- **Messages Analyzed**: Total scan count
- **URLs Analyzed**: Percentage of message scans containing URLs
- **High-Risk Flagged**: Count of HIGH and CRITICAL scans

---

## 🛡️ Security Best Practices

### For Users

1. **Never Click Unknown Links**
   - Always verify sender before clicking
   - Hover over links to see destination

2. **Verify Unusual Requests**
   - Banks never ask for passwords via message
   - Companies won't request OTP in messages
   - Always call company directly if unsure

3. **Enable 2FA**
   - Add extra security layer
   - Use authenticator app, not SMS

4. **Keep Software Updated**
   - Update OS regularly
   - Install security patches
   - Update antivirus software

### For Developers

1. **Keep Dependencies Updated**
   ```bash
   pip install --upgrade -r requirements.txt
   ```

2. **Use HTTPS in Production**
   - Get SSL certificate (Let's Encrypt is free)
   - Redirect HTTP to HTTPS

3. **Set Strong SECRET_KEY**
   ```python
   # Generate random key
   import secrets
   secrets.token_urlsafe(32)
   ```

4. **Database Backups**
   ```bash
   cp database/cyberguardian.db database/cyberguardian.db.backup
   ```

---

## 🚀 Production Deployment

### Pre-Deployment Checklist

- [ ] Set `FLASK_ENV=production`
- [ ] Set `FLASK_DEBUG=False`
- [ ] Generate strong `SECRET_KEY`
- [ ] Configure database backups
- [ ] Set up HTTPS/SSL
- [ ] Review and update security headers
- [ ] Test all pages on production
- [ ] Set up error logging
- [ ] Configure firewall rules
- [ ] Document deployment procedure

### Deployment Options

**Option 1: Heroku**
```bash
heroku create cyberguardian-app
git push heroku main
heroku open
```

**Option 2: DigitalOcean/AWS**
- Create droplet/instance
- Install Python and dependencies
- Use Gunicorn as app server
- Use Nginx as reverse proxy
- Configure SSL with Let's Encrypt

**Option 3: Docker**
Create `Dockerfile`:
```dockerfile
FROM python:3.10
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
CMD ["python", "app.py"]
```

---

## 📞 Getting Help

### Common Questions

**Q: How do I change the risk score threshold?**
A: Edit `config.py` and `RISK_BANDS` configuration

**Q: How do I add more signal patterns?**
A: Edit `backend/analyzer.py` and add to `SIGNAL_CATEGORIES`

**Q: Can I use this with my own threat intelligence data?**
A: Yes, modify `backend/url_analyzer.py` to integrate APIs

**Q: How do I train custom ML models?**
A: Phase 2 feature - placeholder in `models/` directory

### Resources

- **Flask Documentation**: https://flask.palletsprojects.com/
- **Tesseract OCR**: https://github.com/UB-Mannheim/tesseract/wiki
- **OpenCV**: https://docs.opencv.org/
- **SQLite**: https://www.sqlite.org/docs.html

---

## ✨ Next Steps

### Immediate (Day 1)
- [ ] Run application and test scanner
- [ ] Review Phase 1 audit report
- [ ] Check all pages load correctly
- [ ] Test responsive design on mobile

### Short Term (Week 1)
- [ ] Customize colors/branding in design-system.css
- [ ] Add your own threat patterns to analyzer
- [ ] Deploy to test environment
- [ ] Plan Phase 2 features

### Long Term (Phase 2)
- [ ] Integrate real threat intelligence APIs
- [ ] Build mobile apps
- [ ] Add user authentication
- [ ] Implement AI Copilot
- [ ] Set up cloud sync

---

## 🎓 Learning Resources

### Understanding Threat Analysis
- [OWASP Web Security](https://owasp.org/www-project-web-security-testing-guide/)
- [Phishing Prevention](https://www.cisa.gov/phishing)
- [Email Security Best Practices](https://www.sans.org/white-papers/)

### Understanding Risk Scoring
- Risk management frameworks
- Threat modeling approaches
- Security metrics

### Web Development
- Flask documentation
- HTML5/CSS3 best practices
- JavaScript patterns

---

**You're all set! Start exploring CyberGuardian AI now.**

*For technical details, see PHASE1_IMPLEMENTATION.md*
*For quick reference, see PHASE1_COMPLETION_SUMMARY.md*
