# CyberGuardian AI — Quick Reference Guide

**Bookmark this page! Print it for your desk.**

---

## 🚀 Quick Start (One Page)

```bash
# 1. SETUP
cd CyberGuardianAI
python -m venv venv
source venv/bin/activate          # macOS/Linux
# or: venv\Scripts\activate        # Windows
pip install -r requirements.txt

# 2. RUN
python app.py

# 3. OPEN
# http://localhost:5000/command-center
```

---

## 📍 Project Structure (At a Glance)

```
backend/
├── analyzer.py          # Text analysis (8 signals)
├── url_analyzer.py      # URL risk scoring
├── risk_engine.py       # 0-100 risk calculation
├── ocr_processor.py     # Image text extraction
├── qr_processor.py      # QR code detection
├── ai_explainer.py      # Threat explanations
├── database.py          # SQLite operations
└── routes.py            # Flask routes (9 new + legacy)

templates/
├── base.html            # App shell
├── command-center.html  # Dashboard
├── threat-scanner.html  # 5-tab scanner
└── ... (9 pages total)

static/
├── css/design-system.css    # 800+ lines
├── js/app-shell.js          # 250+ lines
└── style.css                # Original styles

database/
└── cyberguardian.db         # SQLite database
```

---

## 🔧 Common Commands

| Task | Command |
|------|---------|
| Start app | `python app.py` |
| Run tests | `pytest tests/` |
| With coverage | `pytest --cov=backend tests/` |
| Format code | `black backend/` |
| Check style | `flake8 backend/` |
| Sort imports | `isort backend/` |
| Check syntax | `python -m py_compile backend/*.py` |
| Reset database | `rm database/cyberguardian.db` |

---

## 🌐 API Endpoints (Quick Ref)

### Analysis
```
POST /api/analyze-text      → {"text": "message"}
POST /api/analyze-url       → {"url": "https://..."}
POST /api/analyze-image     → multipart/form-data (file)
POST /api/analyze-qr        → multipart/form-data (file)
```

### Data
```
GET /api/history?limit=50   → Scan history
GET /api/scan/{id}          → Single scan
GET /api/dashboard          → Statistics
GET /api/health             → Status check
```

### Pages
```
GET /command-center         → Dashboard
GET /threat-scanner         → Scanner
GET /analytics              → Charts
GET /notification-shield    → Notifications
GET /threat-investigation?id=42
GET /url-intelligence
GET /ai-copilot
GET /protection-center
GET /privacy-settings
```

---

## 🧪 Testing Quick Start

```bash
# Run all tests
pytest tests/

# Run with output
pytest -v

# Specific file
pytest tests/test_analyzer.py

# Specific test
pytest tests/test_analyzer.py::TestTextAnalyzer::test_analyze_phishing

# With coverage
pytest --cov=backend tests/

# HTML report
pytest --cov=backend --cov-report=html tests/
open htmlcov/index.html
```

---

## 💾 Database

### Schema (Main Table)
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP,
    input_type TEXT,           -- text, url, image, qr
    risk_score INTEGER,        -- 0-100
    risk_level TEXT,           -- LOW, MEDIUM, HIGH, CRITICAL
    threat_type TEXT,          -- Classification
    indicators JSON,           -- Detected signals
    extracted_text TEXT,
    urls_found JSON,
    url_analysis JSON,
    explanation TEXT,
    recommendations JSON,
    summary TEXT
);
```

### Quick Queries
```sql
-- Last 10 scans
SELECT * FROM scans ORDER BY timestamp DESC LIMIT 10;

-- High-risk scans
SELECT * FROM scans WHERE risk_score > 70;

-- Count by threat type
SELECT threat_type, COUNT(*) FROM scans GROUP BY threat_type;

-- Check database size
SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size();
```

---

## 🚀 Deploy Cheat Sheet

### Local Testing
```bash
export FLASK_ENV=development
export FLASK_DEBUG=1
python app.py
```

### Production Setup
```bash
# Install Gunicorn
pip install gunicorn

# Test run
gunicorn -w 4 -b 0.0.0.0:5000 app:app

# With systemd
sudo systemctl start cyberguardian
sudo systemctl status cyberguardian
sudo journalctl -u cyberguardian -n 50
```

### Docker
```bash
docker build -t cyberguardian:latest .
docker run -p 5000:5000 cyberguardian:latest
```

### Environment Variables
```bash
FLASK_ENV=production
FLASK_DEBUG=False
SECRET_KEY=your-secret-key
DATABASE_PATH=database/cyberguardian.db
UPLOAD_FOLDER=uploads
MAX_CONTENT_LENGTH=8388608
```

---

## 🔐 Security Checklist

- [ ] No hardcoded secrets
- [ ] Parameterized SQL queries
- [ ] Template auto-escaping
- [ ] Input validation on all endpoints
- [ ] File upload validation
- [ ] HTTPS in production
- [ ] Security headers configured
- [ ] Dependency scanning clean
- [ ] Error handling doesn't leak info
- [ ] Logging excludes sensitive data

---

## 📊 Risk Scoring Formula

```
Total Risk = Signal Score + URL Score + QR Score

Signal Score (0-65):
  - Each signal: 10-15 points
  - Multiple signals compound
  - Capped at 65

URL Score (0-40):
  - High-risk URL: 20-40 points
  - Medium-risk: 10-20 points
  - Low-risk: 1-10 points

QR Score (0-8):
  - Risky QR: +8 points
  - Safe QR: 0 points

Risk Level:
  0-30:   🟢 LOW
  31-60:  🟡 MEDIUM
  61-75:  🟠 HIGH
  76-100: 🔴 CRITICAL
```

---

## 📈 Threat Types

1. **PHISHING** - Credential harvesting
2. **FINANCIAL_SCAM** - Money/payment scams
3. **JOB_SCAM** - Fake job offers
4. **MALICIOUS_URL** - Dangerous link
5. **SOCIAL_ENGINEERING** - Manipulation
6. **QR_RISK** - Risky QR code
7. **SUSPICIOUS** - Some red flags
8. **SAFE** - No threats

---

## 🔍 Debugging Tips

```python
# In routes.py, add debugging
import logging
logging.basicConfig(level=logging.DEBUG)

# Log analysis results
app.logger.debug(f"Risk Score: {risk_score}")
app.logger.debug(f"Indicators: {indicators}")

# Check request data
@app.before_request
def log_request():
    app.logger.debug(f"Method: {request.method}")
    app.logger.debug(f"Path: {request.path}")
    app.logger.debug(f"Data: {request.get_json()}")
```

---

## 📱 Pages & Routes Map

| Page | Route | File | Purpose |
|------|-------|------|---------|
| Dashboard | `/command-center` | command-center.html | Threat metrics |
| Scanner | `/threat-scanner` | threat-scanner.html | 5-tab analyzer |
| Investigation | `/threat-investigation?id=` | threat-investigation.html | Scan details |
| Notifications | `/notification-shield` | notification-shield.html | Demo feed |
| URLs | `/url-intelligence` | url-intelligence.html | URL analysis |
| Analytics | `/analytics` | analytics.html | Charts |
| Copilot | `/ai-copilot` | ai-copilot.html | AI chat |
| Status | `/protection-center` | protection-center.html | Module status |
| Settings | `/privacy-settings` | privacy-settings.html | Preferences |

---

## 🆘 Troubleshooting Quick Ref

| Issue | Solution |
|-------|----------|
| "ModuleNotFoundError" | `pip install -r requirements.txt` |
| "Port 5000 in use" | `python app.py --port 8000` or `lsof -i :5000` |
| "Tesseract not found" | Install: `brew install tesseract` |
| "Database locked" | `pkill -f "python app.py"` |
| "Permission denied" | `chmod 755 database/` |
| "Page won't load" | Check browser console (F12) |
| "API returns 400" | Check required parameters |
| "Analysis slow" | First run is slow, caches after |

---

## 📚 Documentation Files

| File | Purpose | Time |
|------|---------|------|
| `GETTING_STARTED.md` | Setup & config | 15 min |
| `API_DOCUMENTATION.md` | API reference | 20 min |
| `DEPLOYMENT_GUIDE.md` | Production | 30 min |
| `ARCHITECTURE.md` | Design | 25 min |
| `CONTRIBUTING.md` | Development | 15 min |
| `SECURITY.md` | Hardening | 25 min |
| `TEST_GUIDE.md` | Testing | 20 min |
| `FAQ_TROUBLESHOOTING.md` | Help | As needed |

---

## 🔗 Useful Links

- Flask Docs: https://flask.palletsprojects.com/
- SQLite: https://sqlite.org/
- Tesseract: https://github.com/tesseract-ocr/
- OpenCV: https://opencv.org/
- Python: https://python.org/

---

## 💡 Pro Tips

1. **Bookmark this file** - Ctrl+D (Cmd+D on Mac)
2. **Keep terminal nearby** - You'll use it often
3. **Enable DevTools** - F12 while developing
4. **Read error messages** - They're usually helpful
5. **Use version control** - `git` early, `git` often
6. **Test locally first** - Before deploying
7. **Check logs** - When something breaks
8. **Document changes** - Future you will thank you

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Purpose |
|----------|---------|
| `F12` | Open DevTools in browser |
| `Ctrl+Shift+M` | Toggle mobile view |
| `Ctrl+Shift+K` | Open browser console |
| `Ctrl+/` | Toggle comment in IDE |
| `Ctrl+F` | Find in page |
| `Ctrl+S` | Save file |

---

## 🗂️ File Extension Quick Ref

| Extension | Language | Location |
|-----------|----------|----------|
| `.py` | Python | `backend/`, `app.py` |
| `.html` | HTML (Jinja2) | `templates/` |
| `.css` | CSS | `static/css/` |
| `.js` | JavaScript | `static/js/` |
| `.json` | JSON data | API responses |
| `.sql` | SQL | Database queries |
| `.md` | Markdown | Documentation |
| `.txt` | Text | `requirements.txt` |
| `.env` | Environment | Secret variables |

---

## 🎯 Common Tasks

### Add new threat signal
1. Edit `backend/analyzer.py`
2. Add pattern to `SIGNAL_CATEGORIES`
3. Add weight to `backend/risk_engine.py`
4. Test in `tests/test_analyzer.py`

### Add new page
1. Create `templates/my-page.html` (extend `base.html`)
2. Add route in `backend/routes.py`
3. Add navigation link in `templates/base.html`
4. Test locally

### Deploy to production
1. Review `DEPLOYMENT_GUIDE.md`
2. Choose platform (traditional/Docker/Heroku/AWS)
3. Follow platform-specific guide
4. Test all endpoints
5. Monitor logs

### Write test
1. Create file in `tests/test_*.py`
2. Use `pytest` fixtures from `conftest.py`
3. Follow Arrange-Act-Assert pattern
4. Run `pytest tests/`

---

## 📊 Performance Targets

| Metric | Target | Current |
|--------|--------|---------|
| Text analysis | <100ms | ✅ <100ms |
| Page load | <2s | ✅ <2s |
| API response | <500ms | ✅ <500ms |
| DB query | <50ms | ✅ <50ms |
| Uptime | 99%+ | ✅ Dev only |

---

## 🎓 Learning Paths

**Frontend Dev:**
templates/ → ARCHITECTURE.md → CONTRIBUTING.md

**Backend Dev:**
backend/ → API_DOCUMENTATION.md → TEST_GUIDE.md

**DevOps:**
DEPLOYMENT_GUIDE.md → SECURITY.md → ARCHITECTURE.md

**Security:**
SECURITY.md → ARCHITECTURE.md → TEST_GUIDE.md

---

## ✨ Quick Wins (Easy Contributions)

1. Add more test cases
2. Improve error messages
3. Add code comments
4. Update documentation
5. Fix typos/grammar
6. Add new threat signals
7. Optimize performance
8. Improve UI/UX

See `CONTRIBUTING.md` for details.

---

**Print this page. Bookmark it. Share it with your team.**

**Last Updated:** September 18, 2026  
**Version:** 1.0.0 (Phase 1)

---

