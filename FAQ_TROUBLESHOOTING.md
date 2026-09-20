# CyberGuardian AI — FAQ & Troubleshooting

## Frequently Asked Questions

---

## Setup & Installation

### Q: I get "ModuleNotFoundError: No module named 'flask'"
**A:** You haven't installed dependencies. Run:
```bash
pip install -r requirements.txt
```

### Q: Python says "3.7 is not supported"
**A:** CyberGuardian requires Python 3.8+. Check your version:
```bash
python --version
python3 --version  # Try this on Mac
```

### Q: Virtual environment won't activate
**A:** Try this instead:
```bash
# macOS/Linux
source venv/bin/activate

# Windows
venv\Scripts\activate

# Or use Python directly
python -m venv venv
python -m pip install -r requirements.txt
python app.py
```

### Q: "Port 5000 is already in use"
**A:** Another app is using port 5000. Either:

**Option 1:** Kill the process
```bash
# macOS/Linux - find what's using port 5000
lsof -i :5000

# Then kill it
kill -9 <PID>
```

**Option 2:** Use different port in `app.py`
```python
if __name__ == '__main__':
    app.run(debug=True, port=8000)  # Use 8000 instead
```

### Q: Tesseract OCR not found
**A:** Install Tesseract:

**Windows:**
- Download: https://github.com/UB-Mannheim/tesseract/wiki
- Run installer
- Add to PATH if needed

**macOS:**
```bash
brew install tesseract
```

**Linux:**
```bash
sudo apt-get install tesseract-ocr
```

---

## Runtime Issues

### Q: "Cannot find database"
**A:** Database not initialized. The app creates it on first run:
```bash
# Delete old database if corrupted
rm database/cyberguardian.db

# Run app - it will create new database
python app.py
```

### Q: Analysis takes too long (>2 seconds)
**A:** Common causes:

1. **Tesseract slow on first run** - Normal, it caches after first use
2. **Large file upload** - File processing takes time for big images
3. **URL analysis slow** - Network requests can delay results

**Solution:** Optimize in `backend/risk_engine.py`
```python
# Add caching
from functools import lru_cache

@lru_cache(maxsize=1000)
def calculate_risk(signals_tuple, urls_tuple, qr_risk):
    # Caching prevents recalculating same inputs
    pass
```

### Q: Memory usage keeps growing
**A:** Likely OCR or file processing issue:

```python
# In ocr_processor.py, add cleanup
import gc

def extract_text_from_image(file):
    try:
        image = Image.open(file)
        text = pytesseract.image_to_string(image)
        image.close()
        del image
        gc.collect()  # Force cleanup
        return text
    except Exception as e:
        return f"Error: {str(e)}"
```

### Q: Database is locked
**A:** Another process is accessing database:

```bash
# Check if app is running twice
ps aux | grep python

# Kill any duplicate processes
pkill -f "python app.py"

# If persistent, reset database
rm database/cyberguardian.db
```

---

## API Usage

### Q: API returns empty results
**A:** Check these:

1. **Is the request valid?**
```bash
# Test with curl
curl -X POST http://localhost:5000/api/analyze-text \
  -H "Content-Type: application/json" \
  -d '{"text":"test message"}'
```

2. **Check if API returned error**
```javascript
// In JavaScript, check response
const data = await response.json();
if (!data.success) {
    console.error("API Error:", data.message);
}
```

### Q: "File too large" error
**A:** Max file size is 8 MB. Check in config:

```python
# config.py
MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8 MB

# To increase, change the number:
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
```

### Q: URL analysis gives wrong results
**A:** The URL analyzer only checks patterns, not real-time reputation (Phase 2):

```python
# Current: Pattern-based detection
risk = analyze_url("https://example.com")
# Results are from regex patterns, not live APIs

# Phase 2 will add real threat intelligence APIs
```

---

## Frontend Issues

### Q: Pages won't load, blank screen
**A:** Check browser console for errors:

1. **Open DevTools:** F12 or Right-click → Inspect
2. **Check Console tab** for JavaScript errors
3. **Check Network tab** to see failed requests
4. **Common issue:** Missing static files

**Solution:**
```bash
# Ensure static files exist
ls static/css/design-system.css
ls static/js/app-shell.js

# If missing, re-download project
```

### Q: Styling looks wrong on mobile
**A:** Design system should be responsive. Check:

```bash
# Test different screen sizes
# DevTools → Toggle device toolbar (Ctrl+Shift+M)

# Or check design-system.css for breakpoints
@media (max-width: 768px) { ... }
@media (max-width: 1024px) { ... }
```

### Q: Charts/graphs not showing
**A:** Phase 1 uses simple HTML. Ensure page loaded:

```javascript
// In browser console, check if data loaded
console.log(window.CG);  // Should show utilities
```

---

## Deployment Issues

### Q: Application crashes on server
**A:** Check these in order:

1. **Check logs**
```bash
journalctl -u cyberguardian -n 50  # Last 50 lines
```

2. **Verify dependencies**
```bash
pip install -r requirements.txt
```

3. **Check permissions**
```bash
ls -la database/
# Should be readable/writable by www-data user
chmod 755 database/
chmod 644 database/cyberguardian.db
```

4. **Test locally first**
```bash
FLASK_ENV=production python app.py
```

### Q: Nginx shows 502 Bad Gateway
**A:** Gunicorn isn't running:

```bash
# Check if Gunicorn is running
ps aux | grep gunicorn

# Restart it
systemctl restart cyberguardian

# Check status
systemctl status cyberguardian

# View errors
journalctl -u cyberguardian -n 100
```

### Q: SSL certificate errors
**A:** Certificate not valid:

```bash
# Check certificate
openssl x509 -in /etc/letsencrypt/live/your.domain.com/cert.pem -text

# Renew certificate
sudo certbot renew

# Force renewal if needed
sudo certbot renew --force-renewal
```

### Q: Heroku deployment fails
**A:** Common Heroku issues:

```bash
# View logs
heroku logs --tail

# Common fixes:
# 1. Missing Procfile
# 2. Missing runtime.txt
# 3. Wrong SECRET_KEY

# Set environment variables
heroku config:set SECRET_KEY=your-secret-key

# Check config
heroku config
```

---

## Testing Issues

### Q: Tests fail locally but pass in CI
**A:** Environment differences. Check:

1. **Python version**
```bash
python --version
# Ensure matches CI (usually 3.9+)
```

2. **Environment variables**
```bash
# Ensure .env exists with test values
cat .env
```

3. **Test database**
```bash
# Tests use in-memory SQLite - should be automatic
# Check tests/conftest.py
```

### Q: Test says "permission denied" for uploads
**A:** Upload directory needs permissions:

```bash
mkdir -p uploads
chmod 755 uploads

# Run tests
pytest tests/
```

### Q: Coverage report shows 0%
**A:** Coverage not collecting data:

```bash
# Run with coverage flag
pytest --cov=backend --cov-report=html tests/

# View report
open htmlcov/index.html
```

---

## Security Questions

### Q: Is my data encrypted?
**A:** Phase 1: Data stored locally in SQLite (not encrypted by default)

**Phase 2 will add:**
- Encrypted database
- HTTPS only
- User authentication
- Data encryption at rest

**For now, ensure:**
```bash
# Secure file permissions
chmod 600 database/cyberguardian.db
chmod 700 database/

# Use HTTPS in production
# Store secrets in environment variables
```

### Q: How do I protect the API?
**A:** Phase 1 has no authentication. Phase 2 will add:

```python
# Phase 2: JWT authentication
@app.before_request
def require_token():
    if request.path.startswith('/api'):
        token = request.headers.get('Authorization', '')
        if not token:
            return jsonify({'error': 'Missing token'}), 401
```

**For now, keep API on private network or use IP whitelist**

### Q: What about SQL injection?
**A:** Safe - using parameterized queries:

```python
# SAFE - parameters are escaped
cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))

# NOT SAFE - string formatting
# cursor.execute(f"SELECT * FROM scans WHERE id = {scan_id}")
```

---

## Performance Questions

### Q: How do I make it faster?
**A:** Optimization checklist:

1. **Enable caching**
```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def analyze_url(url):
    # Results cached after first call
    pass
```

2. **Use production server**
```bash
# Don't use Flask dev server in production
# Use Gunicorn with workers
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

3. **Database indexes**
```sql
CREATE INDEX idx_risk_level ON scans(risk_level);
CREATE INDEX idx_timestamp ON scans(timestamp DESC);
```

4. **Async processing** (Phase 2)
```python
# Phase 2: Use Celery for background jobs
@celery.task
def analyze_async(text):
    return analyze_text(text)
```

### Q: How many users can it handle?
**A:** Phase 1 limitations:

- **Single Flask process:** 10-20 concurrent users
- **With Gunicorn 4 workers:** 40-80 concurrent users
- **With load balancer:** Scale horizontally

**Phase 2 will add:**
- Database connection pooling
- Redis caching
- Horizontal scaling
- Microservices

---

## Feature Questions

### Q: Why doesn't URL analysis use real APIs?
**A:** Phase 1 uses pattern matching only (fast, no API keys needed)

**Phase 2 will add:**
- VirusTotal API
- URLhaus API
- PhishingDB API
- Google Safe Browsing

```python
# Phase 2: Real threat intelligence
from threat_intel import ThreatIntelligenceClient

client = ThreatIntelligenceClient()
risk = client.analyze_url("https://example.com")
```

### Q: Can I add my own threat patterns?
**A:** Yes! Edit `backend/analyzer.py`:

```python
SIGNAL_CATEGORIES = {
    'YOUR_SIGNAL': {
        'patterns': [r'pattern1', r'pattern2'],
        'points': 10,
        'description': 'Your description'
    }
}
```

Then test it:
```bash
pytest tests/test_analyzer.py -v
```

### Q: Will Phase 2 have mobile apps?
**A:** Yes! Planned for Q1-Q2 2027:

- iOS (React Native)
- Android (React Native)
- Offline capability
- Push notifications
- Mobile-specific APIs

See `PHASE2_ROADMAP.md` for details

---

## Data & Export

### Q: How do I export my scan history?
**A:** Use the API:

```python
import requests
import json

# Get all history
response = requests.get('http://localhost:5000/api/history?limit=999')
scans = response.json()['scans']

# Save to file
with open('my_scans.json', 'w') as f:
    json.dump(scans, f, indent=2)
```

### Q: Can I import data from another instance?
**A:** Currently not built in. Phase 2 will add:

```python
# Phase 2: Import/Export feature
def import_scans(json_file):
    with open(json_file) as f:
        scans = json.load(f)
    
    for scan in scans:
        save_scan(scan['input_type'], scan)
```

### Q: How do I backup the database?
**A:** Use SQLite backup:

```bash
# Simple backup
cp database/cyberguardian.db database/cyberguardian.db.backup

# Automated backup (add to crontab)
0 2 * * * cp /path/to/database/cyberguardian.db /backups/cyberguardian_$(date +\%Y\%m\%d).db
```

---

## Contribution Questions

### Q: How do I contribute?
**A:** See `CONTRIBUTING.md`:

1. Fork repository
2. Create feature branch
3. Make changes
4. Write tests
5. Submit pull request

**Process:**
```bash
git checkout -b feature/my-feature
# Make changes
pytest tests/
black backend/
git commit -m "feat: add my feature"
git push origin feature/my-feature
# Create PR on GitHub
```

### Q: Can I add a new page?
**A:** Yes! Template:

```html
<!-- templates/my-page.html -->
{% extends "base.html" %}

{% block content %}
<div class="page-container">
  <h1>My New Page</h1>
  <!-- Your content -->
</div>
{% endblock %}
```

Then add route:
```python
# backend/routes.py
@main.route('/my-page')
def my_page():
    return render_template('my-page.html')
```

### Q: What's the code style?
**A:** Follow PEP 8:

```bash
# Format code
black backend/

# Check style
flake8 backend/

# Sort imports
isort backend/
```

---

## Getting More Help

### Where to Find Answers

| Issue | Documentation | Time |
|-------|---------------|------|
| Setup | GETTING_STARTED.md | 15 min |
| API usage | API_DOCUMENTATION.md | 20 min |
| Deployment | DEPLOYMENT_GUIDE.md | 30 min |
| Development | CONTRIBUTING.md | 15 min |
| Security | SECURITY.md | 25 min |
| Testing | TEST_GUIDE.md | 20 min |
| Architecture | ARCHITECTURE.md | 25 min |

### Resources

- **Flask:** https://flask.palletsprojects.com/
- **Tesseract:** https://github.com/tesseract-ocr/tesseract
- **OpenCV:** https://docs.opencv.org/
- **SQLite:** https://www.sqlite.org/docs.html
- **Python:** https://python.org/docs/

---

## Known Limitations (Phase 1)

1. ✗ No user authentication
2. ✗ No real-time threat APIs
3. ✗ No data encryption at rest
4. ✗ Single-threaded (sync only)
5. ✗ SQLite (no multi-user)
6. ✗ No mobile apps
7. ✗ No AI Copilot
8. ✗ No team features

**All addressed in Phase 2!** See `PHASE2_ROADMAP.md`

---

## Still Stuck?

1. **Search this FAQ** - Ctrl+F (Cmd+F on Mac)
2. **Check docs/** folder for relevant guide
3. **Review code comments** in source files
4. **Check error message closely** - Often very helpful
5. **Search GitHub issues** (Phase 2 when public)
6. **Post in discussions** (Phase 2 when available)

---

**Last Updated:** September 18, 2026

*This FAQ covers Phase 1. Phase 2 will add more features and answers.*

