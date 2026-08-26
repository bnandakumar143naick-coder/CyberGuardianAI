# CyberGuardian AI

**See It. Scan It. Understand It. Stay Safe.**

*Detect → Explain → Protect*

## Problem

Phishing messages, fake prize notifications, fake job/scholarship offers,
and malicious QR codes are increasingly designed to look legitimate.
Most victims don't have the technical background to spot the subtle
red flags — a slightly-off URL, an artificial deadline, a request for
an OTP — before it's too late.

## Solution

CyberGuardian AI lets anyone photograph or upload a screenshot of a
suspicious message, website, or QR code. It extracts the text and
links, runs them through a transparent, explainable analysis pipeline,
and returns a plain-language verdict: what's suspicious, why, and what
to do next — in seconds, without requiring any cybersecurity knowledge.

## Features

- 📷 Photo capture (mobile) or screenshot upload (desktop/mobile)
- 🔤 OCR text extraction (Tesseract)
- 🔗 Automatic URL detection + structural risk analysis
- 🟩 QR code detection and decoding (OpenCV, no external system libs)
- 🧠 Rule-based behavioural signal detection (urgency, fear, reward
  bait, authority impersonation, credential/financial/personal-info
  requests, suspicious calls to action)
- 📊 Transparent, explainable 0–100 Cyber Risk Score with reasons
- 🏷️ Threat classification (phishing, financial scam, job scam,
  malicious URL, QR risk, social engineering, safe, etc.)
- 🤖 Generative AI explanation layer (optional — works with a
  rule-based fallback if no API key is configured)
- 🗂️ Scan history + dashboard with Chart.js visualisation
- 📱 Mobile-first, responsive dark UI
- 🔒 Privacy-conscious: uploaded images are deleted after analysis by
  default; no hardcoded API keys

## Architecture

```
Image / Text / URL input
        │
        ▼
 OCR + QR decoding  (backend/ocr_processor.py, backend/qr_processor.py)
        │
        ▼
 URL feature extraction  (backend/url_analyzer.py)
        │
        ▼
 Behavioural NLP signal detection  (backend/analyzer.py)
        │
        ▼
 Risk Engine — weighted, capped scoring  (backend/risk_engine.py)
        │
        ▼
 Threat classification  (backend/analyzer.py)
        │
        ▼
 AI / rule-based explanation  (backend/ai_explainer.py)
        │
        ▼
 Save to SQLite + return JSON report  (backend/database.py)
```

Every stage is independent and explainable — the risk score is a sum
of specific, named reasons, never a black-box number, and the AI
explainer is only ever shown the indicators the rule engine actually
detected (it cannot invent evidence).

## Technology Stack

**Frontend:** HTML5, CSS3, vanilla JavaScript, Chart.js
**Backend:** Python, Flask, Flask-CORS
**Image processing:** Pillow, OpenCV (QR decoding), pytesseract (OCR)
**Data:** SQLite, pandas/numpy (sample data)
**AI:** Optional LLM call for explanation generation, with a
full rule-based fallback

## Installation

```bash
# 1. Clone / unzip the project, then enter it
cd CyberGuardianAI

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Install Tesseract OCR (system dependency, not a pip package)
#    macOS:   brew install tesseract
#    Ubuntu:  sudo apt-get install tesseract-ocr
#    Windows: https://github.com/UB-Mannheim/tesseract/wiki
```

If Tesseract isn't installed, the app still runs — image uploads will
show "Text could not be reliably extracted," and text/URL analysis
work normally.

## Environment Variables

```bash
cp .env.example .env
```

Edit `.env`:

```
SECRET_KEY=some-random-string
FLASK_DEBUG=True
KEEP_UPLOADS=False
AI_API_KEY=your_api_key_here     # optional - leave blank to use rule-based explanations
AI_MODEL=claude-sonnet-4-6
```

Never commit your real `.env` file — it's already in `.gitignore`.

## Running

```bash
python app.py
# or
flask --app app run
```

Then open **http://localhost:5000** in a browser. On mobile, open the
same address on your phone's browser (on the same network, using your
machine's LAN IP) to use the camera-capture flow.

## API Endpoints

| Method | Endpoint              | Description                              |
|--------|------------------------|-------------------------------------------|
| POST   | `/api/analyze-image`   | Upload an image for full analysis         |
| POST   | `/api/analyze-text`    | Analyse raw pasted text                   |
| POST   | `/api/analyze-url`     | Analyse a single URL                      |
| POST   | `/api/analyze-qr`      | Analyse an image containing only a QR code|
| GET    | `/api/history?limit=N` | Recent scan history                       |
| GET    | `/api/scan/<id>`       | A single saved scan report                |
| GET    | `/api/dashboard`       | Aggregate stats for the dashboard         |
| GET    | `/api/health`          | Health check + OCR availability           |

All endpoints return JSON, e.g.:

```json
{
  "success": true,
  "risk_score": 91,
  "risk_level": "CRITICAL",
  "threat_type": "PHISHING",
  "indicators": ["Artificial urgency", "Credential / OTP request", "Suspicious URL"],
  "explanation": "...",
  "recommendations": ["Do not click the link", "Do not share OTP or password"]
}
```

## Demo

Use `data/sample_data.csv` for ready-made test cases covering bank
phishing, fake prizes, fake jobs/scholarships, a suspicious IP-based
URL, a risky QR destination, and a safe everyday message — paste the
`sample_text` values into the "Paste Text" tab, or the `sample_url`
values into "Check URL", to demonstrate the full range of outcomes
without needing any real malicious content.

## Limitations

CyberGuardian AI identifies **potential** phishing, scam, malicious-URL,
and social-engineering indicators using rule-based heuristics (and
optionally an LLM for plain-language explanation). It does **not**
guarantee that flagged content is malicious, nor that unflagged
content is safe. It is a decision-support tool, not a replacement for
independent verification through an organisation's official channels.

## Future Scope

- Browser extension for real-time link scanning
- Native Android application
- SMS and email integration
- Advanced threat-intelligence feeds and real-time URL reputation APIs
- Voice/call scam analysis
- Enterprise / team deployment with shared threat intelligence
