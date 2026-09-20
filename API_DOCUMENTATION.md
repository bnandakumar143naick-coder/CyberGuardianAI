# CyberGuardian AI — API Documentation

## Base URL
```
http://localhost:5000
```

## Authentication
Currently no authentication required. Phase 2 will add API key authentication.

---

## Page Routes (HTML)

### Dashboard & Main Pages

#### Command Center Dashboard
```
GET /command-center
```
Returns the premium dashboard with cyber risk score, protection status, and security metrics.

**Response:** HTML page with embedded JavaScript that fetches `/api/dashboard`

**Example Usage:**
```html
<a href="/command-center">Open Dashboard</a>
```

#### Notification Shield
```
GET /notification-shield
```
Simulated notification feed for demonstration.

**Features:**
- Prototype/simulation clearly labeled
- Sample notifications with threat data
- Live interaction with scanner

#### Threat Scanner
```
GET /threat-scanner
```
Multi-mode scanner interface with 5 input types.

**Modes:**
- Message (text)
- URL (link)
- Email (full email)
- Screenshot (image OCR)
- QR Code (image)

#### Threat Investigation
```
GET /threat-investigation
```
Deep-dive analysis view for a specific threat.

**Query Parameters:**
- `id` (optional) - Scan ID to investigate
  - Example: `/threat-investigation?id=42`

#### URL Intelligence
```
GET /url-intelligence
```
Dedicated URL analysis interface.

#### Other Pages
- `GET /ai-copilot` - AI copilot foundation
- `GET /analytics` - Security analytics dashboard
- `GET /protection-center` - Module status center
- `GET /privacy-settings` - User preferences

#### Legacy Pages
- `GET /` - Home page
- `GET /scan` - Scanner (legacy)
- `GET /result` - Result (legacy)
- `GET /history` - Scan history

---

## API Endpoints (JSON)

All API responses follow this structure:
```json
{
  "success": true,
  "message": "Optional message",
  "data": { ... }
}
```

### Analysis Endpoints

#### Analyze Text
```
POST /api/analyze-text
Content-Type: application/json

{
  "text": "URGENT: Click here to verify your account"
}
```

**Request Parameters:**
- `text` (string, required) - Text to analyze

**Response:**
```json
{
  "success": true,
  "input_type": "text",
  "risk_score": 91,
  "risk_level": "HIGH",
  "risk_emoji": "🟠",
  "threat_type": "PHISHING",
  "indicators": [
    "Artificial urgency",
    "Credential request",
    "Suspicious call to action"
  ],
  "extracted_text": "URGENT: Click here to verify your account",
  "explanation": "This message shows multiple phishing indicators...",
  "recommendations": [
    "Do not click the link",
    "Do not enter credentials",
    "Verify by calling official number"
  ],
  "summary": "Phishing - risk 91/100",
  "scan_id": 42
}
```

**Threat Types Returned:**
- `PHISHING` - Credential harvesting attempt
- `FINANCIAL_SCAM` - Money or payment scam
- `JOB_SCAM` - Fake job opportunity
- `MALICIOUS_URL` - Dangerous link
- `SOCIAL_ENGINEERING` - Manipulation attempt
- `QR_RISK` - Risky QR code
- `SUSPICIOUS` - Some red flags detected
- `SAFE` - No threats detected

**Risk Levels:**
- `LOW` (0-30) - 🟢
- `MEDIUM` (31-60) - 🟡
- `HIGH` (61-75) - 🟠
- `CRITICAL` (76-100) - 🔴

---

#### Analyze URL
```
POST /api/analyze-url
Content-Type: application/json

{
  "url": "https://secure-bank-verify.xyz/login"
}
```

**Request Parameters:**
- `url` (string, required) - Full URL to analyze

**Response:**
```json
{
  "success": true,
  "input_type": "url",
  "risk_score": 68,
  "risk_level": "HIGH",
  "threat_type": "MALICIOUS_URL",
  "urls_found": ["https://secure-bank-verify.xyz/login"],
  "url_analysis": {
    "analyzed": [
      {
        "url": "https://secure-bank-verify.xyz/login",
        "indicators": [
          "Misspelled domain (secure-bank-verify vs bank)",
          "Suspicious TLD (.xyz)",
          "Login prompt detected"
        ]
      }
    ]
  },
  "indicators": [
    "Misspelled domain",
    "Suspicious TLD",
    "Phishing characteristic"
  ],
  "scan_id": 43
}
```

**Risk Indicators Detected:**
- Misspelled domains
- Suspicious TLDs
- Shortened URLs
- Suspicious keywords
- Encoding detection (Punycode)
- Redirect chains

---

#### Analyze Image
```
POST /api/analyze-image
Content-Type: multipart/form-data

image: <binary file>
```

**Request Parameters:**
- `image` (file, required) - Image file (JPG, PNG, WebP)
- Maximum size: 8 MB

**Supported Formats:**
- JPEG (.jpg, .jpeg)
- PNG (.png)
- WebP (.webp)

**Response:**
```json
{
  "success": true,
  "input_type": "image",
  "risk_score": 75,
  "risk_level": "HIGH",
  "threat_type": "PHISHING",
  "extracted_text": "Text extracted from image via OCR",
  "qr_found": true,
  "qr_content": "https://malicious.example.com",
  "indicators": [
    "Extracted text contains urgency",
    "QR code detected"
  ],
  "scan_id": 44
}
```

**Pipeline Notes:**
- OCR runs first to extract text
- QR detection runs independently
- Results combined for analysis

---

#### Analyze QR Code
```
POST /api/analyze-qr
Content-Type: multipart/form-data

image: <binary file>
```

**Request Parameters:**
- `image` (file, required) - QR code image

**Response:**
```json
{
  "success": true,
  "input_type": "qr",
  "qr_found": true,
  "qr_content": "https://phishing-site.fake",
  "risk_score": 82,
  "risk_level": "HIGH",
  "threat_type": "PHISHING",
  "indicators": [
    "QR destination is suspicious",
    "Phishing characteristics in URL"
  ],
  "scan_id": 45
}
```

---

### History & Data Endpoints

#### Get Scan History
```
GET /api/history?limit=50
```

**Query Parameters:**
- `limit` (integer, optional) - Number of records to return
  - Default: 50
  - Maximum: 999

**Response:**
```json
{
  "success": true,
  "scans": [
    {
      "id": 1,
      "timestamp": "2026-09-17T10:30:45.123456+00:00",
      "input_type": "text",
      "risk_score": 91,
      "risk_level": "HIGH",
      "threat_type": "PHISHING",
      "indicators": ["Artificial urgency", "Credential request"],
      "summary": "Phishing - risk 91/100",
      "explanation": "This appears to be a phishing attempt...",
      "recommendations": ["Do not click", "Do not enter credentials"]
    },
    ...
  ]
}
```

**Returned for Each Scan:**
- `id` - Unique scan identifier
- `timestamp` - ISO format datetime
- `input_type` - Type of input (text, url, image, qr)
- `risk_score` - 0-100 score
- `risk_level` - LOW, MEDIUM, HIGH, CRITICAL
- `threat_type` - Classification
- `indicators` - Array of detected patterns
- `summary` - Human-readable summary
- `explanation` - Detailed analysis
- `recommendations` - Suggested actions

---

#### Get Specific Scan
```
GET /api/scan/{scan_id}
```

**Path Parameters:**
- `scan_id` (integer, required) - ID of scan to retrieve

**Response:**
```json
{
  "success": true,
  "scan": {
    "id": 42,
    "timestamp": "2026-09-17T10:30:45.123456+00:00",
    "input_type": "text",
    "risk_score": 91,
    "risk_level": "HIGH",
    "threat_type": "PHISHING",
    "indicators": ["Artificial urgency", "Credential request"],
    "summary": "Phishing - risk 91/100",
    "explanation": "...",
    "recommendations": ["..."],
    "extracted_text": "Original content analyzed",
    "urls_found": ["https://example.com"],
    "url_analysis": {...}
  }
}
```

**Error Response:**
```json
{
  "success": false,
  "message": "Scan not found."
}
```

---

#### Get Dashboard Statistics
```
GET /api/dashboard
```

**Response:**
```json
{
  "success": true,
  "stats": {
    "total_scans": 42,
    "high_risk": 8,
    "medium_risk": 12,
    "low_risk": 22,
    "threat_distribution": {
      "PHISHING": 5,
      "FINANCIAL_SCAM": 2,
      "SOCIAL_ENGINEERING": 1,
      "SAFE": 22
    },
    "recent_scans": [
      {
        "id": 42,
        "timestamp": "2026-09-17T10:30:45.123456+00:00",
        "threat_type": "PHISHING",
        "risk_score": 91,
        "risk_level": "HIGH",
        "summary": "Phishing - risk 91/100"
      },
      ...
    ]
  }
}
```

**Used by:**
- Command Center Dashboard
- Analytics Page
- All pages that display statistics

---

### Health & Status Endpoints

#### Health Check
```
GET /api/health
```

**Response:**
```json
{
  "success": true,
  "status": "ok",
  "ocr_available": true
}
```

**Indicates:**
- `status` - "ok" if service is running
- `ocr_available` - Whether Tesseract is installed

---

## Error Responses

### 400 Bad Request
```json
{
  "success": false,
  "message": "No text provided."
}
```

**Causes:**
- Missing required parameters
- Empty input
- Invalid file format

### 413 Payload Too Large
```json
{
  "success": false,
  "message": "File is too large. Please upload an image under 8 MB."
}
```

**Causes:**
- File exceeds 8 MB limit
- Configure via `MAX_CONTENT_LENGTH` in config

### 500 Internal Server Error
```json
{
  "success": false,
  "message": "An unexpected error occurred. Please try again."
}
```

**Causes:**
- Tesseract OCR failure
- Database error
- Processing error

---

## Code Examples

### JavaScript/Fetch

#### Analyze Text
```javascript
async function analyzeText(text) {
  const response = await fetch('/api/analyze-text', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ text: text })
  });
  
  const data = await response.json();
  
  if (data.success) {
    console.log('Risk Score:', data.risk_score);
    console.log('Threat Type:', data.threat_type);
    console.log('Explanation:', data.explanation);
  } else {
    console.error('Error:', data.message);
  }
  
  return data;
}
```

#### Analyze URL
```javascript
async function analyzeURL(url) {
  const response = await fetch('/api/analyze-url', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ url: url })
  });
  
  const data = await response.json();
  return data;
}
```

#### Upload Image
```javascript
async function analyzeImage(file) {
  const formData = new FormData();
  formData.append('image', file);
  
  const response = await fetch('/api/analyze-image', {
    method: 'POST',
    body: formData
  });
  
  const data = await response.json();
  return data;
}
```

#### Get History
```javascript
async function getHistory(limit = 50) {
  const response = await fetch(`/api/history?limit=${limit}`);
  const data = await response.json();
  
  if (data.success) {
    data.scans.forEach(scan => {
      console.log(`${scan.threat_type}: ${scan.risk_score}/100`);
    });
  }
  
  return data;
}
```

### Python

#### Using Requests Library
```python
import requests
import json

# Analyze text
response = requests.post(
    'http://localhost:5000/api/analyze-text',
    json={'text': 'Suspicious message here'}
)
result = response.json()
print(f"Risk Score: {result['risk_score']}")
print(f"Threat Type: {result['threat_type']}")

# Get history
response = requests.get('http://localhost:5000/api/history?limit=10')
scans = response.json()['scans']
for scan in scans:
    print(f"Scan {scan['id']}: {scan['threat_type']}")
```

### cURL

```bash
# Analyze text
curl -X POST http://localhost:5000/api/analyze-text \
  -H "Content-Type: application/json" \
  -d '{"text":"URGENT: Click here to verify"}'

# Get history
curl http://localhost:5000/api/history?limit=10

# Get specific scan
curl http://localhost:5000/api/scan/42

# Upload image
curl -F "image=@screenshot.png" \
  http://localhost:5000/api/analyze-image
```

---

## Rate Limiting

Currently no rate limiting implemented. Phase 2 will add:
- Rate limits per IP
- Authentication-based limits
- Burst protection

---

## CORS

Currently CORS is enabled for all origins via Flask-CORS.

Production configuration should restrict to known domains:

```python
from flask_cors import CORS

CORS(app, resources={
    r"/api/*": {
        "origins": ["https://yourdomain.com"],
        "methods": ["GET", "POST"]
    }
})
```

---

## Webhooks (Phase 2)

Planned for Phase 2:
- Threat detection webhooks
- Real-time notifications
- Integration with external services

---

## Changelog

### v1.0.0 (Phase 1)
- Initial API implementation
- Text, URL, image, QR analysis
- History and statistics endpoints
- Health check endpoint

### v1.1.0 (Planned Phase 2)
- Authentication via API keys
- Rate limiting
- Webhooks support
- Advanced filtering
- Batch analysis

---

## Support & Questions

For API questions:
1. Check examples above
2. Review code in `backend/routes.py`
3. Test endpoints using Postman or curl
4. See GETTING_STARTED.md for troubleshooting

---

**Last Updated:** September 17, 2026
**Version:** 1.0.0 (Phase 1)
