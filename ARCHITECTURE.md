# CyberGuardian AI — System Architecture

## Overview

CyberGuardian AI is a layered, modular Flask application designed for extensibility and maintainability. This document describes the system architecture, data flow, and component interactions.

---

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    USER INTERFACE LAYER                      │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │
│  │  Dashboard   │ │   Scanner    │ │  Analytics   │  ...    │
│  │   (HTML/CSS) │ │  (JS/HTML)   │ │  (Charts)    │         │
│  └──────────────┘ └──────────────┘ └──────────────┘         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                      API LAYER (REST)                        │
│  /api/analyze-text    /api/analyze-url    /api/history      │
│  /api/analyze-image   /api/analyze-qr     /api/dashboard    │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   BUSINESS LOGIC LAYER                       │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │
│  │  Analyzer    │ │  Risk Engine │ │  Explainer   │         │
│  │  (Signals)   │ │  (Scoring)   │ │  (Rules)     │         │
│  └──────────────┘ └──────────────┘ └──────────────┘         │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐         │
│  │     URL      │ │     OCR      │ │     QR       │         │
│  │  Analyzer    │ │  Processor   │ │  Processor   │         │
│  └──────────────┘ └──────────────┘ └──────────────┘         │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   DATA ACCESS LAYER                          │
│         Database Module (SQLite Operations)                  │
└─────────────────────────────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────┐
│                   PERSISTENCE LAYER                          │
│  ┌──────────────┐ ┌──────────────┐                          │
│  │   SQLite DB  │ │  File System  │                          │
│  │  (cyberguard │ │  (Uploads)    │                          │
│  │  ian.db)     │ │               │                          │
│  └──────────────┘ └──────────────┘                          │
└─────────────────────────────────────────────────────────────┘
```

---

## Component Architecture

### 1. User Interface Layer

#### Pages & Components
- **base.html** - App shell with navigation
- **command-center.html** - Dashboard with metrics
- **threat-scanner.html** - Multi-mode scanner
- **threat-investigation.html** - Detailed scan analysis
- **notification-shield.html** - Notification feed
- **analytics.html** - Charts and statistics
- **protection-center.html** - Feature status
- **privacy-settings.html** - User preferences

#### Design System
- **design-system.css** - Component library (800+ lines)
  - Layout system (grid, flexbox)
  - Components (cards, badges, buttons)
  - Forms (inputs, selects, textareas)
  - Modals and overlays
  - Responsive breakpoints
  - Utility classes

#### Client-Side Scripting
- **app-shell.js** - Common utilities
  - Navigation handling
  - Toast notifications
  - Date formatting
  - Responsive UI
  - Global helper functions

#### Static Assets
- CSS variables for theming
- Font imports (Space Grotesk, Inter, IBM Plex Mono)
- Responsive media queries

---

### 2. API Layer (REST)

#### Flask Blueprint: `main`
Located in `backend/routes.py`

**Page Routes (HTML):**
```
GET /command-center      → Dashboard
GET /threat-scanner      → Scanner interface
GET /notification-shield → Notifications
GET /threat-investigation?id= → Scan details
GET /url-intelligence    → URL analysis
GET /analytics          → Statistics
GET /ai-copilot         → AI interface
GET /protection-center  → Feature status
GET /privacy-settings   → User settings
```

**API Endpoints (JSON):**
```
POST /api/analyze-text      → Text analysis
POST /api/analyze-url       → URL analysis
POST /api/analyze-image     → Image + OCR
POST /api/analyze-qr        → QR code analysis
GET  /api/history?limit=    → Scan history
GET  /api/scan/{id}         → Single scan details
GET  /api/dashboard         → Statistics
GET  /api/health            → Status check
```

#### Request/Response Flow
```
Client Request
    ↓
Flask Route Handler (routes.py)
    ↓
Input Validation
    ↓
Call Business Logic
    ↓
Save to Database
    ↓
Return JSON Response
    ↓
Client Processes Response
```

---

### 3. Business Logic Layer

#### 3.1 Text Analysis Module
**File:** `backend/analyzer.py`

**Responsibility:** Detect threat signals in text

**Components:**
```python
SIGNAL_CATEGORIES = {
    'URGENCY': patterns for artificial urgency
    'FEAR': patterns triggering fear response
    'REWARD_BAIT': money/benefit temptation
    'AUTHORITY_IMPERSONATION': false authority
    'CREDENTIAL_REQUEST': asking for passwords
    'FINANCIAL_REQUEST': asking for money/payment
    'PERSONAL_INFO_REQUEST': asking for PII
    'SUSPICIOUS_CTA': suspicious call to action
}
```

**Key Functions:**
- `analyze_text(text)` - Main analysis function
- `detect_[signal]()` - Signal detection methods
- `classify_threat(signals)` - Threat classification

**Output:**
```python
{
    'indicators': ['Signal1', 'Signal2', ...],
    'threat_type': 'PHISHING|SCAM|etc',
    'summary': 'Human-readable summary'
}
```

#### 3.2 URL Analysis Module
**File:** `backend/url_analyzer.py`

**Responsibility:** Analyze and score URLs

**Features:**
- URL extraction from text
- Domain reputation checking
- Suspicious pattern detection
- TLD validation
- Redirect detection
- Punycode detection

**Key Functions:**
- `extract_urls(text)` - Find URLs in text
- `analyze_url(url)` - Full URL analysis
- `calculate_url_risk(url)` - Risk scoring (0-40 points)

**Suspicious Indicators:**
- Misspelled domains (homoglyphs)
- Suspicious TLDs (.xyz, .tk, etc.)
- Shortened URLs
- IP addresses as host
- URL encoding/Punycode
- Multiple redirects

#### 3.3 Risk Scoring Engine
**File:** `backend/risk_engine.py`

**Responsibility:** Calculate overall risk score (0-100)

**Scoring Breakdown:**
```
Total Risk = Signal Score + URL Score + QR Score
           ≤ 65 points + ≤ 40 points + ≤ 8 points
           = 0-100 points
```

**Signal Contribution (up to 65):**
- Each signal adds 10-15 points
- Multiple signals compound
- Capped at 65 points

**URL Contribution (up to 40):**
- High-risk URLs: 20-40 points
- Medium-risk URLs: 10-20 points
- Low-risk URLs: 1-10 points

**QR Contribution (up to 8):**
- Risky QR code: +8 points

**Risk Levels:**
```
0-30:   LOW (🟢)
31-60:  MEDIUM (🟡)
61-75:  HIGH (🟠)
76-100: CRITICAL (🔴)
```

**Key Functions:**
- `calculate_risk(signals, urls, qr)` - Main calculation
- `get_signal_weight(signal)` - Signal contribution
- `get_url_risk_score(url)` - URL contribution

#### 3.4 Image Processing Module
**File:** `backend/ocr_processor.py`

**Responsibility:** Extract text from images

**Supported Formats:** JPG, PNG, WebP

**Process:**
```
Image Upload
    ↓
Validate Format & Size (max 8 MB)
    ↓
Load with PIL
    ↓
Preprocess Image (if needed)
    ↓
Run Tesseract OCR
    ↓
Extract Text
    ↓
Return Extracted Text
```

**Key Functions:**
- `extract_text_from_image(file)` - Main extraction
- `preprocess_image(image)` - Image enhancement (optional)
- `validate_image(file)` - Format/size validation

**Error Handling:**
- Unsupported format → 400 Bad Request
- File too large → 413 Payload Too Large
- OCR failure → 500 Server Error

#### 3.5 QR Code Module
**File:** `backend/qr_processor.py`

**Responsibility:** Decode QR codes and analyze content

**Supported Formats:** JPG, PNG, WebP

**Process:**
```
QR Image Upload
    ↓
Load with OpenCV
    ↓
Detect QR Code
    ↓
Decode Content
    ↓
Analyze Decoded URL
    ↓
Return Results
```

**Key Functions:**
- `extract_qr_content(file)` - Main extraction
- `detect_qr(image)` - QR detection
- `decode_qr(qr_data)` - Content decoding

**Analysis:**
- If QR contains URL → analyze with URL analyzer
- If QR contains text → analyze with text analyzer

#### 3.6 Explanation Module
**File:** `backend/ai_explainer.py`

**Responsibility:** Generate human-readable explanations

**Process:**
```
Detected Signals + Classification
    ↓
Build Explanation
    ↓
Add Threat Context
    ↓
Generate Recommendations
    ↓
Return Formatted Output
```

**Key Functions:**
- `get_explanation(threat_type, indicators)` - Main explanation
- `get_threat_description(threat_type)` - Threat info
- `get_recommendations(threat_type)` - User recommendations

**Output:**
```python
{
    'explanation': 'Detailed analysis in plain English',
    'recommendations': [
        'Action 1: ...',
        'Action 2: ...',
        'Action 3: ...'
    ]
}
```

---

### 4. Data Access Layer

**File:** `backend/database.py`

**Database:** SQLite3

**Schema:**
```sql
CREATE TABLE scans (
    id INTEGER PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    input_type TEXT NOT NULL,
    risk_score INTEGER,
    risk_level TEXT,
    threat_type TEXT,
    indicators JSON,
    extracted_text TEXT,
    urls_found JSON,
    url_analysis JSON,
    explanation TEXT,
    recommendations JSON,
    summary TEXT
);

CREATE INDEX idx_risk_level ON scans(risk_level);
CREATE INDEX idx_timestamp ON scans(timestamp DESC);
```

**Key Functions:**
- `init_db()` - Initialize database
- `save_scan(input_type, analysis)` - Save analysis result
- `get_history(limit)` - Retrieve scan history
- `get_scan_by_id(scan_id)` - Get specific scan
- `get_dashboard_stats()` - Statistics for dashboard
- `clear_history()` - Delete all scans (Phase 2)
- `export_data()` - Data export (Phase 2)

**Connection Management:**
- Lazy initialization
- Parameterized queries (SQL injection prevention)
- Automatic cleanup

---

### 5. Application Entry Point

**File:** `app.py`

**Factory Pattern:**
```python
def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    # Initialize database
    Database.init_db()
    
    # Register blueprint
    from backend.routes import main
    app.register_blueprint(main)
    
    # Setup CORS
    CORS(app)
    
    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
```

**Configuration:**
- Environment-based settings
- Default values in `config.py`
- Override with environment variables

---

## Data Flow Diagrams

### Text Analysis Flow
```
User Input Text
    ↓
POST /api/analyze-text
    ↓
[analyzer.py]
  1. Detect urgency signals
  2. Detect fear signals
  3. Detect other signals
    ↓
Collect all signals
    ↓
[url_analyzer.py]
  1. Extract URLs
  2. Score URLs
    ↓
[risk_engine.py]
  Calculate risk score
    ↓
[analyzer.py]
  Classify threat type
    ↓
[ai_explainer.py]
  Generate explanation
    ↓
[database.py]
  Save scan record
    ↓
Return JSON Response
    ↓
Display to user
```

### Image Analysis Flow
```
User Uploads Image
    ↓
POST /api/analyze-image
    ↓
[routes.py]
  Validate file format & size
    ↓
[ocr_processor.py]
  Extract text via Tesseract
    ↓
[qr_processor.py] (parallel)
  Detect & decode QR code
    ↓
If QR found:
  → [url_analyzer.py] for QR URL
    ↓
Text + QR Results
    ↓
[analyzer.py]
  Analyze text and QR content
    ↓
[risk_engine.py]
  Calculate combined risk
    ↓
[database.py]
  Save scan with image analysis
    ↓
Return JSON Response
    ↓
Display results
```

### Dashboard Data Flow
```
User Views /command-center
    ↓
Page Loads HTML
    ↓
JavaScript Fetch
    GET /api/dashboard
    ↓
[routes.py]
    ↓
[database.py]
    get_dashboard_stats()
    ↓
Calculate:
  - Total scans
  - Threat distribution
  - Risk level breakdown
  - Recent activity
    ↓
Return JSON Stats
    ↓
JavaScript Updates DOM
    ↓
Render Charts & Metrics
    ↓
Display Dashboard
```

---

## Module Dependencies

```
app.py
  └─ config.py (configuration)
  └─ backend/routes.py (Flask routes)
      └─ backend/analyzer.py (text analysis)
      └─ backend/url_analyzer.py (URL analysis)
      └─ backend/risk_engine.py (risk scoring)
      └─ backend/ocr_processor.py (image processing)
      └─ backend/qr_processor.py (QR code)
      └─ backend/ai_explainer.py (explanations)
      └─ backend/database.py (data persistence)
```

**No Circular Dependencies:** ✅ Clean import hierarchy

---

## Security Architecture

### Input Validation

**At API Layer:**
- Type validation (text, URL, file)
- Size limits (max 8 MB files)
- File format whitelist (jpg, png, webp)

**At Business Logic:**
- Regex pattern validation
- URL format validation
- Encoding detection

**At Database:**
- Parameterized queries (SQLi prevention)
- Input escaping (XSS prevention)

### Data Protection

**In Transit:**
- HTTPS required (production)
- No sensitive data in logs

**At Rest:**
- SQLite local storage
- No encryption by default (Phase 2)
- File permissions on uploads

**Session Management:**
- Flask session handling
- Secure cookies (production)
- CSRF protection

---

## Performance Characteristics

### Time Complexity
- Text analysis: O(n × m)
  - n = text length
  - m = number of patterns (~50)
  - Typical: <100ms for average message

- URL analysis: O(k)
  - k = number of URLs found
  - Typical: <50ms per URL

- Risk calculation: O(1)
  - Fixed operations per score

### Space Complexity
- Text analysis: O(n)
  - Stores indicators list

- Database: O(scans)
  - Grows with history

### Optimization Opportunities (Phase 2)
- Pattern compilation caching
- URL reputation API caching
- Database indexing
- Result caching
- Batch processing

---

## Scalability Considerations

### Current Limitations
- Single SQLite database (local)
- In-memory pattern compilation
- Synchronous processing
- Single-threaded (Gunicorn workers)

### Phase 2 Improvements
- PostgreSQL for multi-user
- Redis caching layer
- Async job queue (Celery)
- Load balancing
- Horizontal scaling

### Phase 3+ Vision
- Microservices architecture
- Machine learning backend
- API gateway
- WebSocket for real-time
- CDN for static assets

---

## Testing Architecture

### Unit Tests
- `test_analyzer.py` - Signal detection
- `test_url_analyzer.py` - URL scoring
- `test_risk_engine.py` - Risk calculation

### Integration Tests
- API endpoint testing
- Database operations
- Multi-component flows

### Test Coverage
- Current: Analyzer module (core logic)
- Planned: 80%+ coverage all modules

---

## Configuration Management

### Environment Variables
```
FLASK_ENV: development|production
FLASK_DEBUG: 0|1
DATABASE_PATH: path to SQLite
UPLOAD_FOLDER: upload directory
MAX_CONTENT_LENGTH: file size limit
SECRET_KEY: Flask session key
CORS_ORIGINS: allowed origins
```

### Runtime Config
Loaded from `config.py` → Flask config

---

## Deployment Architecture

### Development
- Local Flask dev server
- SQLite local database
- File system uploads

### Production
- Gunicorn application server
- Nginx reverse proxy
- SSL/TLS encryption
- Structured logging

---

## Future Architecture (Phase 2+)

### Microservices
```
┌─ API Gateway (Kong/AWS APIGateway)
├─ Auth Service (JWT)
├─ Analysis Service (FastAPI)
├─ Threat Intelligence Service
├─ Storage Service (S3)
└─ Notification Service
```

### Data Pipeline
```
Raw Input → Analysis Engine → ML Model → Storage → Analytics
```

### Caching Layer
```
User Request → Cache (Redis) → Database → Computation
```

---

## Conclusion

CyberGuardian AI's architecture emphasizes:

1. **Modularity** - Each component has single responsibility
2. **Extensibility** - Easy to add new features
3. **Maintainability** - Clear separation of concerns
4. **Scalability** - Path to distributed architecture
5. **Security** - Input validation and safe practices
6. **Testability** - Isolated, testable components

This foundation supports the Phase 1 goal of creating a functional security analyzer while leaving room for Phase 2's advanced features and Phase 3's enterprise deployment.

---

**Last Updated:** September 17, 2026
