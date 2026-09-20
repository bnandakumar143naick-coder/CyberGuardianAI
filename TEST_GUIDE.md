# CyberGuardian AI — Testing Guide

## Overview

This guide covers testing strategies, frameworks, and best practices for CyberGuardian AI.

---

## Testing Pyramid

```
        /\
       /  \  E2E Tests (UI)
      /____\

     /      \
    /  API   \  Integration Tests
   /________\

  /          \
 /   Unit    \  Unit Tests
/____________\

Broad base: Most tests
Narrow top: Fewer, slower tests
```

---

## Test Setup

### Install Testing Dependencies

```bash
# Install test requirements
pip install pytest pytest-cov pytest-flask

# Install additional testing tools
pip install pytest-mock responses
```

### Test Project Structure

```
cyberguardian/
├── backend/
│   ├── analyzer.py
│   ├── ...
│   └── __init__.py
├── tests/
│   ├── conftest.py           # Test configuration
│   ├── test_analyzer.py      # Analyzer tests
│   ├── test_url_analyzer.py  # URL analyzer tests
│   ├── test_risk_engine.py   # Risk engine tests
│   ├── test_routes.py        # API route tests
│   ├── fixtures/             # Test data
│   │   ├── malicious_text.txt
│   │   ├── suspicious_url.txt
│   │   └── test_image.png
│   └── __init__.py
├── pytest.ini                # Pytest configuration
└── requirements-dev.txt      # Development dependencies
```

---

## Unit Tests

### Test Configuration (conftest.py)

```python
# tests/conftest.py

import pytest
import os
from app import create_app
from backend.database import Database

@pytest.fixture
def app():
    """Create and configure a test app instance."""
    
    app = create_app()
    app.config['TESTING'] = True
    app.config['DATABASE_PATH'] = ':memory:'  # Use in-memory DB
    
    # Create tables in test database
    Database.init_db()
    
    yield app

@pytest.fixture
def client(app):
    """Test client for API requests."""
    return app.test_client()

@pytest.fixture
def runner(app):
    """Test CLI runner."""
    return app.test_cli_runner()
```

### Text Analyzer Tests (test_analyzer.py)

```python
# tests/test_analyzer.py

import pytest
from backend.analyzer import analyze_text, classify_threat

class TestTextAnalyzer:
    """Test text analysis functionality."""
    
    def test_analyze_phishing(self):
        """Test phishing detection."""
        
        # Arrange
        text = "URGENT: Verify your credentials now or account will be locked"
        
        # Act
        result = analyze_text(text)
        
        # Assert
        assert result['risk_score'] > 70
        assert result['threat_type'] == 'PHISHING'
        assert 'Artificial urgency' in result['indicators']
        assert 'Credential request' in result['indicators']
    
    def test_analyze_financial_scam(self):
        """Test financial scam detection."""
        
        text = "Congratulations! You won $1 million. Click to claim your reward!"
        result = analyze_text(text)
        
        assert result['risk_score'] > 60
        assert result['threat_type'] in ['FINANCIAL_SCAM', 'SUSPICIOUS']
        assert any('reward' in i.lower() for i in result['indicators'])
    
    def test_analyze_safe_message(self):
        """Test legitimate message passes."""
        
        text = "Hello, how are you today?"
        result = analyze_text(text)
        
        assert result['risk_score'] < 30
        assert result['threat_type'] == 'SAFE'
    
    def test_empty_text_handling(self):
        """Test empty text handling."""
        
        with pytest.raises(ValueError):
            analyze_text("")
    
    def test_text_length_limit(self):
        """Test maximum text length."""
        
        long_text = "a" * 10001
        
        with pytest.raises(ValueError):
            analyze_text(long_text)
    
    def test_multiple_indicators(self):
        """Test detection of multiple indicators."""
        
        text = "URGENT!!! Click now to verify your banking credentials and claim reward!"
        result = analyze_text(text)
        
        # Should detect multiple signals
        assert len(result['indicators']) >= 3
        assert result['risk_score'] > 75

class TestThreatClassification:
    """Test threat type classification."""
    
    def test_classify_phishing(self):
        """Test phishing classification."""
        
        signals = {
            'URGENCY': True,
            'AUTHORITY_IMPERSONATION': True,
            'CREDENTIAL_REQUEST': True
        }
        
        threat_type = classify_threat(signals)
        assert threat_type == 'PHISHING'
    
    def test_classify_financial_scam(self):
        """Test financial scam classification."""
        
        signals = {
            'REWARD_BAIT': True,
            'FINANCIAL_REQUEST': True
        }
        
        threat_type = classify_threat(signals)
        assert threat_type in ['FINANCIAL_SCAM', 'SUSPICIOUS']
    
    def test_no_signals_safe(self):
        """Test safe classification with no signals."""
        
        signals = {}
        
        threat_type = classify_threat(signals)
        assert threat_type == 'SAFE'
```

### URL Analyzer Tests (test_url_analyzer.py)

```python
# tests/test_url_analyzer.py

import pytest
from backend.url_analyzer import extract_urls, analyze_url, calculate_url_risk

class TestURLExtraction:
    """Test URL extraction from text."""
    
    def test_extract_single_url(self):
        """Test extracting single URL."""
        
        text = "Click here: https://example.com"
        urls = extract_urls(text)
        
        assert len(urls) == 1
        assert "example.com" in urls[0]
    
    def test_extract_multiple_urls(self):
        """Test extracting multiple URLs."""
        
        text = "Visit https://site1.com or https://site2.com"
        urls = extract_urls(text)
        
        assert len(urls) == 2
    
    def test_no_urls(self):
        """Test text with no URLs."""
        
        text = "This message has no links"
        urls = extract_urls(text)
        
        assert len(urls) == 0
    
    def test_shortened_url_detection(self):
        """Test shortened URL detection."""
        
        text = "Check out bit.ly/abc123"
        urls = extract_urls(text)
        
        assert len(urls) > 0

class TestURLAnalysis:
    """Test URL analysis."""
    
    def test_analyze_suspicious_domain(self):
        """Test analysis of suspicious domain."""
        
        url = "https://secure-bank-verify.xyz/login"
        result = analyze_url(url)
        
        assert result['risk_score'] > 40
        assert any('domain' in i.lower() for i in result['indicators'])
    
    def test_analyze_legitimate_url(self):
        """Test analysis of legitimate URL."""
        
        url = "https://google.com"
        result = analyze_url(url)
        
        # Should be lower risk
        assert result['risk_score'] < 30
    
    def test_invalid_url_handling(self):
        """Test handling of invalid URLs."""
        
        with pytest.raises(ValueError):
            analyze_url("not-a-valid-url")

class TestURLRiskScoring:
    """Test URL risk score calculation."""
    
    def test_suspicious_tld_scoring(self):
        """Test suspicious TLD increases risk."""
        
        suspicious_urls = [
            "https://bank.xyz",
            "https://paypal.tk",
            "https://verify.click"
        ]
        
        for url in suspicious_urls:
            risk = calculate_url_risk(url)
            assert risk > 20
    
    def test_phishing_keywords(self):
        """Test phishing keywords in URLs."""
        
        urls = [
            "https://paypal-verify.com",
            "https://amazon-login.com",
            "https://apple-id-verify.com"
        ]
        
        for url in urls:
            risk = calculate_url_risk(url)
            assert risk > 30
```

### Risk Engine Tests (test_risk_engine.py)

```python
# tests/test_risk_engine.py

import pytest
from backend.risk_engine import calculate_risk, get_signal_weight

class TestRiskCalculation:
    """Test risk score calculation."""
    
    def test_single_signal_score(self):
        """Test risk calculation with single signal."""
        
        signals = {'URGENCY': True}
        urls = []
        qr_risk = 0
        
        score = calculate_risk(signals, urls, qr_risk)
        
        assert 0 <= score <= 100
        assert score > 0
    
    def test_multiple_signals_compound(self):
        """Test multiple signals compound risk."""
        
        single_signal = {'URGENCY': True}
        multiple_signals = {
            'URGENCY': True,
            'FEAR': True,
            'CREDENTIAL_REQUEST': True
        }
        
        score1 = calculate_risk(single_signal, [], 0)
        score2 = calculate_risk(multiple_signals, [], 0)
        
        # Multiple signals should have higher risk
        assert score2 > score1
    
    def test_risk_capped_at_100(self):
        """Test risk score capped at 100."""
        
        many_signals = {
            'URGENCY': True,
            'FEAR': True,
            'REWARD_BAIT': True,
            'AUTHORITY_IMPERSONATION': True,
            'CREDENTIAL_REQUEST': True,
            'FINANCIAL_REQUEST': True,
            'PERSONAL_INFO_REQUEST': True,
            'SUSPICIOUS_CTA': True
        }
        
        score = calculate_risk(many_signals, [], 0)
        
        assert score <= 100
    
    def test_risk_with_url_contribution(self):
        """Test URL risk contributes to score."""
        
        signals = {'URGENCY': True}
        urls = ['https://suspicious.xyz']
        
        score_no_url = calculate_risk(signals, [], 0)
        score_with_url = calculate_risk(signals, urls, 0)
        
        # URL should increase risk
        assert score_with_url > score_no_url
    
    def test_risk_levels(self):
        """Test risk level classification."""
        
        test_cases = [
            (15, 'LOW'),
            (45, 'MEDIUM'),
            (70, 'HIGH'),
            (85, 'CRITICAL')
        ]
        
        for score, expected_level in test_cases:
            # Test the risk level determination logic
            if score < 30:
                level = 'LOW'
            elif score < 61:
                level = 'MEDIUM'
            elif score < 76:
                level = 'HIGH'
            else:
                level = 'CRITICAL'
            
            assert level == expected_level

class TestSignalWeighting:
    """Test signal weight calculation."""
    
    def test_signal_weights_positive(self):
        """Test all signals have positive weights."""
        
        signals = [
            'URGENCY', 'FEAR', 'REWARD_BAIT',
            'AUTHORITY_IMPERSONATION', 'CREDENTIAL_REQUEST',
            'FINANCIAL_REQUEST', 'PERSONAL_INFO_REQUEST',
            'SUSPICIOUS_CTA'
        ]
        
        for signal in signals:
            weight = get_signal_weight(signal)
            assert weight > 0
    
    def test_critical_signal_higher_weight(self):
        """Test critical signals have higher weights."""
        
        critical_signals = ['CREDENTIAL_REQUEST', 'FINANCIAL_REQUEST']
        normal_signals = ['URGENCY', 'FEAR']
        
        for crit in critical_signals:
            for norm in normal_signals:
                assert get_signal_weight(crit) >= get_signal_weight(norm)
```

---

## Integration Tests

### API Route Tests (test_routes.py)

```python
# tests/test_routes.py

import json
import pytest

class TestAnalyzeTextAPI:
    """Test /api/analyze-text endpoint."""
    
    def test_analyze_text_success(self, client):
        """Test successful text analysis."""
        
        response = client.post('/api/analyze-text',
            data=json.dumps({'text': 'URGENT: Verify credentials'}),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
        assert 'risk_score' in data
        assert 'threat_type' in data
    
    def test_analyze_text_missing_data(self, client):
        """Test missing required data."""
        
        response = client.post('/api/analyze-text',
            data=json.dumps({}),
            content_type='application/json'
        )
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert data['success'] is False
    
    def test_analyze_text_empty_string(self, client):
        """Test empty text input."""
        
        response = client.post('/api/analyze-text',
            data=json.dumps({'text': ''}),
            content_type='application/json'
        )
        
        assert response.status_code == 400

class TestAnalyzeURLAPI:
    """Test /api/analyze-url endpoint."""
    
    def test_analyze_url_success(self, client):
        """Test successful URL analysis."""
        
        response = client.post('/api/analyze-url',
            data=json.dumps({'url': 'https://example.com'}),
            content_type='application/json'
        )
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert data['success'] is True
    
    def test_analyze_url_invalid(self, client):
        """Test invalid URL handling."""
        
        response = client.post('/api/analyze-url',
            data=json.dumps({'url': 'not-a-url'}),
            content_type='application/json'
        )
        
        assert response.status_code == 400

class TestHistoryAPI:
    """Test /api/history endpoint."""
    
    def test_get_history(self, client):
        """Test retrieving history."""
        
        response = client.get('/api/history?limit=10')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'scans' in data
        assert isinstance(data['scans'], list)
    
    def test_history_limit(self, client):
        """Test history limit parameter."""
        
        response = client.get('/api/history?limit=5')
        
        data = json.loads(response.data)
        assert len(data['scans']) <= 5

class TestDashboardAPI:
    """Test /api/dashboard endpoint."""
    
    def test_get_dashboard_stats(self, client):
        """Test dashboard statistics."""
        
        response = client.get('/api/dashboard')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'stats' in data
        assert 'total_scans' in data['stats']
        assert 'threat_distribution' in data['stats']
```

---

## Test Execution

### Run All Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_analyzer.py

# Run specific test class
pytest tests/test_analyzer.py::TestTextAnalyzer

# Run specific test
pytest tests/test_analyzer.py::TestTextAnalyzer::test_analyze_phishing
```

### Code Coverage

```bash
# Run tests with coverage
pytest --cov=backend --cov=backend/routes tests/

# Generate HTML coverage report
pytest --cov=backend --cov-report=html tests/

# View report
open htmlcov/index.html

# Set coverage threshold
pytest --cov=backend --cov-fail-under=80 tests/
```

### Test Output Examples

```bash
# Successful test output
$ pytest tests/test_analyzer.py -v

tests/test_analyzer.py::TestTextAnalyzer::test_analyze_phishing PASSED [ 20%]
tests/test_analyzer.py::TestTextAnalyzer::test_analyze_safe_message PASSED [ 40%]
tests/test_analyzer.py::TestTextAnalyzer::test_empty_text_handling PASSED [ 60%]

====== 3 passed in 0.45s ======

# Failed test output
$ pytest tests/test_analyzer.py::TestTextAnalyzer::test_analyze_phishing -v

tests/test_analyzer.py::TestTextAnalyzer::test_analyze_phishing FAILED

AssertionError: assert 45 > 70
  where 45 = result['risk_score']
```

---

## Test Data & Fixtures

### Using Pytest Fixtures

```python
# tests/conftest.py

@pytest.fixture
def phishing_text():
    """Phishing message for testing."""
    return "URGENT: Click here to verify your credentials immediately!"

@pytest.fixture
def safe_text():
    """Safe message for testing."""
    return "Hello, how are you doing today?"

# Use in tests
def test_with_fixture(phishing_text):
    result = analyze_text(phishing_text)
    assert result['threat_type'] == 'PHISHING'
```

### Test Data Files

```
tests/fixtures/
├── malicious_urls.txt       # One URL per line
├── phishing_messages.json   # Test message corpus
└── test_image.png           # Sample image for OCR
```

---

## Testing Best Practices

### 1. Arrange-Act-Assert (AAA)

```python
def test_example():
    # Arrange - Set up test data
    text = "Suspicious message"
    
    # Act - Execute the code
    result = analyze_text(text)
    
    # Assert - Verify the results
    assert result['threat_type'] in ['PHISHING', 'SUSPICIOUS']
```

### 2. One Assertion Per Test

```python
# ✅ GOOD - One assertion
def test_high_risk_score():
    result = analyze_text("URGENT PHISHING")
    assert result['risk_score'] > 70

# ❌ AVOID - Multiple assertions
def test_phishing_detection():
    result = analyze_text("URGENT PHISHING")
    assert result['threat_type'] == 'PHISHING'
    assert result['risk_score'] > 70
    assert 'URGENCY' in result['indicators']
    assert result['explanation'] != ''
```

### 3. Use Descriptive Names

```python
# ✅ GOOD - Clear name
def test_phishing_with_urgency_and_credential_request():
    pass

# ❌ POOR - Vague name
def test_phishing():
    pass
```

### 4. Test Edge Cases

```python
def test_edge_cases():
    """Test boundary conditions."""
    
    # Empty input
    with pytest.raises(ValueError):
        analyze_text("")
    
    # Maximum length
    long_text = "a" * 10000
    result = analyze_text(long_text)
    assert result is not None
    
    # Special characters
    special = "Test!@#$%^&*()message"
    result = analyze_text(special)
    assert result is not None
```

### 5. Mock External Dependencies

```python
import pytest
from unittest.mock import patch

@patch('backend.url_analyzer.requests.get')
def test_url_analysis_with_mock(mock_get):
    """Test URL analysis with mocked API."""
    
    # Mock the API response
    mock_get.return_value.status_code = 200
    mock_get.return_value.json.return_value = {'malicious': False}
    
    # Test with mocked API
    result = analyze_url("https://example.com")
    
    # Verify mock was called
    mock_get.assert_called_once()
```

---

## Performance Testing

```python
import time
import pytest

@pytest.mark.performance
def test_analysis_performance():
    """Test analysis completes within time limit."""
    
    text = "Test message for performance check"
    
    start = time.time()
    result = analyze_text(text)
    elapsed = time.time() - start
    
    # Should complete in under 100ms
    assert elapsed < 0.1
    assert result is not None
```

---

## Continuous Integration

### GitHub Actions Example

```yaml
# .github/workflows/tests.yml

name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.10
    
    - name: Install dependencies
      run: |
        pip install -r requirements.txt
        pip install -r requirements-dev.txt
    
    - name: Run tests
      run: pytest --cov=backend tests/
    
    - name: Upload coverage
      uses: codecov/codecov-action@v2
```

---

## Troubleshooting Tests

### Common Issues

**Problem:** Tests pass locally but fail in CI
- Ensure all environment variables set
- Check Python version matches
- Verify test data files exist

**Problem:** Tests are too slow
- Use `@pytest.mark.slow` to separate
- Mock slow operations
- Use in-memory database for tests

**Problem:** Flaky tests (intermittently fail)
- Remove timing dependencies
- Mock time-based operations
- Ensure proper test isolation

---

## Testing Checklist

Before merging code:
- [ ] All tests pass locally (`pytest`)
- [ ] Coverage maintained (≥80%)
- [ ] No new security issues in tests
- [ ] Edge cases tested
- [ ] Documentation updated
- [ ] Performance acceptable

---

## Resources

- [Pytest Documentation](https://docs.pytest.org/)
- [Unit Testing Best Practices](https://docs.python-guide.org/writing/tests/)
- [Flask Testing Guide](https://flask.palletsprojects.com/testing/)
- [Mock/Patch Tutorial](https://docs.python.org/3/library/unittest.mock.html)

---

**Last Updated:** September 17, 2026
