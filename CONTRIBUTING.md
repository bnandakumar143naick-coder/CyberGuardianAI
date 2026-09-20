# Contributing to CyberGuardian AI

We welcome contributions from developers, security researchers, and cybersecurity professionals!

---

## Code of Conduct

This project is committed to fostering a welcoming, inclusive community. All contributors agree to:

- Be respectful and constructive in all interactions
- Welcome feedback and differing viewpoints
- Report concerns to project maintainers
- Focus on what's best for the community
- Help resolve conflicts professionally

---

## Getting Started

### 1. Fork the Repository
```bash
# Click "Fork" button on GitHub
# Clone your fork
git clone https://github.com/YOUR-USERNAME/cyberguardian.git
cd cyberguardian
```

### 2. Set Up Development Environment
```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # macOS/Linux
# or
venv\Scripts\activate     # Windows

# Install development dependencies
pip install -r requirements.txt
pip install -e .

# Install development tools
pip install black flake8 isort pytest pytest-cov
```

### 3. Create Feature Branch
```bash
# Update main branch
git checkout main
git pull origin main

# Create feature branch
git checkout -b feature/your-feature-name
# or for bug fixes
git checkout -b bugfix/issue-description
```

---

## Development Workflow

### Code Style

We follow PEP 8 with tools for enforcement:

```bash
# Format code with Black
black backend/ templates/ static/

# Check style with Flake8
flake8 backend/ tests/

# Sort imports with isort
isort backend/ tests/
```

### Commit Guidelines

Write clear, descriptive commit messages:

```bash
# Good commit message
git commit -m "feat: add email header validation to threat scanner"

# Also good
git commit -m "fix: correct QR code parsing on Windows

- Handle image format conversion issues
- Add UTF-8 support for QR content"
```

**Commit Types:**
- `feat:` - New feature
- `fix:` - Bug fix
- `docs:` - Documentation update
- `style:` - Code style changes (no logic change)
- `refactor:` - Code refactoring
- `perf:` - Performance improvement
- `test:` - Test addition/update
- `chore:` - Maintenance tasks

### Testing

Add tests for all new features:

```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=backend tests/

# Run specific test
pytest tests/test_analyzer.py::test_analyze_phishing
```

**Test Structure:**
```python
# tests/test_analyzer.py
import pytest
from backend.analyzer import analyze_text

def test_analyze_phishing():
    """Test phishing detection."""
    text = "URGENT: Verify your credentials now or account will be locked"
    result = analyze_text(text)
    
    assert result['risk_score'] > 70
    assert result['threat_type'] == 'PHISHING'
    assert len(result['indicators']) > 0

def test_safe_text():
    """Test legitimate text passes through."""
    text = "Hello, how are you today?"
    result = analyze_text(text)
    
    assert result['risk_score'] < 30
    assert result['threat_type'] == 'SAFE'
```

---

## Feature Development

### Adding a New Threat Signal

1. **Update Analyzer** (`backend/analyzer.py`)
```python
# Add to SIGNAL_CATEGORIES
SIGNAL_CATEGORIES = {
    'NEW_SIGNAL': {
        'patterns': [r'pattern1', r'pattern2'],
        'points': 10,
        'description': 'Detects new threat pattern'
    }
}
```

2. **Add Detection Logic**
```python
def detect_new_signal(text):
    """Detect new threat signal."""
    patterns = SIGNAL_CATEGORIES['NEW_SIGNAL']['patterns']
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)
```

3. **Update Risk Engine** (`backend/risk_engine.py`)
```python
SIGNAL_WEIGHTS = {
    'NEW_SIGNAL': 10,
    # ... other signals
}
```

4. **Add Explanation** (`backend/ai_explainer.py`)
```python
def explain_new_signal():
    return "This message contains patterns associated with [threat type]..."
```

5. **Write Tests** (`tests/test_analyzer.py`)
```python
def test_new_signal_detection():
    """Test new signal detection."""
    text = "Text with new signal pattern"
    result = analyze_text(text)
    
    assert 'NEW_SIGNAL' in result['indicators']
    assert result['risk_score'] > threshold
```

### Adding a New Page

1. **Create Template** (`templates/new-page.html`)
```html
{% extends "base.html" %}

{% block content %}
<div class="page-container">
  <!-- Your content -->
</div>
{% endblock %}
```

2. **Add Route** (`backend/routes.py`)
```python
@main.route('/new-page')
def new_page():
    """New page route."""
    return render_template('new-page.html')
```

3. **Add Navigation Link** (`templates/base.html`)
```html
<a class="sidebar-nav-link {% if 'new-page' in request.path %}active{% endif %}" 
   href="{{ url_for('main.new_page') }}">
  New Page
</a>
```

4. **Add Styles** (`static/css/design-system.css`)
```css
.new-page-container {
  /* Your styles */
}
```

### Adding an API Endpoint

1. **Create Route Handler** (`backend/routes.py`)
```python
@main.route('/api/analyze-new-type', methods=['POST'])
def analyze_new_type():
    """Analyze new content type."""
    data = request.get_json()
    
    if not data.get('content'):
        return jsonify({'success': False, 'message': 'No content provided'}), 400
    
    # Perform analysis
    result = analyze_content(data['content'])
    
    # Save to database
    scan = save_scan('new_type', result)
    
    return jsonify({
        'success': True,
        'data': result,
        'scan_id': scan.id
    })
```

2. **Write Tests**
```python
def test_analyze_new_type():
    """Test new analysis type."""
    response = client.post('/api/analyze-new-type',
        json={'content': 'test content'})
    
    assert response.status_code == 200
    assert response.json['success'] is True
```

---

## Pull Request Process

### 1. Before Submitting

```bash
# Update with latest changes
git fetch origin
git rebase origin/main

# Run tests locally
pytest tests/ -v

# Check code style
black backend/ tests/
flake8 backend/ tests/
isort backend/ tests/

# Verify no errors
python -m py_compile backend/*.py
```

### 2. Submit Pull Request

**PR Title:**
```
feat: add [feature name]
fix: resolve [issue description]
```

**PR Description Template:**
```markdown
## Description
Brief description of changes.

## Motivation
Why is this change needed?

## Changes Made
- Item 1
- Item 2
- Item 3

## Testing
How to test these changes:
1. Step 1
2. Step 2

## Screenshots (if applicable)
![screenshot]

## Checklist
- [ ] Code follows style guidelines
- [ ] Tests written and passing
- [ ] No breaking changes
- [ ] Documentation updated
- [ ] Commits are clean and descriptive
```

### 3. Code Review

- Maintainers will review your PR
- Address feedback and make requested changes
- Push updates to the same branch (no new PR needed)
- Be patient and respectful during review

### 4. Merge

Once approved, maintainers will merge your PR!

---

## Reporting Bugs

### Security Vulnerabilities

**Do NOT open a public issue for security vulnerabilities.**

Email security concerns to: security@cyberguardian.ai

Include:
- Description of vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Regular Bugs

1. Check existing issues first
2. Use bug report template:

```markdown
## Description
Clear description of the bug.

## Steps to Reproduce
1. Step 1
2. Step 2
3. Bug occurs

## Expected Behavior
What should happen.

## Actual Behavior
What actually happens.

## Environment
- OS: [e.g., Windows 10]
- Python: [e.g., 3.10.2]
- Flask: [version]

## Error Log
```
Paste any error messages
```

## Additional Context
Any other relevant info.
```

---

## Feature Requests

Suggest improvements through GitHub Discussions:

```markdown
## Feature Title
Brief description of what you want to add.

## Motivation
Why is this feature needed?

## Proposed Solution
How would this feature work?

## Alternatives Considered
Are there other approaches?

## Additional Context
Screenshots, links, or other info.
```

---

## Documentation Contributions

Help improve documentation:

1. **Fix typos/errors**: Submit PR directly
2. **Clarify explanations**: Submit PR with improved text
3. **Add examples**: Create comprehensive examples
4. **Translate docs**: Translate to other languages

### Documentation Style Guide

- Use clear, simple language
- Include code examples where helpful
- Add tables for comparisons
- Use headers to organize content
- Link to related docs
- Keep line length readable

---

## Project Structure

```
cyberguardian/
├── backend/              # Python business logic
│   ├── analyzer.py       # Threat detection
│   ├── url_analyzer.py   # URL analysis
│   ├── risk_engine.py    # Risk calculation
│   ├── ocr_processor.py  # Image processing
│   ├── qr_processor.py   # QR codes
│   ├── ai_explainer.py   # Explanations
│   ├── database.py       # Data persistence
│   └── routes.py         # Flask routes
├── templates/            # HTML pages
├── static/               # CSS & JavaScript
│   ├── css/
│   └── js/
├── tests/                # Test suite
├── database/             # SQLite DB
├── uploads/              # User uploads
└── app.py                # Flask app entry
```

---

## Development Tips

### Debugging

```python
# Use Flask debug mode
export FLASK_DEBUG=1
python app.py

# Use pdb for step debugging
import pdb; pdb.set_trace()

# Use logging for debugging
import logging
logging.debug("Debug message")
```

### Performance Profiling

```python
# Profile function execution time
import time

start = time.time()
# Code to profile
end = time.time()
print(f"Execution time: {end - start} seconds")
```

### Database Inspection

```bash
# Query database directly
sqlite3 database/cyberguardian.db

# Show schema
.schema

# Query data
SELECT * FROM scans LIMIT 5;
```

---

## Code Review Checklist

When reviewing PRs, check:

- [ ] Code follows style guidelines
- [ ] Tests are included and passing
- [ ] Documentation is updated
- [ ] No hardcoded secrets or sensitive data
- [ ] No unnecessary dependencies added
- [ ] Performance impact considered
- [ ] Backwards compatibility maintained
- [ ] Commit messages are clear

---

## Recognition

Contributors are recognized in:
- GitHub contributors page
- Release notes
- Project README

---

## Questions?

- **Discord**: Join our community server
- **Email**: dev@cyberguardian.ai
- **Discussions**: GitHub Discussions tab
- **Issues**: Use GitHub Issues for bugs

---

## Resources for Contributors

### Learning Resources
- [Flask Documentation](https://flask.palletsprojects.com/)
- [Python Best Practices](https://pep8.org/)
- [SQLite Guide](https://www.sqlite.org/docs.html)
- [Security Best Practices](https://owasp.org/)

### Useful Tools
- [Git Cheat Sheet](https://github.github.com/training-kit/downloads/github-git-cheat-sheet.pdf)
- [Markdown Guide](https://www.markdownguide.org/)
- [Regular Expression Tester](https://regex101.com/)

### Local Development Setup Video Tutorial
- [Available on YouTube](https://example.com)

---

## Thank You!

Your contributions help make CyberGuardian AI better for everyone. We appreciate your time and effort! 🙏

**Happy coding!** 🚀

---

**Last Updated:** September 17, 2026
