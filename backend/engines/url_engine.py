"""
CyberGuardian AI Phase 3 - URL Intelligence Engine

Analyzes URLs for structural indicators and brand context mismatches.
Upgraded from Phase 1 to include:
- Brand context detection
- Domain mismatch analysis
- Comprehensive feature extraction
- Structured evidence generation
"""

import re
from urllib.parse import urlparse
from typing import Dict, List, Tuple

# ============================================================================
# TRUSTED DOMAIN REFERENCE
# ============================================================================

TRUSTED_DOMAINS = {
    # Banks
    "sbi": ["sbi.co.in", "onlinesbi.com"],
    "hdfc": ["hdfcbank.com", "hdfc.com"],
    "icici": ["icicibank.com", "ibank.icicibank.com"],
    "axis": ["axisbank.com"],
    "kotak": ["kotakbank.com"],
    
    # Tech/Social
    "amazon": ["amazon.in", "amazon.com"],
    "whatsapp": ["whatsapp.com"],
    "facebook": ["facebook.com", "fb.com"],
    "instagram": ["instagram.com"],
    "microsoft": ["microsoft.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
}

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "short.link",
}

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
PUNYCODE_PATTERN = re.compile(r"xn--")

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "payment", "signin", "password", "unlock",
    "suspend", "billing", "invoice", "reset", "authenticate",
    "authorization", "security", "alert", "action-required",
]

# ============================================================================
# URL ANALYSIS
# ============================================================================

def find_urls(text: str) -> List[str]:
    """Extract all URLs from text."""
    if not text or not isinstance(text, str):
        return []
    
    url_pattern = re.compile(
        r"((?:https?://|www\.)[^\s\"'<>()]+)",
        re.IGNORECASE
    )
    
    matches = url_pattern.findall(text)
    cleaned = []
    
    for match in matches:
        url = match.rstrip(".,;:!?)")
        if not url.lower().startswith(("http://", "https://")):
            url = "http://" + url
        cleaned.append(url)
    
    # De-duplicate while preserving order
    seen = set()
    result = []
    for url in cleaned:
        if url not in seen:
            seen.add(url)
            result.append(url)
    
    return result


def analyze_url(url: str, claimed_brand: str = "") -> Dict:
    """
    Analyze a single URL for suspicious indicators.
    
    Args:
        url: URL to analyze
        claimed_brand: Brand claimed in message (e.g., "SBI", "Amazon")
    
    Returns:
        {
            "url": str,
            "domain": str,
            "signals": [...],
            "features": {...},
            "brand_context": {
                "claimed_brand": str,
                "destination_domain": str,
                "mismatch_risk": bool,
            },
            "risk_contribution": int,
        }
    """
    signals = []
    score = 0
    
    try:
        parsed = urlparse(url)
    except Exception:
        return {
            "url": url,
            "domain": "",
            "signals": [
                {
                    "indicator": "URL parsing error",
                    "severity": "MEDIUM",
                    "evidence": "URL could not be parsed properly",
                }
            ],
            "features": {},
            "brand_context": {},
            "risk_contribution": 15,
        }
    
    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    full_url = url.lower()
    
    # Extract features
    features = {
        "url_length": len(url),
        "hostname": hostname,
        "scheme": parsed.scheme,
        "uses_https": parsed.scheme == "https",
        "has_at_symbol": "@" in url,
        "has_port": parsed.port is not None,
        "port": parsed.port,
        "subdomain_count": max(hostname.count(".") - 1, 0) if hostname else 0,
        "is_ip_address": bool(IP_PATTERN.match(hostname)) if hostname else False,
        "is_shortener": hostname in SHORTENER_DOMAINS,
        "uses_punycode": bool(PUNYCODE_PATTERN.search(hostname)) if hostname else False,
        "path_depth": len(path.split("/")) if path else 0,
        "has_suspicious_keywords": any(kw in full_url for kw in SUSPICIOUS_KEYWORDS),
    }
    
    # ====== SIGNAL 1: URL Length ======
    if features["url_length"] > 100:
        signals.append({
            "indicator": "Unusually long URL",
            "severity": "LOW",
            "evidence": f"URL length: {features['url_length']} characters (typical: <75)",
            "score": 8,
        })
        score += 8
    
    # ====== SIGNAL 2: '@' Symbol ======
    if features["has_at_symbol"]:
        signals.append({
            "indicator": "Contains @ symbol",
            "severity": "HIGH",
            "evidence": "@ can mask the real destination in URL",
            "score": 20,
        })
        score += 20
    
    # ====== SIGNAL 3: IP Address ======
    if features["is_ip_address"]:
        signals.append({
            "indicator": "IP-based URL",
            "severity": "HIGH",
            "evidence": f"Uses IP {hostname} instead of domain name",
            "score": 25,
        })
        score += 25
    
    # ====== SIGNAL 4: Excessive Subdomains ======
    if features["subdomain_count"] >= 3:
        signals.append({
            "indicator": "Multiple subdomains",
            "severity": "MEDIUM",
            "evidence": f"URL has {features['subdomain_count']} subdomains (unusual)",
            "score": 12,
        })
        score += 12
    
    # ====== SIGNAL 5: No HTTPS ======
    if not features["uses_https"] and "http://" in url:
        signals.append({
            "indicator": "Unencrypted connection",
            "severity": "MEDIUM",
            "evidence": "Uses HTTP instead of HTTPS (connection not encrypted)",
            "score": 10,
        })
        score += 10
    
    # ====== SIGNAL 6: Shortener ======
    if features["is_shortener"]:
        signals.append({
            "indicator": "Link shortener",
            "severity": "MEDIUM",
            "evidence": f"Uses {hostname} shortener (hides real destination)",
            "score": 12,
        })
        score += 12
    
    # ====== SIGNAL 7: Punycode/IDN ======
    if features["uses_punycode"]:
        signals.append({
            "indicator": "Punycode/IDN domain",
            "severity": "MEDIUM",
            "evidence": "Uses internationalized domain name (can hide characters)",
            "score": 10,
        })
        score += 10
    
    # ====== SIGNAL 8: Suspicious Keywords ======
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    if matched_keywords:
        signals.append({
            "indicator": "Credential-related keywords",
            "severity": "MEDIUM",
            "evidence": f"Contains: {', '.join(matched_keywords[:3])}",
            "score": min(15, 5 * len(matched_keywords)),
        })
        score += min(15, 5 * len(matched_keywords))
    
    # ====== SIGNAL 9: Multiple Hyphens (Impersonation Pattern) ======
    if hostname.count("-") >= 3:
        signals.append({
            "indicator": "Hyphen-heavy domain",
            "severity": "LOW",
            "evidence": "Domain contains many hyphens (impersonation indicator)",
            "score": 8,
        })
        score += 8
    
    # ====== SIGNAL 10: Brand Mismatch ======
    brand_context = {}
    if claimed_brand:
        brand_context = {
            "claimed_brand": claimed_brand,
            "destination_domain": hostname,
            "mismatch_detected": not _domain_matches_brand(hostname, claimed_brand),
        }
        
        if brand_context["mismatch_detected"]:
            signals.append({
                "indicator": "Brand/domain mismatch",
                "severity": "CRITICAL",
                "evidence": f"Message claims '{claimed_brand}' but URL goes to {hostname}",
                "score": 20,
            })
            score += 20
    
    # Cap score at 100
    score = min(score, 100)
    
    return {
        "url": url,
        "domain": hostname,
        "signals": signals,
        "features": features,
        "brand_context": brand_context,
        "risk_contribution": score,
    }


def analyze_urls(urls: List[str], claimed_brand: str = "") -> Dict:
    """Analyze multiple URLs and return aggregate analysis."""
    if not urls:
        return {
            "analyzed": [],
            "max_risk_contribution": 0,
            "all_signals": [],
            "urls_with_critical_signals": [],
        }
    
    analyzed = [analyze_url(url, claimed_brand) for url in urls]
    max_contribution = max((a["risk_contribution"] for a in analyzed), default=0)
    
    all_signals = []
    urls_with_critical = []
    
    for a in analyzed:
        all_signals.extend(a["signals"])
        if any(s["severity"] == "CRITICAL" for s in a["signals"]):
            urls_with_critical.append(a["url"])
    
    return {
        "analyzed": analyzed,
        "max_risk_contribution": max_contribution,
        "all_signals": all_signals,
        "urls_with_critical_signals": urls_with_critical,
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _domain_matches_brand(domain: str, brand: str) -> bool:
    """Check if domain matches claimed brand."""
    domain_lower = domain.lower()
    brand_lower = brand.lower()
    
    # Get trusted domains for this brand
    trusted = TRUSTED_DOMAINS.get(brand_lower, [])
    
    if domain_lower in trusted:
        return True
    
    # Check if domain starts with brand name (loose check)
    if domain_lower.startswith(brand_lower):
        # But not if it's brand-impersonation (like 'brand-security.com')
        if any(bad in domain_lower for bad in ["-security", "-verify", "-confirm", "-login"]):
            return False
        return True
    
    return False


def extract_brand_from_domain(domain: str) -> str:
    """Extract brand hint from domain."""
    domain_lower = domain.lower()
    
    for brand, trusted_domains in TRUSTED_DOMAINS.items():
        for trusted in trusted_domains:
            if domain_lower == trusted:
                return brand.upper()
    
    # Check if brand name appears at start of domain
    for brand in TRUSTED_DOMAINS.keys():
        if domain_lower.startswith(brand):
            return brand.upper()
    
    return ""


def is_trusted_domain(domain: str) -> bool:
    """Check if domain is in trusted list."""
    domain_lower = domain.lower()
    
    for trusted_domains in TRUSTED_DOMAINS.values():
        if domain_lower in trusted_domains:
            return True
    
    return False
