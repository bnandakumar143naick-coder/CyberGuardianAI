"""
CyberGuardian AI - URL Analyzer

Extracts structural features from URLs and produces an explainable
set of "potential indicators" plus a partial risk contribution.
This is heuristic, not a guarantee of maliciousness.
"""

import re
from urllib.parse import urlparse

URL_REGEX = re.compile(
    r"((?:https?://|www\.)[^\s\"'<>()]+)", re.IGNORECASE
)

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "payment", "signin", "webscr", "password", "unlock",
    "suspend", "billing", "invoice", "reset",
]

IP_PATTERN = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly",
}


def find_urls(text: str) -> list:
    """Find all URL-like substrings in a block of text."""
    if not text:
        return []
    matches = URL_REGEX.findall(text)
    cleaned = []
    for m in matches:
        m = m.rstrip(".,;:!?)")
        if not m.lower().startswith(("http://", "https://")):
            m = "http://" + m
        cleaned.append(m)
    # De-duplicate while preserving order
    seen = set()
    result = []
    for u in cleaned:
        if u not in seen:
            seen.add(u)
            result.append(u)
    return result


def analyze_url(url: str) -> dict:
    """
    Analyse a single URL and return structural features plus
    a list of human-readable potential indicators and a
    0-100 partial risk contribution.
    """
    indicators = []
    score = 0

    try:
        parsed = urlparse(url)
    except Exception:
        return {
            "url": url,
            "indicators": ["URL could not be parsed"],
            "risk_contribution": 10,
            "features": {},
        }

    hostname = (parsed.hostname or "").lower()
    path = (parsed.path or "").lower()
    full = url.lower()

    features = {
        "length": len(url),
        "hostname": hostname,
        "uses_https": parsed.scheme == "https",
        "has_at_symbol": "@" in url,
        "subdomain_count": max(hostname.count(".") - 1, 0) if hostname else 0,
        "is_ip_based": bool(IP_PATTERN.match(hostname)) if hostname else False,
        "is_shortener": hostname in SHORTENER_DOMAINS,
    }

    # 1. Excessive length
    if features["length"] > 90:
        indicators.append("Unusually long URL")
        score += 10

    # 2. '@' symbol (can hide real destination)
    if features["has_at_symbol"]:
        indicators.append("Contains '@' symbol, which can mask the real destination")
        score += 20

    # 3. IP address instead of domain name
    if features["is_ip_based"]:
        indicators.append("Uses a raw IP address instead of a domain name")
        score += 25

    # 4. Excessive subdomains
    if features["subdomain_count"] >= 3:
        indicators.append("Unusually high number of subdomains")
        score += 15

    # 5. No HTTPS
    if not features["uses_https"]:
        indicators.append("Connection is not encrypted (no HTTPS)")
        score += 10

    # 6. Known shortener (hides real destination)
    if features["is_shortener"]:
        indicators.append("Uses a link-shortening service, which can hide the real destination")
        score += 10

    # 7. Suspicious keywords in path/hostname (credential/verification bait)
    matched_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full]
    if matched_keywords:
        indicators.append(
            "Credential/verification-related path or wording detected (" + ", ".join(matched_keywords[:4]) + ")"
        )
        score += min(20, 5 * len(matched_keywords))

    # 8. Suspicious encoding
    if "%" in path or "xn--" in hostname:
        indicators.append("Contains encoded or punycode characters")
        score += 10

    # 9. Hyphen-heavy hostnames (common brand-impersonation pattern)
    if hostname.count("-") >= 3:
        indicators.append("Hostname contains multiple hyphens, a common impersonation pattern")
        score += 10

    score = min(score, 100)

    return {
        "url": url,
        "indicators": indicators,
        "risk_contribution": score,
        "features": features,
    }


def analyze_urls(urls: list) -> dict:
    """Analyse a list of URLs and return the aggregate worst-case result."""
    if not urls:
        return {"analyzed": [], "max_risk_contribution": 0, "all_indicators": []}

    analyzed = [analyze_url(u) for u in urls]
    max_contribution = max(a["risk_contribution"] for a in analyzed)
    all_indicators = []
    for a in analyzed:
        all_indicators.extend(a["indicators"])

    return {
        "analyzed": analyzed,
        "max_risk_contribution": max_contribution,
        "all_indicators": list(dict.fromkeys(all_indicators)),  # de-dup, preserve order
    }
