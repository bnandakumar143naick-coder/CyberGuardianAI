"""
CyberGuardian AI - Message / NLP Analyzer

Rule-based behavioural-signal detection over extracted text. This is
intentionally transparent (keyword/pattern based) so every signal it
raises can be explained to the user. It does NOT claim to prove fraud -
only to flag patterns worth a closer look.
"""

import re

# Each category maps to: (keywords/phrases, human-readable label)
SIGNAL_CATEGORIES = {
    "URGENCY": {
        "label": "Artificial urgency",
        "patterns": [
            r"\bimmediately\b", r"\burgent\b", r"\bwithin\s+\d+\s*(minutes|hours|mins)\b",
            r"\bact now\b", r"\blast chance\b", r"\bexpire[sd]?\s+(today|soon)\b",
            r"\bhurry\b", r"\btime[-\s]?sensitive\b", r"\bfinal notice\b",
        ],
    },
    "FEAR": {
        "label": "Fear / threatening language",
        "patterns": [
            r"\baccount\s+(will\s+be\s+)?blocked\b", r"\blegal action\b", r"\bpenalty\b",
            r"\bsuspension\b", r"\bsuspended\b", r"\barrest\b", r"\bfine\b",
            r"\bdeactivat(ed|ion)\b", r"\bfraudulent activity\b",
        ],
    },
    "REWARD_BAIT": {
        "label": "Reward / prize bait",
        "patterns": [
            r"\bcongratulations\b", r"\bwon\b.*\b(money|prize|lottery|gift)\b",
            r"\bprize\b", r"\bcashback\b", r"\breward\b", r"\bjackpot\b",
            r"\bfree gift\b", r"\bclaim your\b",
        ],
    },
    "AUTHORITY_IMPERSONATION": {
        "label": "Authority impersonation",
        "patterns": [
            r"\bbank\b", r"\bgovernment\b", r"\bpolice\b", r"\btax department\b",
            r"\bincome tax\b", r"\bcourier\b", r"\bofficial support\b", r"\brbi\b",
            r"\bcustoms\b", r"\bamazon support\b", r"\bmicrosoft support\b",
        ],
    },
    "CREDENTIAL_REQUEST": {
        "label": "Credential / OTP request",
        "patterns": [
            r"\bpassword\b", r"\botp\b", r"\bpin\b", r"\blogin\b",
            r"\bverification code\b", r"\bcvv\b", r"\bsecurity code\b",
        ],
    },
    "FINANCIAL_REQUEST": {
        "label": "Financial / payment request",
        "patterns": [
            r"\btransfer money\b", r"\bpay(ment)?\s+fee\b", r"\bprocessing fee\b",
            r"\bupi\b", r"\bbank account\b", r"\bregistration fee\b",
            r"\badvance payment\b", r"\bwire transfer\b", r"\bgift card\b",
        ],
    },
    "PERSONAL_INFO_REQUEST": {
        "label": "Personal information request",
        "patterns": [
            r"\baadhaar\b", r"\bpan\s*(card|number)?\b", r"\bdate of birth\b",
            r"\bcard number\b", r"\bssn\b", r"\bsocial security\b", r"\baccount details\b",
            r"\bpassport number\b",
        ],
    },
    "SUSPICIOUS_CTA": {
        "label": "Suspicious call to action",
        "patterns": [
            r"\bclick (this|the) link\b", r"\bscan (this|the) qr\b",
            r"\bdownload (this|the) app(lication)?\b", r"\bverify now\b",
            r"\bclick here\b", r"\btap here\b", r"\bconfirm your (details|identity)\b",
        ],
    },
}

# Category → threat category mapping used for primary classification
CATEGORY_TO_THREAT = {
    "CREDENTIAL_REQUEST": "PHISHING",
    "FINANCIAL_REQUEST": "FINANCIAL_SCAM",
    "PERSONAL_INFO_REQUEST": "PHISHING",
    "REWARD_BAIT": "FINANCIAL_SCAM",
}

JOB_SCAM_HINTS = [
    r"\bwork from home\b", r"\bearn\s+\$?\d", r"\bpart[-\s]?time job\b",
    r"\bselected for the (job|post|position)\b", r"\bregistration fee\b.*\bjob\b",
    r"\bscholarship\b", r"\bhiring immediately\b", r"\bno experience needed\b",
]


def analyze_text(text: str) -> dict:
    """
    Scan extracted text for behavioural signals.

    Returns:
        {
            "signals": {category: {"label": str, "matches": [str]}, ...},
            "signal_count": int,
            "job_scam_hint": bool
        }
    """
    if not text:
        return {"signals": {}, "signal_count": 0, "job_scam_hint": False}

    lowered = text.lower()
    signals = {}

    for category, cfg in SIGNAL_CATEGORIES.items():
        matches = []
        for pattern in cfg["patterns"]:
            for m in re.finditer(pattern, lowered):
                matches.append(m.group(0))
        if matches:
            signals[category] = {
                "label": cfg["label"],
                "matches": list(dict.fromkeys(matches))[:5],
            }

    job_scam_hint = any(re.search(p, lowered) for p in JOB_SCAM_HINTS)

    return {
        "signals": signals,
        "signal_count": len(signals),
        "job_scam_hint": job_scam_hint,
    }


def classify_threat(signals: dict, url_risk: int, qr_found: bool, job_scam_hint: bool) -> str:
    """
    Decide a single primary threat category from the collected signals.
    This is a simple, explainable priority ladder - not a black box.
    """
    categories = set(signals.keys())

    if job_scam_hint and ("FINANCIAL_REQUEST" in categories or "SUSPICIOUS_CTA" in categories):
        return "JOB_SCAM"

    if "CREDENTIAL_REQUEST" in categories and (url_risk >= 30 or "AUTHORITY_IMPERSONATION" in categories):
        return "PHISHING"

    if "FINANCIAL_REQUEST" in categories or "REWARD_BAIT" in categories:
        return "FINANCIAL_SCAM"

    if qr_found and url_risk >= 40:
        return "QR_RISK"

    if url_risk >= 50:
        return "MALICIOUS_URL"

    if categories & {"URGENCY", "FEAR", "AUTHORITY_IMPERSONATION", "SUSPICIOUS_CTA"}:
        return "SOCIAL_ENGINEERING"

    if categories:
        return "SUSPICIOUS"

    return "SAFE"
