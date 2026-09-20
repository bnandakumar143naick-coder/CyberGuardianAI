"""
CyberGuardian AI Phase 3 - Threat Engine

Detects threat patterns and produces structured threat classification.
"""

from typing import Dict, Set, Tuple, List

# ============================================================================
# THREAT CLASSIFICATIONS
# ============================================================================

THREAT_TYPES = {
    "SAFE": {
        "label": "Safe",
        "description": "No suspicious indicators detected",
        "emoji": "🟢",
    },
    "SUSPICIOUS": {
        "label": "Suspicious",
        "description": "Some suspicious signals detected - use caution",
        "emoji": "🟡",
    },
    "PHISHING": {
        "label": "Phishing Attack",
        "description": "Attempting to steal credentials or personal information",
        "emoji": "🟠",
    },
    "FINANCIAL_SCAM": {
        "label": "Financial Scam",
        "description": "Attempting to obtain money or financial information",
        "emoji": "🟠",
    },
    "SOCIAL_ENGINEERING": {
        "label": "Social Engineering",
        "description": "Using psychological manipulation to trick you",
        "emoji": "🟠",
    },
    "MALICIOUS_URL": {
        "label": "Malicious URL",
        "description": "Contains a link with suspicious characteristics",
        "emoji": "🟠",
    },
    "IMPERSONATION": {
        "label": "Impersonation",
        "description": "Falsely claims to be from a known organization",
        "emoji": "🟠",
    },
    "CREDENTIAL_THEFT": {
        "label": "Credential Theft",
        "description": "Attempting to steal login credentials or authentication codes",
        "emoji": "🔴",
    },
    "JOB_SCAM": {
        "label": "Job Scam",
        "description": "Fraudulent job offer or employment scheme",
        "emoji": "🟠",
    },
    "DELIVERY_SCAM": {
        "label": "Delivery Scam",
        "description": "False delivery or refund notification",
        "emoji": "🟠",
    },
    "QR_RISK": {
        "label": "QR Code Risk",
        "description": "Contains QR code with suspicious destination",
        "emoji": "🟠",
    },
}

# ============================================================================
# THREAT DETECTION
# ============================================================================

def detect_threat(
    message_signals: Dict,
    url_analysis: Dict,
    context: Dict,
    qr_found: bool = False,
) -> Tuple[str, List[str]]:
    """
    Detect threat type from combined signals.
    
    Returns:
        (primary_threat_type, secondary_threat_types)
    """
    
    # Extract signals
    message_categories = message_signals.get("unique_categories", set())
    url_signals = url_analysis.get("all_signals", [])
    context_signals = context.get("signals", [])
    impersonation_risk = context.get("impersonation_risk", False)
    claimed_brand = context.get("claimed_brand", "")
    
    # Check for URL criticality
    has_critical_url = any(
        s.get("severity") == "CRITICAL" for s in url_signals
    )
    has_brand_mismatch = any(
        s.get("indicator") == "Brand/domain mismatch" for s in url_signals
    )
    
    # Extract primary threat
    primary = _classify_primary_threat(
        message_categories=message_categories,
        has_critical_url=has_critical_url,
        has_brand_mismatch=has_brand_mismatch,
        impersonation_risk=impersonation_risk,
        claimed_brand=claimed_brand,
        qr_found=qr_found,
        url_signals=url_signals,
    )
    
    # Extract secondary threats
    secondary = _classify_secondary_threats(
        message_categories=message_categories,
        primary_threat=primary,
    )
    
    return primary, secondary


def _classify_primary_threat(
    message_categories: Set[str],
    has_critical_url: bool,
    has_brand_mismatch: bool,
    impersonation_risk: bool,
    claimed_brand: str,
    qr_found: bool,
    url_signals: List[Dict],
) -> str:
    """
    Deterministic threat classification based on signal priority.
    """
    
    # ====== PRIORITY 1: Credential Theft ======
    if "CREDENTIAL_REQUEST" in message_categories and (
        has_critical_url or impersonation_risk or "FEAR_PRESSURE" in message_categories
    ):
        return "CREDENTIAL_THEFT"
    
    # ====== PRIORITY 2: Job Scam ======
    if "JOB_SCAM" in message_categories:
        if "FINANCIAL_TARGETING" in message_categories or has_critical_url:
            return "JOB_SCAM"
    
    # ====== PRIORITY 3: Financial Scam ======
    if "FINANCIAL_TARGETING" in message_categories:
        if "REWARD_BAIT" in message_categories or has_critical_url:
            return "FINANCIAL_SCAM"
    
    # ====== PRIORITY 4: Phishing ======
    if "CREDENTIAL_REQUEST" in message_categories:
        if has_critical_url or "IMPERSONATION_AUTHORITY" in message_categories:
            return "PHISHING"
    
    # ====== PRIORITY 5: Delivery Scam ======
    if "DELIVERY_SCAM" in message_categories:
        return "DELIVERY_SCAM"
    
    # ====== PRIORITY 6a: Impersonation via confirmed brand/domain mismatch ======
    # Strong, direct evidence: the message claims a brand AND the URL
    # provably goes somewhere else. This alone is sufficient regardless
    # of whether AUTHORITY_PATTERNS matched specific wording.
    if claimed_brand and has_brand_mismatch:
        return "IMPERSONATION"
    
    # ====== PRIORITY 6b: Impersonation via risky brand + suspicious message ======
    # Weaker evidence: brand is commonly impersonated AND the message
    # also carries at least one other suspicious signal. Being a
    # "commonly impersonated" brand alone (e.g. a benign "your Amazon
    # order shipped" message) must NOT be enough on its own, or benign
    # notifications from well-known brands would be false-flagged.
    if claimed_brand and impersonation_risk and message_categories:
        return "IMPERSONATION"
    
    # ====== PRIORITY 7: Malicious URL ======
    if has_critical_url:
        return "MALICIOUS_URL"
    
    # ====== PRIORITY 8: QR Risk ======
    if qr_found and has_critical_url:
        return "QR_RISK"
    
    # ====== PRIORITY 9: Social Engineering ======
    if message_categories & {"URGENCY_MANIPULATION", "FEAR_PRESSURE", "REWARD_BAIT"}:
        if len(message_categories) >= 2:
            return "SOCIAL_ENGINEERING"
    
    # ====== PRIORITY 10: Suspicious or Safe ======
    if message_categories or url_signals:
        return "SUSPICIOUS"
    
    return "SAFE"


def _classify_secondary_threats(
    message_categories: Set[str],
    primary_threat: str,
) -> List[str]:
    """
    Classify secondary threat types that might also apply.
    """
    secondary = []
    
    # Map categories to threat types
    category_to_threat = {
        "CREDENTIAL_REQUEST": "PHISHING",
        "FINANCIAL_TARGETING": "FINANCIAL_SCAM",
        "IMPERSONATION_AUTHORITY": "IMPERSONATION",
        "REWARD_BAIT": "FINANCIAL_SCAM",
        "FEAR_PRESSURE": "SOCIAL_ENGINEERING",
        "JOB_SCAM": "JOB_SCAM",
    }
    
    for category, threat_type in category_to_threat.items():
        if category in message_categories and threat_type != primary_threat:
            if threat_type not in secondary:
                secondary.append(threat_type)
    
    return secondary[:3]  # Limit to 3 secondary threats


# ============================================================================
# THREAT DESCRIPTION GENERATION
# ============================================================================

def get_threat_info(threat_type: str) -> Dict:
    """Get info for a threat type."""
    return THREAT_TYPES.get(threat_type, THREAT_TYPES["SUSPICIOUS"])


def get_threat_description(
    threat_type: str,
    message_categories: Set[str],
    key_indicators: List[str],
) -> str:
    """Generate detailed threat description."""
    threat_info = get_threat_info(threat_type)
    description = threat_info["description"]
    
    if key_indicators:
        description += f"\n\nKey indicators: {', '.join(key_indicators[:3])}"
    
    return description


def get_threat_recommendations(threat_type: str) -> List[str]:
    """Get safety recommendations for threat type."""
    
    recommendations_map = {
        "SAFE": [
            "✓ This message appears safe",
            "Always stay vigilant for social engineering attempts",
            "Report suspicious messages to the app provider",
        ],
        "SUSPICIOUS": [
            "🛑 Be cautious with this message",
            "Verify the sender through a trusted channel",
            "Do not click links or download files",
            "Do not provide any personal information",
        ],
        "PHISHING": [
            "🛑 DANGER: Do not click any links",
            "Do not enter login credentials or personal info",
            "Do not download any files or apps",
            "Report to: Verify sender with official customer support",
            "Use official website/app to access accounts directly",
        ],
        "FINANCIAL_SCAM": [
            "🛑 Do not send money or payment information",
            "Do not authorize transactions",
            "Verify claims through official channels",
            "Contact your bank/service if unsure",
            "Report to: financial regulator/provider",
        ],
        "SOCIAL_ENGINEERING": [
            "🛑 Be aware of manipulation tactics",
            "Scammers create artificial urgency to bypass your judgment",
            "Take time to verify claims independently",
            "Do not act based solely on this message",
        ],
        "MALICIOUS_URL": [
            "🛑 Do not click the suspicious link",
            "Links may lead to malware or phishing sites",
            "Do not download files from the link",
            "Use URL preview or security tools before clicking",
        ],
        "IMPERSONATION": [
            "🛑 This appears to impersonate an organization",
            "Real organizations use official channels",
            "Contact the organization directly (use official contact)",
            "Verify before providing any information",
        ],
        "CREDENTIAL_THEFT": [
            "🛑 CRITICAL: Do not share credentials",
            "Official organizations never ask for passwords via message",
            "Always verify requests through official channels",
            "Use official apps/websites to manage your accounts",
        ],
        "JOB_SCAM": [
            "⚠️  Be skeptical of unsolicited job offers",
            "Real employers don't ask for fees before hiring",
            "Research the company through official sources",
            "Verify through LinkedIn/official career pages",
        ],
        "DELIVERY_SCAM": [
            "⚠️  Verify delivery status through official channels",
            "Use the company's official app or website",
            "Real companies don't ask for urgent payment via message",
            "Contact customer service if you're unsure",
        ],
    }
    
    return recommendations_map.get(threat_type, recommendations_map["SUSPICIOUS"])
