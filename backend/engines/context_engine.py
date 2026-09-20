"""
CyberGuardian AI Phase 3 - Context Engine

Analyzes sender/app metadata and context to produce contextual risk signals.
"""

from typing import Dict, Optional

# ============================================================================
# APP DEFINITIONS
# ============================================================================

MESSAGING_APPS = {
    "WhatsApp": "messaging",
    "Telegram": "messaging",
    "Signal": "messaging",
    "SMS": "messaging",
    "iMessage": "messaging",
    "WeChat": "messaging",
}

SOCIAL_APPS = {
    "Instagram": "social",
    "Facebook": "social",
    "Twitter": "social",
    "LinkedIn": "social",
    "TikTok": "social",
    "Snapchat": "social",
}

EMAIL_APPS = {
    "Gmail": "email",
    "Outlook": "email",
    "Yahoo Mail": "email",
    "ProtonMail": "email",
}

BANKING_APPS = {
    "SBI": "banking",
    "HDFC Bank": "banking",
    "ICICI Bank": "banking",
    "Axis Bank": "banking",
    "Kotak Bank": "banking",
}

MARKETPLACE_APPS = {
    "Amazon": "marketplace",
    "Flipkart": "marketplace",
    "eBay": "marketplace",
    "OLX": "marketplace",
}

# App risk profile: apps that are commonly impersonated
HIGH_IMPERSONATION_RISK_APPS = {
    "WhatsApp", "Amazon", "SBI", "HDFC Bank", "ICICI Bank",
    "PayPal", "Microsoft", "Apple", "Google", "Facebook",
}

# ============================================================================
# CONTEXT ANALYSIS
# ============================================================================

def analyze_context(
    source_app: Optional[str] = None,
    sender: Optional[str] = None,
    claimed_brand: Optional[str] = None,
) -> Dict:
    """
    Analyze sender/app context.
    
    Args:
        source_app: App the notification came from
        sender: Claimed sender/contact name
        claimed_brand: Brand claimed in message
    
    Returns:
        {
            "source_app": str,
            "app_category": str,
            "sender": str,
            "sender_verified": bool,
            "claimed_brand": str,
            "impersonation_risk": bool,
            "signals": [...],
        }
    """
    signals = []
    
    # Normalize inputs
    source_app = source_app or ""
    sender = sender or ""
    claimed_brand = claimed_brand or ""
    
    app_category = _get_app_category(source_app)
    
    # ====== SIGNAL 1: Brand Impersonation Risk ======
    impersonation_risk = False
    if claimed_brand:
        impersonation_risk = claimed_brand.title() in HIGH_IMPERSONATION_RISK_APPS
        
        if impersonation_risk:
            signals.append({
                "indicator": "High-impersonation brand",
                "severity": "HIGH",
                "evidence": f"{claimed_brand} is commonly impersonated in scams",
            })
    
    # ====== SIGNAL 2: App Impersonation ======
    if source_app and sender:
        app_sender_mismatch = _check_app_sender_mismatch(source_app, sender)
        if app_sender_mismatch:
            signals.append({
                "indicator": "Inconsistent sender",
                "severity": "MEDIUM",
                "evidence": f"Sender '{sender}' inconsistent with app '{source_app}'",
            })
    
    # ====== SIGNAL 3: Messaging App Risk ======
    if source_app in ["WhatsApp", "Telegram", "SMS"]:
        # These apps are common vectors for phishing
        signals.append({
            "indicator": "Common phishing vector",
            "severity": "LOW",
            "evidence": f"{source_app} is a common vector for scam messages",
        })
    
    return {
        "source_app": source_app,
        "app_category": app_category,
        "sender": sender,
        "sender_verified": False,  # Phase 4 can add real verification
        "claimed_brand": claimed_brand,
        "impersonation_risk": impersonation_risk,
        "signals": signals,
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _get_app_category(app_name: str) -> str:
    """Get app category."""
    if not app_name:
        return "UNKNOWN"
    
    app_lower = app_name.lower()
    
    if app_lower in [a.lower() for a in MESSAGING_APPS.keys()]:
        return "MESSAGING"
    if app_lower in [a.lower() for a in SOCIAL_APPS.keys()]:
        return "SOCIAL"
    if app_lower in [a.lower() for a in EMAIL_APPS.keys()]:
        return "EMAIL"
    if app_lower in [a.lower() for a in BANKING_APPS.keys()]:
        return "BANKING"
    if app_lower in [a.lower() for a in MARKETPLACE_APPS.keys()]:
        return "MARKETPLACE"
    
    return "UNKNOWN"


def _check_app_sender_mismatch(app_name: str, sender: str) -> bool:
    """Check if sender is inconsistent with app."""
    if not sender or not app_name:
        return False
    
    sender_lower = sender.lower()
    app_lower = app_name.lower()
    
    # Generic official-sounding names that might be suspicious
    suspicious_sender_names = {
        "support", "admin", "system", "service", "noreply",
        "notification", "alert", "security", "account",
    }
    
    if sender_lower in suspicious_sender_names:
        return True  # Mismatch
    
    return False


def get_context_summary(context: Dict) -> str:
    """Create human-readable context summary."""
    parts = []
    
    if context.get("source_app"):
        parts.append(f"From: {context['source_app']}")
    
    if context.get("sender"):
        parts.append(f"Sender: {context['sender']}")
    
    if context.get("claimed_brand"):
        parts.append(f"Claims: {context['claimed_brand']}")
    
    if context.get("impersonation_risk"):
        parts.append("⚠️ High impersonation risk")
    
    return " | ".join(parts) if parts else "No context available"
