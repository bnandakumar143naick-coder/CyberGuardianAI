"""
CyberGuardian AI Phase 3 - Message Intelligence Engine

Analyzes notification/message text to extract behavioral signals.
Each signal is independently verified and documented with evidence.

This is a deterministic, rule-based engine designed for transparency
and explainability. Every signal includes the exact text that triggered it.
"""

import re
from typing import Dict, List, Tuple

# ============================================================================
# SIGNAL DEFINITIONS
# ============================================================================

URGENCY_PATTERNS = {
    "patterns": [
        (r"\bimmediately\b", "Immediate action requested"),
        (r"\burgent\b", "Marked as urgent"),
        (r"\bwithin\s+\d+\s*(minute|hour|day|week)s?\b", "Time-limited action"),
        (r"\bact now\b", "Call to immediate action"),
        (r"\blast chance\b", "Last chance framing"),
        (r"\bexpire[sd]?\s+(today|soon|shortly)\b", "Expiration implied"),
        (r"\bhurry\b", "Pressure to rush"),
        (r"\btime[-\s]?sensitive\b", "Time sensitivity emphasized"),
        (r"\bfinal notice\b", "Final notice language"),
        (r"\bdon't delay\b", "Don't delay message"),
        (r"\bthis won't last\b", "Limited duration implied"),
    ],
    "category": "URGENCY_MANIPULATION",
    "severity": "MEDIUM",
    "base_score": 12,
}

FEAR_PATTERNS = {
    "patterns": [
        (r"\baccount\s+(will\s+be\s+)?(blocked|suspended|closed|terminated|deactivated)\b", "Account blocking threat"),
        (r"\blegal action\b", "Legal threat"),
        (r"\bpenalty\b", "Penalty threat"),
        (r"\bsuspension\b", "Suspension threat"),
        (r"\barrest\b", "Arrest threat"),
        (r"\bfine\b", "Fine/penalty threat"),
        (r"\bdeactivat(ed|ion)\b", "Account deactivation"),
        (r"\bfraudulent activity\b", "Fraud accusation"),
        (r"\bunauthorized access\b", "Security breach claim"),
        (r"\byour account is at risk\b", "Account risk warning"),
        (r"\bsecurity alert\b", "Security alert claim"),
    ],
    "category": "FEAR_PRESSURE",
    "severity": "HIGH",
    "base_score": 14,
}

REWARD_PATTERNS = {
    "patterns": [
        (r"\bcongratulations\b", "Congratulations message"),
        (r"\bwon\b", "Claiming user won something"),
        (r"\bprize\b", "Prize offer"),
        (r"\bcashback\b", "Cashback offer"),
        (r"\breward\b", "Reward offer"),
        (r"\bjackpot\b", "Jackpot mention"),
        (r"\bfree gift\b", "Free gift offer"),
        (r"\bclaim your\b", "Claim your reward"),
        (r"\bmoney\b", "Money offer"),
        (r"\blottery\b", "Lottery mention"),
        (r"\bbonus\b", "Bonus offer"),
    ],
    "category": "REWARD_BAIT",
    "severity": "MEDIUM",
    "base_score": 10,
}

AUTHORITY_PATTERNS = {
    "patterns": [
        (r"\byour\s+bank\b", "Bank impersonation"),
        (r"\b(?:sbi|hdfc|icici|axis bank|kotak)\b", "Bank brand name mentioned"),
        (r"\bgovernment\b", "Government impersonation"),
        (r"\bpolice\b", "Police impersonation"),
        (r"\btax department\b", "Tax authority impersonation"),
        (r"\bincome tax\b", "Income tax impersonation"),
        (r"\brbi\b", "RBI impersonation"),
        (r"\bcustoms\b", "Customs impersonation"),
        (r"\bamazon support\b", "Amazon support impersonation"),
        (r"\bmicrosoft support\b", "Microsoft support impersonation"),
        (r"\bfacebook support\b", "Facebook support impersonation"),
        (r"\bwhatsapp team\b", "WhatsApp team impersonation"),
        (r"\bofficer\b|\badministrator\b", "Authority title claim"),
    ],
    "category": "IMPERSONATION_AUTHORITY",
    "severity": "HIGH",
    "base_score": 15,
}

CREDENTIAL_PATTERNS = {
    "patterns": [
        (r"\botp\b", "OTP request"),
        (r"\bpassword\b", "Password request"),
        (r"\bpin\b", "PIN request"),
        (r"\blogin\b", "Login request"),
        (r"\bverification code\b", "Verification code request"),
        (r"\bsecurity code\b", "Security code request"),
        (r"\bcvv\b", "CVV request"),
        (r"\bcard number\b", "Card number request"),
        (r"\bexpiry\b", "Card expiry request"),
        (r"\bconfirm password\b", "Password confirmation"),
    ],
    "category": "CREDENTIAL_REQUEST",
    "severity": "CRITICAL",
    "base_score": 22,
}

FINANCIAL_PATTERNS = {
    "patterns": [
        (r"\btransfer money\b", "Money transfer request"),
        (r"\bpay(ment)?\s+fee\b", "Fee payment request"),
        (r"\bprocessing fee\b", "Processing fee request"),
        (r"\bupi\b", "UPI payment mention"),
        (r"\bbank account\b", "Bank account request"),
        (r"\bregistration fee\b", "Registration fee request"),
        (r"\bkyc\b", "KYC verification request"),
        (r"\badvance payment\b", "Advance payment request"),
        (r"\bwire transfer\b", "Wire transfer request"),
        (r"\bgift card\b", "Gift card request"),
        (r"\brefund\b", "Refund claim"),
        (r"\bcredit card\b", "Credit card request"),
    ],
    "category": "FINANCIAL_TARGETING",
    "severity": "HIGH",
    "base_score": 18,
}

PERSONAL_INFO_PATTERNS = {
    "patterns": [
        (r"\baadhaar\b", "Aadhaar number request"),
        (r"\bpan\s*(?:card|number)?\b", "PAN request"),
        (r"\bdate of birth\b", "Date of birth request"),
        (r"\bsocial security\b", "Social security request"),
        (r"\bpassport number\b", "Passport request"),
        (r"\bdriver['s]+ license\b", "Driver's license request"),
        (r"\bfather'?s name\b", "Personal info request"),
        (r"\bmother'?s maiden name\b", "Personal info request"),
        (r"\baccount number\b", "Account number request"),
        (r"\bphone number\b", "Phone number verification"),
    ],
    "category": "PERSONAL_INFO_REQUEST",
    "severity": "HIGH",
    "base_score": 16,
}

SUSPICIOUS_CTA_PATTERNS = {
    "patterns": [
        (r"\bclick (?:this|the) link\b", "Suspicious link click"),
        (r"\bscan (?:this|the) qr\b", "QR scan request"),
        (r"\bdownload (?:this|the) app\b", "App download request"),
        (r"\binstall now\b", "App installation request"),
        (r"\bverify now\b", "Verification prompt"),
        (r"\bclick here\b", "Click here CTA"),
        (r"\btap here\b", "Tap here CTA"),
        (r"\bconfirm\s+(?:your\s+)?(?:details|identity)\b", "Confirmation prompt"),
        (r"\bupdate your profile\b", "Profile update request"),
        (r"\breset your password\b", "Password reset request"),
    ],
    "category": "SUSPICIOUS_CTA",
    "severity": "MEDIUM",
    "base_score": 12,
}

JOB_SCAM_PATTERNS = {
    "patterns": [
        (r"\bwork from home\b", "Work from home offer"),
        (r"\bneed\s+\d+\s+people\s+immediately\b", "Immediate hiring"),
        (r"\bearn\s+(?:rs\.?\s*)?\$?\d+[,\d]*\s*(?:/|per\s+)?\s*(?:daily|hourly|per\s*day)\b", "High earnings claim"),
        (r"\bpart[-\s]?time job\b", "Part-time job offer"),
        (r"\bselected\b[^.]{0,50}\b(?:job|post|position)\b", "Selection claim near job mention"),
        (r"\bscholarship\b", "Scholarship offer"),
        (r"\bhiring immediately\b", "Immediate hiring"),
        (r"\bno experience needed\b", "No experience required"),
        (r"\bno interview\b", "No interview claim"),
        (r"\b(?:salary|income|job|placement)\s+guarantee[d]?\b", "Guaranteed income/placement claim"),
    ],
    "category": "JOB_SCAM",
    "severity": "HIGH",
    "base_score": 15,
}

DELIVERY_SCAM_PATTERNS = {
    "patterns": [
        (r"\bparcel\b", "Parcel mention"),
        (r"\bdelivery\b", "Delivery mention"),
        (r"\bfailed delivery\b", "Failed delivery claim"),
        (r"\bcustoms fee\b", "Customs fee request"),
        (r"\brefund\b", "Refund offer"),
        (r"\bverify delivery\b", "Delivery verification"),
        (r"\btracking\b", "Package tracking"),
        (r"\backnowledge delivery\b", "Delivery acknowledgment"),
        (r"\bpayment confirmation\b", "Payment confirmation request"),
        (r"\brefund processing\b", "Refund processing claim"),
    ],
    "category": "DELIVERY_SCAM",
    "severity": "MEDIUM",
    "base_score": 12,
}

ALL_SIGNAL_PATTERNS = [
    URGENCY_PATTERNS,
    FEAR_PATTERNS,
    REWARD_PATTERNS,
    AUTHORITY_PATTERNS,
    CREDENTIAL_PATTERNS,
    FINANCIAL_PATTERNS,
    PERSONAL_INFO_PATTERNS,
    SUSPICIOUS_CTA_PATTERNS,
    JOB_SCAM_PATTERNS,
    DELIVERY_SCAM_PATTERNS,
]

# ============================================================================
# MESSAGE ANALYSIS
# ============================================================================

def analyze_message(text: str) -> Dict:
    """
    Analyze message text for behavioral signals.
    
    Returns:
        {
            "signals": [
                {
                    "category": str,
                    "indicator": str,
                    "severity": str,
                    "base_score": int,
                    "matched_text": str,
                    "evidence": str,
                },
                ...
            ],
            "signal_count": int,
            "unique_categories": set,
        }
    """
    if not text or not isinstance(text, str):
        return {
            "signals": [],
            "signal_count": 0,
            "unique_categories": set(),
        }
    
    lowered = text.lower()
    signals = []
    seen_indicators = set()
    
    # Extract signals from each pattern group
    for pattern_group in ALL_SIGNAL_PATTERNS:
        category = pattern_group["category"]
        severity = pattern_group["severity"]
        base_score = pattern_group["base_score"]
        
        for pattern, evidence_text in pattern_group["patterns"]:
            matches = list(re.finditer(pattern, lowered))
            for match in matches:
                matched_text = match.group(0).strip()
                indicator_key = f"{category}:{matched_text}"
                
                # Avoid duplicate indicators
                if indicator_key not in seen_indicators:
                    seen_indicators.add(indicator_key)
                    signals.append({
                        "category": category,
                        "indicator": evidence_text,
                        "severity": severity,
                        "base_score": base_score,
                        "matched_text": matched_text,
                        "evidence": f"Detected phrase: \"{matched_text}\"",
                    })
    
    unique_categories = set(s["category"] for s in signals)
    
    return {
        "signals": signals,
        "signal_count": len(signals),
        "unique_categories": unique_categories,
    }


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def extract_claimed_brand(text: str) -> str:
    """Extract claimed brand/institution from message."""
    if not text:
        return ""
    
    brand_patterns = [
        r"(?:your\s+)?(\bsbi\b|\bhdfc\b|\bicici\b|\baxis\b|\bkotak\b)",
        r"(?:from\s+)?(\bamazon\b|\bfacebook\b|\bwhatsapp\b|\binstagram\b)",
        r"(?:from\s+)?(\byour\s+\w+\s+(?:bank|app|service))",
    ]
    
    lowered = text.lower()
    for pattern in brand_patterns:
        match = re.search(pattern, lowered)
        if match:
            return match.group(1).title()
    
    return ""


def extract_action_requested(text: str) -> str:
    """Extract requested action from message."""
    if not text:
        return ""
    
    action_patterns = [
        (r"(?:please\s+)?(?:click|tap)\s+(?:this\s+)?link", "Click link"),
        (r"(?:please\s+)?scan\s+(?:this\s+)?qr", "Scan QR code"),
        (r"(?:please\s+)?download\s+(?:our\s+)?app", "Download app"),
        (r"(?:please\s+)?verify\s+(?:your\s+)?(?:details|identity|account)", "Verify account"),
        (r"(?:please\s+)?confirm\s+(?:your\s+)?(?:details|password)", "Confirm details"),
        (r"(?:please\s+)?(?:transfer|send)\s+money", "Transfer money"),
    ]
    
    lowered = text.lower()
    for pattern, action in action_patterns:
        if re.search(pattern, lowered):
            return action
    
    return ""


def get_signal_summary(signals: List[Dict]) -> str:
    """Create a human-readable summary of detected signals."""
    if not signals:
        return "No suspicious signals detected."
    
    categories = set(s["category"] for s in signals)
    category_labels = {
        "URGENCY_MANIPULATION": "Urgency",
        "FEAR_PRESSURE": "Fear/Threat",
        "REWARD_BAIT": "Reward Bait",
        "IMPERSONATION_AUTHORITY": "Authority Claim",
        "CREDENTIAL_REQUEST": "Credential Request",
        "FINANCIAL_TARGETING": "Financial Request",
        "PERSONAL_INFO_REQUEST": "Personal Info Request",
        "SUSPICIOUS_CTA": "Suspicious Link/Action",
        "JOB_SCAM": "Job Scam Pattern",
        "DELIVERY_SCAM": "Delivery Scam Pattern",
    }
    
    labels = [category_labels.get(c, c) for c in sorted(categories)]
    return ", ".join(labels)
