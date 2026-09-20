"""
CyberGuardian AI Phase 4 - Risk Engine (Upgraded)

Evidence-based risk scoring with transparent contribution breakdown.
"""

from typing import Dict, List, Tuple

# ============================================================================
# SCORING CONFIGURATION
# ============================================================================

# Maximum contribution from each signal category (prevents inflation)
MAX_SIGNAL_CONTRIBUTION = 65
MAX_URL_CONTRIBUTION = 40
QR_BONUS = 8

# Risk level bands
RISK_BANDS = [
    (0, 19, "SAFE", "🟢"),
    (20, 39, "LOW", "🟢"),
    (40, 59, "MEDIUM", "🟡"),
    (60, 79, "HIGH", "🟠"),
    (80, 100, "CRITICAL", "🔴"),
]

# ============================================================================
# RISK CALCULATION
# ============================================================================

def calculate_risk(
    message_evidence: List[Dict],
    url_evidence: List[Dict],
    context_evidence: List[Dict],
    qr_found: bool = False,
) -> Dict:
    """
    Calculate risk score from evidence.
    
    Returns:
        {
            "score": int (0-100),
            "level": str,
            "emoji": str,
            "contributions": [...],
            "explanation": str,
        }
    """
    
    score = 0
    contributions = []
    
    # ====== MESSAGE EVIDENCE SCORING ======
    message_score, message_contributions = _score_evidence_list(
        message_evidence,
        max_contribution=MAX_SIGNAL_CONTRIBUTION,
        deduplicate=True,  # Avoid counting same signal twice
    )
    score += message_score
    contributions.extend(message_contributions)
    
    # ====== URL EVIDENCE SCORING ======
    url_score, url_contributions = _score_evidence_list(
        url_evidence,
        max_contribution=MAX_URL_CONTRIBUTION,
        deduplicate=True,
    )
    score += url_score
    contributions.extend(url_contributions)
    
    # ====== QR BONUS (if risky content found) ======
    if qr_found and (message_score > 0 or url_score > 0):
        qr_contribution = min(QR_BONUS, 100 - score)
        score += qr_contribution
        contributions.append({
            "indicator": "QR code detected with risky content",
            "score": qr_contribution,
            "severity": "MEDIUM",
        })
    
    # ====== NORMALIZE SCORE ======
    score = max(0, min(int(score), 100))
    
    # ====== GET RISK LEVEL ======
    level, emoji = _get_risk_level(score)
    
    # ====== CREATE EXPLANATION ======
    explanation = _create_risk_explanation(score, level, contributions)
    
    return {
        "score": score,
        "level": level,
        "emoji": emoji,
        "contributions": contributions,
        "explanation": explanation,
    }


def _score_evidence_list(
    evidence_list: List[Dict],
    max_contribution: int,
    deduplicate: bool = True,
) -> Tuple[int, List[Dict]]:
    """
    Score a list of evidence items.
    
    Returns:
        (total_score, contributions_list)
    """
    if not evidence_list:
        return 0, []
    
    contributions = []
    seen_indicators = set()
    total = 0
    
    # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    sorted_evidence = sorted(
        evidence_list,
        key=lambda x: severity_order.get(x.get("severity", "LOW"), 0),
        reverse=True,
    )
    
    for evidence in sorted_evidence:
        indicator = evidence.get("indicator", "")
        score_contribution = evidence.get("score_contribution", 0)
        severity = evidence.get("severity", "LOW")
        
        # Deduplicate if requested
        if deduplicate and indicator in seen_indicators:
            continue
        seen_indicators.add(indicator)
        
        # Add contribution
        adjusted_score = min(score_contribution, max_contribution - total)
        if adjusted_score > 0:
            total += adjusted_score
            contributions.append({
                "indicator": indicator,
                "score": adjusted_score,
                "severity": severity,
                "matched_value": evidence.get("matched_value", ""),
            })
        
        # Stop if we've hit the max
        if total >= max_contribution:
            break
    
    # Cap at max
    total = min(total, max_contribution)
    
    return total, contributions


def _get_risk_level(score: int) -> Tuple[str, str]:
    """Get risk level and emoji for score."""
    for low, high, level, emoji in RISK_BANDS:
        if low <= score <= high:
            return level, emoji
    
    # Fallback (should not reach here)
    return "LOW", "🟢"


def _create_risk_explanation(
    score: int,
    level: str,
    contributions: List[Dict],
) -> str:
    """Create human-readable risk explanation."""
    
    explanation = f"CyberGuardian Risk Score: {score}/100\n"
    explanation += f"Risk Level: {level}\n\n"
    
    if score == 0:
        explanation += "✓ No suspicious indicators detected in this message.\n"
    elif score < 20:
        explanation += "✓ This message appears safe, but stay cautious.\n"
    elif score < 40:
        explanation += "⚠️  Low-to-moderate risk. Verify before interacting.\n"
    elif score < 60:
        explanation += "⚠️  Moderate risk detected. Use caution.\n"
    elif score < 80:
        explanation += "🛑 High risk. Do not interact. Verify through official channels.\n"
    else:
        explanation += "🛑 CRITICAL RISK. This appears to be a scam. Do not interact.\n"
    
    if contributions:
        explanation += "\nContributing factors:\n"
        for contrib in contributions[:5]:  # Top 5 factors
            explanation += f"  • {contrib['indicator']}: +{contrib['score']} pts\n"
    
    return explanation


# ============================================================================
# RISK TRANSPARENCY
# ============================================================================

def get_risk_breakdown(risk_result: Dict) -> Dict:
    """Get detailed risk score breakdown for UI display."""
    
    return {
        "score": risk_result["score"],
        "level": risk_result["level"],
        "emoji": risk_result["emoji"],
        "message_contribution": sum(
            c["score"] for c in risk_result["contributions"]
            if c.get("severity") != "MEDIUM" or "URL" not in c.get("indicator", "")
        ),
        "url_contribution": sum(
            c["score"] for c in risk_result["contributions"]
            if "URL" in c.get("indicator", "") or c.get("severity") == "CRITICAL"
        ),
        "top_factors": risk_result["contributions"][:3],
        "explanation": risk_result["explanation"],
    }


def should_flag_for_review(risk_result: Dict) -> bool:
    """Determine if result should be flagged for human review."""
    score = risk_result["score"]
    
    # Flag if high risk
    if score >= 70:
        return True
    
    # Flag if multiple critical signals
    critical = [c for c in risk_result["contributions"] if c["severity"] == "CRITICAL"]
    if len(critical) >= 2:
        return True
    
    return False
