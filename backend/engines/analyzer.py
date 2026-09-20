"""
CyberGuardian AI Phase 3 + Phase 4 - Analysis Orchestrator

Unifies all threat detection engines into a single analysis pipeline.
"""

from typing import Dict, Optional, Tuple

from . import message_engine
from . import url_engine
from . import context_engine
from . import evidence_engine
from . import risk_engine
from . import threat_engine


# ============================================================================
# UNIFIED ANALYSIS PIPELINE
# ============================================================================

def analyze_notification(
    text: str,
    source_app: Optional[str] = None,
    sender: Optional[str] = None,
) -> Dict:
    """
    Full Phase 3 + Phase 4 analysis pipeline.
    
    Args:
        text: Message/notification text
        source_app: Source application (WhatsApp, Gmail, etc.)
        sender: Sender name/contact
    
    Returns:
        Structured analysis result with evidence and risk
    """
    
    # ====== STAGE 1: MESSAGE INTELLIGENCE ======
    message_analysis = message_engine.analyze_message(text)
    message_signals = message_analysis["signals"]
    claimed_brand = message_engine.extract_claimed_brand(text)
    requested_action = message_engine.extract_action_requested(text)
    
    # ====== STAGE 2: URL INTELLIGENCE ======
    urls = url_engine.find_urls(text)
    url_analysis = url_engine.analyze_urls(urls, claimed_brand)
    
    # ====== STAGE 3: CONTEXT ANALYSIS ======
    context = context_engine.analyze_context(
        source_app=source_app,
        sender=sender,
        claimed_brand=claimed_brand,
    )
    
    # ====== STAGE 4: THREAT DETECTION ======
    primary_threat, secondary_threats = threat_engine.detect_threat(
        message_signals=message_analysis,
        url_analysis=url_analysis,
        context=context,
        qr_found=False,  # Phase 3/4 doesn't include QR yet
    )
    
    # ====== STAGE 5: EVIDENCE COLLECTION ======
    message_evidence = evidence_engine.collect_message_evidence(
        signals=message_signals,
        text_preview=text[:200],
    )
    url_evidence = evidence_engine.collect_url_evidence(url_analysis)
    context_evidence = evidence_engine.collect_context_evidence(context)
    
    evidence_result = evidence_engine.aggregate_evidence(
        message_evidence=message_evidence,
        url_evidence=url_evidence,
        context_evidence=context_evidence,
    )
    
    # ====== STAGE 6: RISK CALCULATION ======
    # Keep message and URL evidence in separate buckets so each is
    # scored against its own budget (risk_engine.MAX_SIGNAL_CONTRIBUTION
    # vs MAX_URL_CONTRIBUTION) rather than competing for one shared cap.
    risk_result = risk_engine.calculate_risk(
        message_evidence=[e.to_dict() for e in message_evidence],
        url_evidence=[e.to_dict() for e in url_evidence],
        context_evidence=[e.to_dict() for e in context_evidence],
        qr_found=False,
    )
    
    # ====== STAGE 7: THREAT INFO & RECOMMENDATIONS ======
    threat_info = threat_engine.get_threat_info(primary_threat)
    recommendations = threat_engine.get_threat_recommendations(primary_threat)
    
    # ====== BUILD RESULT ======
    result = {
        "success": True,
        "analysis_type": "PHASE_3_4_UNIFIED",

        # The original analyzed text. Needed so the Threat Investigation
        # Center (Phase 6, spec Section 19) can display what was actually
        # analyzed. Kept only inside the Phase 6/7 scan_details JSON blob
        # (a separate, additive table) — never added to the original,
        # deliberately lean `scans` table from Phase 1.
        "extracted_text": text,

        # Core Results
        "threat": {
            "primary": primary_threat,
            "secondary": secondary_threats,
            "label": threat_info["label"],
            "description": threat_info["description"],
            "emoji": threat_info["emoji"],
        },
        
        "risk": {
            "score": risk_result["score"],
            "level": risk_result["level"],
            "emoji": risk_result["emoji"],
            "contributions": risk_result["contributions"][:5],  # Top 5
            "explanation": risk_result["explanation"],
        },
        
        # Detailed Analysis
        "message_analysis": {
            "signals": [s.to_dict() for s in message_evidence],
            "signal_count": len(message_evidence),
            "claimed_brand": claimed_brand,
            "requested_action": requested_action,
            "summary": message_engine.get_signal_summary(message_signals),
        },
        
        "url_analysis": {
            "urls_found": urls,
            "analyzed_urls": url_analysis.get("analyzed", []),
            "max_risk_contribution": url_analysis.get("max_risk_contribution", 0),
            "urls_with_critical_signals": url_analysis.get("urls_with_critical_signals", []),
        },
        
        "context_analysis": {
            "source_app": source_app or "Unknown",
            "sender": sender or "Unknown",
            "sender_verified": context.get("sender_verified", False),
            "impersonation_risk": context.get("impersonation_risk", False),
            "summary": context_engine.get_context_summary(context),
        },
        
        # Evidence
        "evidence": {
            "total_items": evidence_result["total_evidence_items"],
            "critical": evidence_result["critical_evidence"],
            "high": evidence_result["high_evidence"],
            "medium": evidence_result["medium_evidence"],
            "low": evidence_result["low_evidence"],
            "summary": evidence_engine.generate_evidence_summary(evidence_result),
            "top": evidence_engine.get_top_evidence(evidence_result, limit=5),
        },
        
        # Recommendations
        "recommendations": recommendations,
        
        # Metadata
        "metadata": {
            "text_length": len(text),
            "urls_detected": len(urls),
            "signals_detected": len(message_evidence),
            "evidence_confidence": _calculate_confidence(risk_result),
        },
    }
    
    return result


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _calculate_confidence(risk_result: Dict) -> str:
    """Calculate confidence level in the analysis."""
    score = risk_result["score"]
    contributions = risk_result.get("contributions", [])
    
    if score < 20:
        return "HIGH"  # Confident it's safe
    elif score > 80:
        return "HIGH"  # Confident it's dangerous
    else:
        # Medium-risk: confidence depends on evidence count
        if len(contributions) >= 3:
            return "MEDIUM"
        else:
            return "LOW"


def get_analysis_summary(analysis: Dict) -> Dict:
    """Get brief summary of analysis for quick display."""
    return {
        "threat": analysis["threat"]["primary"],
        "threat_label": analysis["threat"]["label"],
        "threat_emoji": analysis["threat"]["emoji"],
        "risk_score": analysis["risk"]["score"],
        "risk_level": analysis["risk"]["level"],
        "risk_emoji": analysis["risk"]["emoji"],
        "summary": analysis["evidence"]["summary"],
        "should_block": analysis["risk"]["score"] >= 70,
    }
