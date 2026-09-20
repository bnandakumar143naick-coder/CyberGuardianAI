"""
CyberGuardian AI Phase 4 - Evidence Engine

Collects and structures evidence from all threat detection engines.
Every detected threat produces traceable, auditable evidence.
"""

from typing import Dict, List, Optional
from datetime import datetime, timezone

# ============================================================================
# EVIDENCE SCHEMA
# ============================================================================

class Evidence:
    """Represents a single piece of evidence."""
    
    def __init__(
        self,
        evidence_id: str,
        category: str,
        indicator: str,
        severity: str,
        title: str,
        description: str,
        source: str,
        matched_value: str,
        score_contribution: int,
    ):
        self.evidence_id = evidence_id
        self.category = category
        self.indicator = indicator
        self.severity = severity
        self.title = title
        self.description = description
        self.source = source
        self.matched_value = matched_value
        self.score_contribution = score_contribution
        self.timestamp = datetime.now(timezone.utc).isoformat()
    
    def to_dict(self) -> Dict:
        return {
            "evidence_id": self.evidence_id,
            "category": self.category,
            "indicator": self.indicator,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source": self.source,
            "matched_value": self.matched_value,
            "score_contribution": self.score_contribution,
            "timestamp": self.timestamp,
        }


# ============================================================================
# EVIDENCE COLLECTION
# ============================================================================

def collect_message_evidence(
    signals: List[Dict],
    text_preview: str,
) -> List[Evidence]:
    """
    Convert message signals to evidence.
    
    Args:
        signals: List of signal dicts from message_engine
        text_preview: Preview of analyzed text (not the full message)
    
    Returns:
        List of Evidence objects
    """
    evidence_list = []
    
    for idx, signal in enumerate(signals):
        evidence_id = f"msg_{idx}_{signal['category']}"
        
        evidence = Evidence(
            evidence_id=evidence_id,
            category=signal.get("category", "UNKNOWN"),
            indicator=signal.get("indicator", ""),
            severity=signal.get("severity", "LOW"),
            title=signal.get("indicator", "Unknown indicator"),
            description=signal.get("evidence", ""),
            source="MESSAGE_ANALYSIS",
            matched_value=signal.get("matched_text", ""),
            score_contribution=signal.get("base_score", 0),
        )
        evidence_list.append(evidence)
    
    return evidence_list


def collect_url_evidence(
    url_analysis: Dict,
) -> List[Evidence]:
    """
    Convert URL signals to evidence.
    
    Args:
        url_analysis: Aggregate URL analysis result from
            url_engine.analyze_urls(), i.e. a dict with an "analyzed"
            key holding one per-URL result (each with its own
            "signals" list) produced by url_engine.analyze_url().
    
    Returns:
        List of Evidence objects, one per detected URL signal across
        all analyzed URLs.
    """
    evidence_list = []
    idx = 0
    
    for url_result in url_analysis.get("analyzed", []):
        domain = url_result.get("domain", "")
        for signal in url_result.get("signals", []):
            evidence_id = f"url_{idx}_{signal.get('indicator', 'unknown')}"
            
            evidence = Evidence(
                evidence_id=evidence_id,
                category="URL_ANALYSIS",
                indicator=signal.get("indicator", ""),
                severity=signal.get("severity", "LOW"),
                title=signal.get("indicator", "URL issue"),
                description=signal.get("evidence", ""),
                source="URL_ANALYSIS",
                matched_value=domain,
                score_contribution=signal.get("score", 0),
            )
            evidence_list.append(evidence)
            idx += 1
    
    return evidence_list


def collect_context_evidence(
    context: Dict,
) -> List[Evidence]:
    """
    Convert context signals to evidence.
    
    Args:
        context: Context analysis result from context_engine
    
    Returns:
        List of Evidence objects
    """
    evidence_list = []
    
    for idx, signal in enumerate(context.get("signals", [])):
        evidence_id = f"ctx_{idx}_{signal.get('indicator', 'unknown')}"
        
        evidence = Evidence(
            evidence_id=evidence_id,
            category="CONTEXT_ANALYSIS",
            indicator=signal.get("indicator", ""),
            severity=signal.get("severity", "LOW"),
            title=signal.get("indicator", "Context issue"),
            description=signal.get("evidence", ""),
            source="CONTEXT_ANALYSIS",
            matched_value=context.get("sender", "") or context.get("source_app", ""),
            score_contribution=0,  # Context doesn't directly add score
        )
        evidence_list.append(evidence)
    
    return evidence_list


def aggregate_evidence(
    message_evidence: List[Evidence],
    url_evidence: List[Evidence],
    context_evidence: List[Evidence],
) -> Dict:
    """
    Aggregate all evidence into structured result.
    
    Returns:
        {
            "total_evidence_items": int,
            "critical_evidence": [...],
            "high_evidence": [...],
            "medium_evidence": [...],
            "low_evidence": [...],
            "all_evidence": [...],
            "evidence_by_category": {...},
        }
    """
    all_evidence = message_evidence + url_evidence + context_evidence
    
    # Categorize by severity
    critical = [e for e in all_evidence if e.severity == "CRITICAL"]
    high = [e for e in all_evidence if e.severity == "HIGH"]
    medium = [e for e in all_evidence if e.severity == "MEDIUM"]
    low = [e for e in all_evidence if e.severity == "LOW"]
    
    # Group by category
    by_category = {}
    for evidence in all_evidence:
        if evidence.category not in by_category:
            by_category[evidence.category] = []
        by_category[evidence.category].append(evidence)
    
    return {
        "total_evidence_items": len(all_evidence),
        "critical_evidence": [e.to_dict() for e in critical],
        "high_evidence": [e.to_dict() for e in high],
        "medium_evidence": [e.to_dict() for e in medium],
        "low_evidence": [e.to_dict() for e in low],
        "all_evidence": [e.to_dict() for e in all_evidence],
        "evidence_by_category": {
            cat: [e.to_dict() for e in items]
            for cat, items in by_category.items()
        },
    }


# ============================================================================
# EVIDENCE REPORTING
# ============================================================================

def generate_evidence_summary(evidence_dict: Dict) -> str:
    """Generate human-readable evidence summary."""
    critical = evidence_dict.get("critical_evidence", [])
    high = evidence_dict.get("high_evidence", [])
    medium = evidence_dict.get("medium_evidence", [])
    
    summary_parts = []
    
    if critical:
        summary_parts.append(f"🔴 {len(critical)} critical warning(s)")
    
    if high:
        summary_parts.append(f"🟠 {len(high)} high-risk indicator(s)")
    
    if medium:
        summary_parts.append(f"🟡 {len(medium)} medium-risk indicator(s)")
    
    if not summary_parts:
        return "No significant evidence collected"
    
    return " | ".join(summary_parts)


def get_top_evidence(evidence_dict: Dict, limit: int = 5) -> List[Dict]:
    """Get top evidence items by severity and category."""
    all_evidence = evidence_dict.get("all_evidence", [])
    
    # Sort by: severity (CRITICAL > HIGH > MEDIUM > LOW), then score contribution
    severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    
    sorted_evidence = sorted(
        all_evidence,
        key=lambda x: (
            severity_order.get(x.get("severity", "LOW"), 0),
            x.get("score_contribution", 0),
        ),
        reverse=True,
    )
    
    return sorted_evidence[:limit]
