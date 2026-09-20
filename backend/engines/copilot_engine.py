"""
CyberGuardian AI Phase 7 - AI Cyber Copilot

A context-aware Q&A layer over a single stored investigation's structured
analysis. This is deliberately deterministic (pattern-matches the question
against a fixed set of intents, then answers from the analysis dict) rather
than calling an external LLM:

  - It has no external dependency, so it always works (Section 15/33 of the
    spec: "If external AI is unavailable, use deterministic responses").
  - It has no prompt-injection surface: the analyzed message text and the
    user's question both only ever flow into Python string matching and
    f-string formatting here, never into anything that "executes"
    instructions found inside them.
  - Every answer is grounded in the `analysis` dict actually passed in —
    nothing here invents evidence that isn't already in that dict.
"""

from typing import Dict

NO_SELECTION_MESSAGE = "Select a security event to ask CyberGuardian about it."


def answer_question(analysis: Dict, question: str) -> str:
    """
    Answer a natural-language question about one stored analysis.

    Args:
        analysis: The structured analysis dict for a single scan (the
            merged analyzer + explainable_ai result, as stored by
            /api/v2/analyze-unified).
        question: The user's typed question. Treated as inert text —
            matched against known intents only, never executed.
    """
    q = (question or "").strip().lower()

    if not q:
        return _fallback(analysis)

    if "why" in q and ("flag" in q or "risk" in q or "suspicious" in q):
        return _why_flagged(analysis)
    if "evidence" in q or "what did you find" in q or "what was found" in q or "what do you see" in q:
        return _what_evidence(analysis)
    if "should i do" in q or "what should" in q or "recommend" in q or "advice" in q:
        return _what_to_do(analysis)
    if "contribut" in q and ("most" in q or "highest" in q or "biggest" in q or "which" in q):
        return _top_contributor(analysis)
    if "legitimate" in q or "could this be safe" in q or "is this safe" in q or "false positive" in q or "real" in q:
        return _could_be_legitimate(analysis)
    if "score" in q or ("risk" in q and "why" not in q):
        return _risk_summary(analysis)

    return _fallback(analysis)


# ============================================================================
# INTENT HANDLERS
# ============================================================================

def _why_flagged(analysis: Dict) -> str:
    explain = analysis.get("explainable_ai") or {}
    summary = explain.get("summary") or analysis.get("risk", {}).get("explanation", "")
    why = explain.get("why_flagged", [])
    if not why:
        return summary or "CyberGuardian did not identify significant threat indicators in this message."
    lines = [f"- {w['title']}: {w['explanation']}" for w in why[:3]]
    return summary + "\n\n" + "\n".join(lines)


def _what_evidence(analysis: Dict) -> str:
    evidence = analysis.get("evidence", {}) or {}
    total = evidence.get("total_items", 0)
    if not total:
        return "CyberGuardian did not record any specific evidence items for this message."
    parts = []
    for sev in ("critical", "high", "medium", "low"):
        items = evidence.get(sev, []) or []
        if items:
            titles = ", ".join(i.get("indicator", "") for i in items[:5])
            parts.append(f"{sev.upper()}: {titles}")
    return f"CyberGuardian recorded {total} evidence item(s).\n" + "\n".join(parts)


def _what_to_do(analysis: Dict) -> str:
    explain = analysis.get("explainable_ai") or {}
    avoid = explain.get("avoid_actions") or []
    recommended = explain.get("recommended_actions") or []
    if not avoid and not recommended:
        recs = analysis.get("recommendations", []) or []
        if not recs:
            return "CyberGuardian has no specific recommendation for this message."
        return "\n".join(f"- {r}" for r in recs)
    lines = []
    if avoid:
        lines.append("Avoid:")
        lines.extend(f"  - {a}" for a in avoid)
    if recommended:
        lines.append("Recommended:")
        lines.extend(f"  - {r}" for r in recommended)
    return "\n".join(lines)


def _top_contributor(analysis: Dict) -> str:
    contributions = analysis.get("risk", {}).get("contributions", []) or []
    if not contributions:
        return "No individual risk contributors were recorded for this message."
    top = max(contributions, key=lambda c: c.get("score", 0))
    return (
        f"The largest single contributor was \"{top.get('indicator')}\" "
        f"(+{top.get('score')} points, {top.get('severity')} severity)."
    )


def _could_be_legitimate(analysis: Dict) -> str:
    risk = analysis.get("risk", {}) or {}
    score = risk.get("score", 0)
    level = risk.get("level", "SAFE")
    if level in ("SAFE", "LOW"):
        return (
            "Based on the available evidence, CyberGuardian did not find strong "
            "indicators of malicious intent \u2014 this could plausibly be legitimate, "
            "though CyberGuardian cannot fully confirm the sender's identity."
        )
    if level == "MEDIUM":
        return (
            "CyberGuardian found some suspicious indicators, but the evidence isn't "
            "strong enough to rule out a legitimate message. Verify the sender through "
            "an official channel before acting on it."
        )
    return (
        f"At a {level.lower()} risk level ({score}/100), the combination of evidence "
        "found makes it unlikely this is a routine legitimate message \u2014 but "
        "CyberGuardian's score is an indicator, not proof, so independent "
        "verification is still the safest step."
    )


def _risk_summary(analysis: Dict) -> str:
    risk = analysis.get("risk", {}) or {}
    return (
        f"CyberGuardian Risk Score: {risk.get('score', 0)}/100 "
        f"({risk.get('level', 'SAFE')}). This score is an evidence-based "
        "indicator, not a statistical probability of maliciousness."
    )


def _fallback(analysis: Dict) -> str:
    return (
        "I can answer questions like \u201cWhy was this flagged?\u201d, \u201cWhat "
        "evidence was detected?\u201d, \u201cWhat should I do?\u201d, \u201cWhich "
        "indicator contributed most?\u201d, or \u201cCould this be legitimate?\u201d "
        "for this investigation. Here's a quick summary:\n\n" + _risk_summary(analysis)
    )
