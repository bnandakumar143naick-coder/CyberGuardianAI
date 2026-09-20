"""
CyberGuardian AI - AI Explainer

Turns structured findings from the risk engine into a short, plain-
language explanation and recommended actions. Uses an LLM (Anthropic
API) if AI_API_KEY is configured; otherwise falls back to a clear
rule-based template so the app always works end-to-end offline.

IMPORTANT: The LLM is only ever given the indicators the analysis
engine actually detected. It is instructed not to invent evidence.
"""

import json
import logging
import requests

logger = logging.getLogger(__name__)

BASE_RECOMMENDATIONS = {
    "PHISHING": [
        "Do not click the link or enter your login details.",
        "Do not share your password, PIN, or OTP with anyone.",
        "Verify independently using the organisation's official app or website.",
    ],
    "FINANCIAL_SCAM": [
        "Do not transfer money or pay any 'processing fee'.",
        "Do not share your bank/UPI details.",
        "Verify the offer directly with the organisation through official channels.",
    ],
    "JOB_SCAM": [
        "Do not pay any registration or processing fee for a job offer.",
        "Verify the company's identity independently before sharing documents.",
        "Be cautious of unrealistic salaries for minimal work.",
    ],
    "QR_RISK": [
        "Do not scan or open the QR destination if it wasn't expected.",
        "Check the decoded link before visiting it.",
        "Verify independently if the QR claims to be from a bank or official source.",
    ],
    "MALICIOUS_URL": [
        "Do not click or visit this link.",
        "Do not enter any personal or payment information.",
        "Check the sender/source through an independent, trusted channel.",
    ],
    "SOCIAL_ENGINEERING": [
        "Slow down - urgency and fear are common manipulation tactics.",
        "Do not act on pressure alone; verify independently.",
        "Avoid sharing personal or financial information based on this message.",
    ],
    "SUSPICIOUS": [
        "Treat this content with caution.",
        "Avoid sharing sensitive information until you can verify the source.",
    ],
    "SAFE": [
        "No major action needed, but always verify unexpected requests independently.",
    ],
    "UNKNOWN": [
        "Not enough information was extracted to assess this content confidently.",
        "Avoid acting on it until you can verify the source independently.",
    ],
}


def _rule_based_explanation(threat_type: str, reasons: list, risk_score: int) -> str:
    if not reasons:
        return (
            "No major suspicious indicators were detected by CyberGuardian's "
            "current analysis. This does not guarantee the content is completely "
            "safe - always verify unexpected requests independently."
        )

    reason_text = "; ".join(reasons[:5]).lower()
    return (
        f"This content was classified as {threat_type.replace('_', ' ').title()} "
        f"with a Cyber Risk Score of {risk_score}/100. The main reasons are: "
        f"{reason_text}. Together, these patterns are commonly seen in scam or "
        f"phishing attempts, though this is not a definitive verdict."
    )


def _call_llm(api_key: str, api_url: str, model: str, findings: dict) -> str | None:
    """Call the LLM with strictly the detected findings. Returns text or None on failure."""
    system_prompt = (
        "You are a cybersecurity assistant. You will be given structured, "
        "already-detected findings from a rule-based analysis engine. "
        "Write a short (3-5 sentence), plain-language explanation of why the "
        "content might be risky, aimed at a non-technical user. "
        "STRICT RULE: only reference indicators present in the findings JSON. "
        "Do not invent technical evidence, statistics, or claims that are not "
        "in the findings. Do not claim certainty - use language like "
        "'potential' and 'may indicate'."
    )

    user_content = (
        "Findings:\n" + json.dumps(findings, indent=2) +
        "\n\nWrite the explanation now."
    )

    payload = {
        "model": model,
        "max_tokens": 400,
        "system": system_prompt,
        "messages": [{"role": "user", "content": user_content}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    try:
        resp = requests.post(api_url, json=payload, headers=headers, timeout=15)
        resp.raise_for_status()
        data = resp.json()
        parts = [b.get("text", "") for b in data.get("content", []) if b.get("type") == "text"]
        text = "\n".join(p for p in parts if p).strip()
        return text or None
    except Exception as exc:  # noqa: BLE001 - AI must never crash the app
        logger.warning("AI explainer call failed, using rule-based fallback: %s", exc)
        return None


def generate_explanation(config, threat_type: str, risk_score: int, reasons: list, extracted_text: str = "") -> dict:
    """
    Build the final explanation + recommendations block for the report.

    Returns:
        {
            "explanation": str,
            "recommendations": list[str],
            "ai_used": bool,
            "status_message": str | None
        }
    """
    recommendations = BASE_RECOMMENDATIONS.get(threat_type, BASE_RECOMMENDATIONS["SUSPICIOUS"])
    status_message = None
    ai_used = False

    if config.AI_API_KEY:
        findings = {
            "risk_score": risk_score,
            "threat_type": threat_type,
            "indicators": reasons,
            "extracted_text_excerpt": (extracted_text or "")[:500],
        }
        llm_text = _call_llm(config.AI_API_KEY, config.AI_API_URL, config.AI_MODEL, findings)
        if llm_text:
            return {
                "explanation": llm_text,
                "recommendations": recommendations,
                "ai_used": True,
                "status_message": None,
            }
        status_message = "AI explanation service is temporarily unavailable. Showing rule-based security analysis."

    explanation = _rule_based_explanation(threat_type, reasons, risk_score)
    return {
        "explanation": explanation,
        "recommendations": recommendations,
        "ai_used": ai_used,
        "status_message": status_message,
    }
