"""
CyberGuardian AI Phase 5 - Explainable AI Engine

Turns the structured Phase 3/4 analysis (threat + risk + evidence) into a
human-readable explanation. This is deterministic and rule-based by design
(see Section 15 of the Phase 5/6/7 spec: "If external AI is unavailable,
use deterministic explanation. The product must still work.") — there is
no external LLM call in this module, so there is no dependency to fail and
no prompt-injection surface. The analyzed message text only ever flows
into Python string formatting here, never into anything that executes it.

Grounding rule: every line in the output must trace back to an actual
field in the analysis dict that was passed in (score, indicator label,
matched phrase, severity). Nothing here invents evidence, threat-intel
results, or probability claims — see DISCLAIMER below, which is worded
to match the exact text required by the spec.
"""

from typing import Dict, List, Tuple

from . import threat_engine

DISCLAIMER = (
    "CyberGuardian Risk Score is an evidence-based risk indicator and is "
    "not a statistical probability of maliciousness."
)

# ============================================================================
# CATEGORY -> EXPLANATION LOOKUP
#
# Keyed by the evidence "category" string exactly as emitted by
# message_engine.py's ALL_SIGNAL_PATTERNS groups. One entry per category
# (not per individual pattern) — this matches the spec's own worked
# example in Section 6, which explains at the indicator/category level
# ("urgency_manipulation" -> one generic sentence), with the *specific*
# matched phrase surfaced separately as "observed_evidence".
#
# priority: lower number = shown earlier. Order follows Section 7 of the
# spec: credential theft, financial targeting, suspicious URL, domain/
# brand mismatch, impersonation, payment request, urgency, social
# engineering, other.
# ============================================================================

CATEGORY_EXPLANATIONS: Dict[str, Dict] = {
    "CREDENTIAL_REQUEST": {
        "why_it_matters": (
            "Legitimate organizations do not normally ask you to share one-time "
            "passwords, PINs, CVVs, or login credentials through a message."
        ),
        "potential_impact": "Account takeover if the requested credential is shared",
        "priority": 1,
    },
    "FINANCIAL_TARGETING": {
        "why_it_matters": (
            "The message asks for a payment, transfer, or financial account "
            "detail — the direct objective of most financial scams."
        ),
        "potential_impact": "Direct financial loss if a payment or transfer is made",
        "priority": 2,
    },
    "IMPERSONATION_AUTHORITY": {
        "why_it_matters": (
            "Claiming to be a bank, government body, or other authority creates "
            "false trust, making the request seem more legitimate than it is."
        ),
        "potential_impact": "Trusting instructions that did not actually come from the claimed organization",
        "priority": 5,
    },
    "PERSONAL_INFO_REQUEST": {
        "why_it_matters": (
            "Government ID numbers and other personal identifiers can be used "
            "for identity theft if handed over to an untrusted party."
        ),
        "potential_impact": "Identity exposure or misuse of personal identification details",
        "priority": 6,
    },
    "URGENCY_MANIPULATION": {
        "why_it_matters": (
            "This wording creates pressure to act quickly, which can discourage "
            "the recipient from pausing to verify the request independently."
        ),
        "potential_impact": "Rushed decisions made under artificial time pressure",
        "priority": 7,
    },
    "FEAR_PRESSURE": {
        "why_it_matters": (
            "Threatening consequences such as account loss or legal trouble is a "
            "common tactic to provoke an emotional reaction instead of a considered one."
        ),
        "potential_impact": "Being pressured into acting out of fear before verifying the claim",
        "priority": 7,
    },
    "SUSPICIOUS_CTA": {
        "why_it_matters": (
            "The message pushes toward an immediate action — clicking, scanning, "
            "or downloading — before there is a chance to verify it's safe."
        ),
        "potential_impact": "Landing on a malicious page or installing unwanted software",
        "priority": 7,
    },
    "REWARD_BAIT": {
        "why_it_matters": (
            "An unexpected prize or reward is a common lure used to get a target "
            "to click a link or share information they otherwise wouldn't."
        ),
        "potential_impact": "Being drawn into sharing information or paying a fee to 'claim' a reward that doesn't exist",
        "priority": 8,
    },
    "JOB_SCAM": {
        "why_it_matters": (
            "Guaranteed income or job placement in exchange for an upfront fee "
            "is a well-known recruitment-scam pattern."
        ),
        "potential_impact": "Losing money paid as a registration or processing fee for a job that doesn't exist",
        "priority": 9,
    },
    "DELIVERY_SCAM": {
        "why_it_matters": (
            "Fake delivery or customs-fee notices are commonly used to trick "
            "recipients into small payments or sharing card details."
        ),
        "potential_impact": "Small unauthorized payments or card-detail exposure via a fake payment page",
        "priority": 9,
    },
}

_DEFAULT_CATEGORY = {
    "why_it_matters": "This is a pattern CyberGuardian associates with scam or phishing messages.",
    "potential_impact": "Potential exposure to a scam or phishing attempt",
    "priority": 9,
}

# URL-specific indicators (category is generically "URL_ANALYSIS" — the
# indicator string itself carries the specific structural signal).
URL_INDICATOR_EXPLANATIONS: Dict[str, Dict] = {
    "Brand/domain mismatch": {
        "why_it_matters": (
            "The message claims to be from one organization, but the link points "
            "to a different, unrelated domain — a strong sign of impersonation."
        ),
        "potential_impact": "Being redirected to a fake, look-alike site set up to imitate the real organization",
        "priority": 4,
    },
    "IP-based URL": {
        "why_it_matters": (
            "The link uses a raw numeric address instead of a domain name, which "
            "legitimate organizations essentially never do for customer-facing links."
        ),
        "potential_impact": "Landing on an unverifiable server with no domain-level accountability",
        "priority": 3,
    },
    "Contains @ symbol": {
        "why_it_matters": (
            "The '@' symbol in a URL can disguise the real destination — browsers "
            "typically ignore everything before it."
        ),
        "potential_impact": "Being sent to a hidden destination different from what the link appears to show",
        "priority": 3,
    },
    "Link shortener": {
        "why_it_matters": "Shortened links hide their real destination until clicked, making it harder to judge safety in advance.",
        "potential_impact": "Being redirected to an unknown or malicious page without warning",
        "priority": 3,
    },
    "Unencrypted connection": {
        "why_it_matters": "The link does not use a secure (HTTPS) connection, so information submitted there could potentially be intercepted.",
        "potential_impact": "Data submitted on the page being exposed in transit",
        "priority": 3,
    },
    "Unusually long URL": {
        "why_it_matters": "Excessively long or complex URLs are sometimes used to obscure the real domain or pack in obfuscation parameters.",
        "potential_impact": "Difficulty visually verifying where the link actually leads",
        "priority": 3,
    },
    "Multiple subdomains": {
        "why_it_matters": "A large number of subdomains can make a suspicious link visually resemble a trusted domain at a glance.",
        "potential_impact": "Mistaking the link for a legitimate, trusted domain",
        "priority": 3,
    },
    "Punycode/IDN domain": {
        "why_it_matters": "Internationalized domain names can use look-alike characters from other alphabets to imitate a trusted name.",
        "potential_impact": "Visually mistaking the domain for a legitimate one",
        "priority": 3,
    },
    "Credential-related keywords": {
        "why_it_matters": "Words like 'login', 'verify', or 'secure' inside the URL itself often indicate a page designed to collect credentials.",
        "potential_impact": "Landing on a page designed to harvest login details",
        "priority": 3,
    },
    "Hyphen-heavy domain": {
        "why_it_matters": "Domains with many hyphens are frequently used to build look-alike addresses that resemble a trusted brand's name.",
        "potential_impact": "Mistaking the domain for a legitimate brand's official site",
        "priority": 3,
    },
    "URL parsing error": {
        "why_it_matters": "The link could not be safely parsed, which is itself unusual for a normal, well-formed link.",
        "potential_impact": "Unpredictable behavior if the link is opened",
        "priority": 3,
    },
}

_DEFAULT_URL = {
    "why_it_matters": "This URL has a structural characteristic commonly seen in suspicious links.",
    "potential_impact": "Landing on an unsafe or unverified page",
    "priority": 3,
}

CONTEXT_INDICATOR_EXPLANATIONS: Dict[str, Dict] = {
    "High-impersonation brand": {
        "why_it_matters": "This message claims to be from a brand that is frequently impersonated in scam messages, so extra caution is warranted.",
        "potential_impact": "Trusting a message that only appears to be from a well-known brand",
        "priority": 5,
    },
    "Inconsistent sender": {
        "why_it_matters": "The sender shown is a generic label (like 'Support' or 'Admin') rather than a specific, verifiable identity.",
        "potential_impact": "Difficulty verifying who actually sent the message",
        "priority": 6,
    },
    "Common phishing vector": {
        "why_it_matters": "This app/channel is frequently used to deliver scam messages, so messages arriving this way deserve extra scrutiny.",
        "potential_impact": "",
        "priority": 9,
    },
}

_DEFAULT_CONTEXT = {
    "why_it_matters": "This is contextual information relevant to assessing the message's legitimacy.",
    "potential_impact": "",
    "priority": 9,
}

_LEVEL_TEXT = {
    "SAFE": "very low risk",
    "LOW": "low risk",
    "MEDIUM": "moderate risk",
    "HIGH": "high risk",
    "CRITICAL": "critical risk",
}

_MAX_WHY_FLAGGED = 8
_MAX_POTENTIAL_IMPACTS = 5


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def generate_explanation(analysis: Dict) -> Dict:
    """
    Build a Phase 5 explanation from a Phase 3/4 analysis result (the dict
    returned by backend.engines.analyzer.analyze_notification()).

    Returns:
        {
            "summary": str,
            "why_flagged": [
                {evidence_id, title, observed_evidence, explanation,
                 severity, score_contribution}, ...
            ],  # sorted strongest/highest-priority evidence first
            "risk_interpretation": str,
            "potential_impacts": [str, ...],
            "recommended_actions": [str, ...],
            "avoid_actions": [str, ...],
            "ai_used": False,
            "disclaimer": str,
        }
    """
    risk = analysis.get("risk", {}) or {}
    threat = analysis.get("threat", {}) or {}
    evidence = analysis.get("evidence", {}) or {}
    contributions = risk.get("contributions", []) or []
    score = risk.get("score", 0)
    level = risk.get("level", "SAFE")
    threat_primary = threat.get("primary", "SAFE")

    category_by_indicator = _build_category_lookup(evidence)

    why_flagged = _build_why_flagged(contributions, category_by_indicator)
    potential_impacts = _build_potential_impacts(contributions, category_by_indicator)
    summary = _build_summary(score, level, threat_primary, why_flagged)
    risk_interpretation = _build_risk_interpretation(score, level)
    avoid_actions, recommended_actions = _split_recommendations(
        analysis.get("recommendations", []) or []
    )

    return {
        "summary": summary,
        "why_flagged": why_flagged[:_MAX_WHY_FLAGGED],
        "risk_interpretation": risk_interpretation,
        "potential_impacts": potential_impacts or [
            "No specific impact identified from the current evidence."
        ],
        "recommended_actions": recommended_actions,
        "avoid_actions": avoid_actions,
        "ai_used": False,
        "disclaimer": DISCLAIMER,
    }


# ============================================================================
# INTERNAL HELPERS
# ============================================================================

def _build_category_lookup(evidence: Dict) -> Dict[str, str]:
    """
    Map indicator label -> category, by combining the severity-bucketed
    evidence lists (critical/high/medium/low) that evidence_engine
    produces. Contributions and evidence entries share the same
    "indicator" string because both originate from the same Evidence
    object, so this lookup lets us recover category info that the
    (already-deduplicated) contributions list doesn't carry directly.
    """
    lookup = {}
    for bucket in ("critical", "high", "medium", "low"):
        for item in evidence.get(bucket, []) or []:
            indicator = item.get("indicator", "")
            if indicator and indicator not in lookup:
                lookup[indicator] = item.get("category", "")
    return lookup


def _lookup_meta(category: str, indicator: str) -> Dict:
    if category == "URL_ANALYSIS":
        return URL_INDICATOR_EXPLANATIONS.get(indicator, _DEFAULT_URL)
    if category == "CONTEXT_ANALYSIS":
        return CONTEXT_INDICATOR_EXPLANATIONS.get(indicator, _DEFAULT_CONTEXT)
    return CATEGORY_EXPLANATIONS.get(category, _DEFAULT_CATEGORY)


def _build_why_flagged(contributions: List[Dict], category_by_indicator: Dict[str, str]) -> List[Dict]:
    items = []
    for idx, c in enumerate(contributions):
        indicator = c.get("indicator", "")
        category = category_by_indicator.get(indicator, "")
        meta = _lookup_meta(category, indicator)
        items.append({
            "evidence_id": f"why_{idx}_{indicator}"[:80],
            "title": indicator,
            "observed_evidence": c.get("matched_value", ""),
            "explanation": meta["why_it_matters"],
            "severity": c.get("severity", "LOW"),
            "score_contribution": c.get("score", 0),
            "_priority": meta["priority"],
        })
    # Strongest/most-important evidence first: lower priority number first,
    # then higher score contribution first within the same priority tier.
    items.sort(key=lambda x: (x["_priority"], -x["score_contribution"]))
    for item in items:
        item.pop("_priority", None)
    return items


def _build_potential_impacts(contributions: List[Dict], category_by_indicator: Dict[str, str]) -> List[str]:
    impacts = []
    seen = set()
    # Iterate in priority order too, so the most relevant impacts surface first.
    ranked = sorted(
        contributions,
        key=lambda c: _lookup_meta(
            category_by_indicator.get(c.get("indicator", ""), ""),
            c.get("indicator", ""),
        )["priority"],
    )
    for c in ranked:
        indicator = c.get("indicator", "")
        category = category_by_indicator.get(indicator, "")
        impact = _lookup_meta(category, indicator).get("potential_impact", "")
        if impact and impact not in seen:
            seen.add(impact)
            impacts.append(impact)
        if len(impacts) >= _MAX_POTENTIAL_IMPACTS:
            break
    return impacts


def _build_summary(score: int, level: str, threat_primary: str, why_flagged: List[Dict]) -> str:
    # Safe: no evidence at all.
    if not why_flagged and threat_primary == "SAFE":
        return "CyberGuardian did not identify significant threat indicators in this message."

    # Uncertain: some signal, but not enough to call it malicious with
    # confidence — matches Section 13's required uncertain-case wording.
    if level in ("LOW", "MEDIUM") and threat_primary in ("SUSPICIOUS", "SAFE"):
        return (
            "CyberGuardian identified suspicious indicators, but the available "
            "evidence is not sufficient to establish that the message is malicious."
        )

    label = threat_engine.get_threat_info(threat_primary).get(
        "label", threat_primary.replace("_", " ").title()
    )
    top_titles = [w["title"] for w in why_flagged[:3] if w.get("title")]
    if top_titles:
        if len(top_titles) == 1:
            joined = top_titles[0]
        else:
            joined = ", ".join(top_titles[:-1]) + " and " + top_titles[-1]
        return (
            f"CyberGuardian flagged this message as {label} based on: {joined}."
        )
    return f"CyberGuardian flagged this message as {label}."


def _build_risk_interpretation(score: int, level: str) -> str:
    level_text = _LEVEL_TEXT.get(level, level.lower())
    return f"CyberGuardian Risk Score: {score}/100 ({level} \u2014 {level_text}). {DISCLAIMER}"


def _split_recommendations(recommendations: List[str]) -> Tuple[List[str], List[str]]:
    """
    Split threat_engine's flat recommendation list into "avoid" (things
    not to do) vs "recommended" (things to do), by simple keyword check —
    the recommendation strings are all authored in-house by threat_engine,
    so this is a controlled, known vocabulary rather than guesswork on
    arbitrary text.
    """
    avoid, recommended = [], []
    for rec in recommendations:
        lowered = rec.lower()
        if "do not" in lowered or "don't" in lowered or "never" in lowered:
            avoid.append(rec)
        else:
            recommended.append(rec)
    return avoid, recommended
