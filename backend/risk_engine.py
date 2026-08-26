"""
CyberGuardian AI - Risk Engine

Combines behavioural-signal findings and URL/QR findings into a single
transparent 0-100 "Cyber Risk Score", with the reasons that contributed
to it. This is a weighted heuristic score, not a validated statistical
probability.
"""

# Weight given to each behavioural signal category if present.
# Kept modest per-signal so a single keyword never dominates the score,
# and capped in aggregate to avoid double-counting many overlapping signals.
SIGNAL_WEIGHTS = {
    "URGENCY": 12,
    "FEAR": 14,
    "REWARD_BAIT": 10,
    "AUTHORITY_IMPERSONATION": 10,
    "CREDENTIAL_REQUEST": 20,
    "FINANCIAL_REQUEST": 18,
    "PERSONAL_INFO_REQUEST": 16,
    "SUSPICIOUS_CTA": 12,
}

MAX_SIGNAL_CONTRIBUTION = 65   # cap behavioural-signal contribution
MAX_URL_CONTRIBUTION = 40      # cap URL contribution
QR_UNRESOLVED_BONUS = 8        # small bump if a QR points somewhere risky


def get_risk_level(score: int, bands) -> tuple:
    for low, high, level, emoji in bands:
        if low <= score <= high:
            return level, emoji
    return "LOW", "🟢"


def calculate_risk(signals: dict, url_analysis: dict, qr_found: bool, bands) -> dict:
    """
    Combine signals into a final score.

    Args:
        signals: output of analyzer.analyze_text()["signals"]
        url_analysis: output of url_analyzer.analyze_urls()
        qr_found: whether a QR code was detected
        bands: Config.RISK_BANDS

    Returns:
        {
            "score": int,
            "level": str,
            "emoji": str,
            "reasons": [str, ...]
        }
    """
    reasons = []

    # --- Behavioural signal contribution (capped, non-linear to avoid
    #     simply summing every keyword hit) ---
    signal_score = 0
    for category, data in signals.items():
        weight = SIGNAL_WEIGHTS.get(category, 8)
        signal_score += weight
        reasons.append(data["label"])
    signal_score = min(signal_score, MAX_SIGNAL_CONTRIBUTION)

    # --- URL contribution ---
    url_score = 0
    if url_analysis and url_analysis.get("analyzed"):
        url_score = min(url_analysis["max_risk_contribution"], MAX_URL_CONTRIBUTION)
        reasons.extend(url_analysis.get("all_indicators", []))

    # --- QR bonus: an unresolved-but-present QR with a risky payload
    #     nudges the score slightly, since QR destinations are often
    #     not visible to the user before scanning ---
    qr_score = 0
    if qr_found and url_score > 0:
        qr_score = QR_UNRESOLVED_BONUS
        reasons.append("QR code destination shares risk characteristics with the flagged link")

    total = signal_score + url_score + qr_score
    total = max(0, min(int(total), 100))

    level, emoji = get_risk_level(total, bands)

    return {
        "score": total,
        "level": level,
        "emoji": emoji,
        "reasons": list(dict.fromkeys(reasons)),  # de-dup, preserve order
    }
