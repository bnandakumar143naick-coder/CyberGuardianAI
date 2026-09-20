"""
CyberGuardian AI - Flask Routes

Implements the full pipeline:
  image -> OCR + QR -> URL analysis -> NLP signals -> risk score
        -> threat classification -> AI explanation -> save + return
"""

import os
import uuid
import logging
from flask import Blueprint, request, jsonify, render_template, current_app

from werkzeug.utils import secure_filename

from backend import ocr_processor, qr_processor, url_analyzer, analyzer, risk_engine, ai_explainer, database
from backend.engines import (
    analyzer as unified_analyzer,
    explainability_engine,
    copilot_engine,
)

logger = logging.getLogger(__name__)
bp = Blueprint("main", __name__)


# ---------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------

@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/command-center")
def command_center():
    return render_template("command-center.html")


@bp.route("/notification-shield")
def notification_shield():
    return render_template("notification-shield.html")


@bp.route("/threat-scanner")
def threat_scanner():
    return render_template("threat-scanner.html")


@bp.route("/threat-investigation")
def threat_investigation():
    return render_template("threat-investigation.html")


@bp.route("/url-intelligence")
def url_intelligence():
    return render_template("url-intelligence.html")


@bp.route("/ai-copilot")
def ai_copilot():
    return render_template("ai-copilot.html")


@bp.route("/analytics")
def analytics():
    return render_template("analytics.html")


@bp.route("/protection-center")
def protection_center():
    return render_template("protection-center.html")


@bp.route("/privacy-settings")
def privacy_settings():
    return render_template("privacy-settings.html")


@bp.route("/scan")
def scan_page():
    return render_template("scan.html")


@bp.route("/result")
def result_page():
    return render_template("result.html")


@bp.route("/history")
def history_page():
    return render_template("history.html")


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

def _allowed_file(filename: str) -> bool:
    ext_ok = "." in filename and filename.rsplit(".", 1)[1].lower() in current_app.config["ALLOWED_EXTENSIONS"]
    return ext_ok


def _run_pipeline(extracted_text: str, qr_result: dict, input_type: str) -> dict:
    """Shared analysis pipeline used by image, text, and URL endpoints."""
    cfg = current_app.config["APP_CONFIG"]

    # Combine any text found in the QR payload into the analysis text
    combined_text = extracted_text or ""
    if qr_result and qr_result.get("found") and qr_result.get("content"):
        combined_text += "\n" + qr_result["content"]

    # 1. URL detection + analysis
    urls = url_analyzer.find_urls(combined_text)
    url_analysis = url_analyzer.analyze_urls(urls)

    # 2. Behavioural NLP signals
    text_signals = analyzer.analyze_text(combined_text)

    # 3. Risk scoring
    risk = risk_engine.calculate_risk(
        signals=text_signals["signals"],
        url_analysis=url_analysis,
        qr_found=bool(qr_result and qr_result.get("found")),
        bands=cfg.RISK_BANDS,
    )

    # 4. Threat classification
    threat_type = analyzer.classify_threat(
        signals=text_signals["signals"],
        url_risk=url_analysis["max_risk_contribution"],
        qr_found=bool(qr_result and qr_result.get("found")),
        job_scam_hint=text_signals["job_scam_hint"],
    )
    if risk["score"] <= 30 and not text_signals["signals"] and not urls:
        threat_type = "SAFE"

    # 5. AI / rule-based explanation
    ai_result = ai_explainer.generate_explanation(
        config=cfg,
        threat_type=threat_type,
        risk_score=risk["score"],
        reasons=risk["reasons"],
        extracted_text=combined_text,
    )

    indicators = [s["label"] for s in text_signals["signals"].values()]
    indicators.extend(url_analysis.get("all_indicators", []))
    indicators = list(dict.fromkeys(indicators))

    summary = (
        f"{threat_type.replace('_', ' ').title()} - risk {risk['score']}/100"
        if threat_type != "SAFE"
        else "No major suspicious indicators detected"
    )

    result = {
        "success": True,
        "input_type": input_type,
        "risk_score": risk["score"],
        "risk_level": risk["level"],
        "risk_emoji": risk["emoji"],
        "threat_type": threat_type,
        "indicators": indicators,
        "urls_found": urls,
        "url_analysis": url_analysis["analyzed"],
        "qr_found": bool(qr_result and qr_result.get("found")),
        "qr_content": qr_result.get("content", "") if qr_result else "",
        "extracted_text": combined_text,
        "explanation": ai_result["explanation"],
        "recommendations": ai_result["recommendations"],
        "ai_used": ai_result["ai_used"],
        "status_message": ai_result["status_message"],
        "summary": summary,
    }

    # 6. Save to history
    scan_id = database.save_scan(cfg.DATABASE_PATH, result)
    result["scan_id"] = scan_id

    return result


# ---------------------------------------------------------------------
# API: Image analysis (photo / screenshot)
# ---------------------------------------------------------------------

@bp.route("/api/analyze-image", methods=["POST"])
def analyze_image():
    cfg = current_app.config["APP_CONFIG"]

    if "image" not in request.files:
        return jsonify({"success": False, "message": "No image file provided."}), 400

    file = request.files["image"]
    if file.filename == "":
        return jsonify({"success": False, "message": "No file selected."}), 400

    if not _allowed_file(file.filename):
        return jsonify({
            "success": False,
            "message": "Unsupported file type. Please upload JPG, PNG, or WEBP.",
        }), 400

    filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
    filepath = os.path.join(cfg.UPLOAD_FOLDER, filename)

    try:
        file.save(filepath)

        # Basic size sanity check (Flask MAX_CONTENT_LENGTH also enforces this)
        if os.path.getsize(filepath) == 0:
            return jsonify({"success": False, "message": "Uploaded file is empty."}), 400

        ocr_result = ocr_processor.extract_text(filepath)
        qr_result = qr_processor.detect_and_decode(filepath)

        pipeline_notes = []
        if not ocr_result["success"]:
            pipeline_notes.append(ocr_result["message"])
        if not qr_result["found"]:
            pipeline_notes.append(qr_result["message"])

        result = _run_pipeline(ocr_result.get("text", ""), qr_result, input_type="image")
        result["pipeline_notes"] = pipeline_notes

        return jsonify(result)

    except Exception as exc:  # noqa: BLE001
        logger.exception("Image analysis failed")
        return jsonify({
            "success": False,
            "message": "Something went wrong analysing this image. Please try again with a clearer photo.",
        }), 500

    finally:
        if os.path.exists(filepath) and not cfg.KEEP_UPLOADS:
            try:
                os.remove(filepath)
            except OSError:
                pass


# ---------------------------------------------------------------------
# API: Raw text analysis
# ---------------------------------------------------------------------

@bp.route("/api/analyze-text", methods=["POST"])
def analyze_text_endpoint():
    data = request.get_json(silent=True) or {}
    text = (data.get("text") or "").strip()

    if not text:
        return jsonify({"success": False, "message": "No text provided."}), 400

    result = _run_pipeline(text, qr_result=None, input_type="text")
    return jsonify(result)


# ---------------------------------------------------------------------
# API: Direct URL check
# ---------------------------------------------------------------------

@bp.route("/api/analyze-url", methods=["POST"])
def analyze_url_endpoint():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"success": False, "message": "No URL provided."}), 400

    result = _run_pipeline(url, qr_result=None, input_type="url")
    return jsonify(result)


# ---------------------------------------------------------------------
# API: QR-only analysis (e.g. from a cropped QR image)
# ---------------------------------------------------------------------

@bp.route("/api/analyze-qr", methods=["POST"])
def analyze_qr_endpoint():
    cfg = current_app.config["APP_CONFIG"]

    if "image" not in request.files:
        return jsonify({"success": False, "message": "No image file provided."}), 400

    file = request.files["image"]
    if not _allowed_file(file.filename):
        return jsonify({"success": False, "message": "Unsupported file type."}), 400

    filename = secure_filename(f"{uuid.uuid4().hex}_{file.filename}")
    filepath = os.path.join(cfg.UPLOAD_FOLDER, filename)

    try:
        file.save(filepath)
        qr_result = qr_processor.detect_and_decode(filepath)

        if not qr_result["found"]:
            return jsonify({"success": True, "qr_found": False, "message": qr_result["message"]})

        result = _run_pipeline("", qr_result, input_type="qr")
        return jsonify(result)

    finally:
        if os.path.exists(filepath) and not cfg.KEEP_UPLOADS:
            try:
                os.remove(filepath)
            except OSError:
                pass


# ---------------------------------------------------------------------
# API: Unified Phase 3 + Phase 4 analysis
#
# Runs notification/message text through the multi-layer threat engine
# (message + URL + context + threat + evidence + risk) and returns the
# full structured result. Saved into the same `scans` table used by
# Phase 1 (via database.save_scan) so /api/history, /api/scan/<id> and
# /api/dashboard all pick it up automatically — no schema change and no
# change to any existing endpoint.
# ---------------------------------------------------------------------

@bp.route("/api/v2/analyze-unified", methods=["POST"])
def analyze_unified_endpoint():
    cfg = current_app.config["APP_CONFIG"]
    data = request.get_json(silent=True) or {}

    # The analyzed text is always treated as inert data, never as
    # instructions — it is only ever passed into regex-based pattern
    # matching in backend.engines, never evaluated or executed.
    text = (data.get("text") or "").strip()
    source_app = (data.get("source_app") or "").strip() or None
    sender = (data.get("sender") or "").strip() or None
    # Optional: the Android NotificationListenerService app sets
    # origin="android" so real phone notifications can be told apart from
    # website "Demo Simulation" scans in history/analytics. Any other
    # value (or none) keeps the original "notification" input type.
    origin = (data.get("origin") or "").strip().lower()

    if not text:
        return jsonify({"success": False, "message": "No text provided."}), 400

    # Guard against pathological input sizes before it reaches the engines.
    max_len = getattr(cfg, "MAX_ANALYZE_TEXT_LENGTH", 20000)
    if len(text) > max_len:
        text = text[:max_len]

    try:
        result = unified_analyzer.analyze_notification(
            text=text,
            source_app=source_app,
            sender=sender,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Unified analysis failed")
        return jsonify({
            "success": False,
            "message": "Something went wrong analysing this message. Please try again.",
        }), 500

    # Phase 5: deterministic, evidence-grounded explanation. Never fails
    # the request even if something odd is in `result` — an explanation
    # engine issue should degrade gracefully, not break the whole scan.
    try:
        result["explainable_ai"] = explainability_engine.generate_explanation(result)
    except Exception:  # noqa: BLE001
        logger.exception("Explanation generation failed")
        result["explainable_ai"] = None

    # Persist using the existing Phase 1 scans table/schema so history,
    # scan-detail, and dashboard endpoints work without modification.
    # Prefer the Phase 5 human-friendly summary for the legacy
    # `explanation` column when available, so even the degraded fallback
    # path (a scan_details row that's missing or lost) still reads well.
    explanation_text = result["risk"]["explanation"]
    if result.get("explainable_ai") and result["explainable_ai"].get("summary"):
        explanation_text = result["explainable_ai"]["summary"]

    db_record = {
        "input_type": "android_notification" if origin == "android" else "notification",
        "risk_score": result["risk"]["score"],
        "risk_level": result["risk"]["level"],
        "threat_type": result["threat"]["primary"],
        "indicators": [c["indicator"] for c in result["risk"]["contributions"]],
        "summary": result["evidence"]["summary"],
        "explanation": explanation_text,
        "recommendations": result["recommendations"],
    }
    scan_id = database.save_scan(cfg.DATABASE_PATH, db_record)

    result["scan_id"] = scan_id
    result["success"] = True

    # Phase 6/7: also persist the FULL structured result (evidence, risk
    # contribution breakdown, explainable AI) plus source_app/sender, so
    # the Threat Investigation Center and Copilot can retrieve it later
    # in full detail. This never touches the `scans` table above.
    try:
        database.save_scan_details(
            cfg.DATABASE_PATH,
            scan_id,
            source_app=source_app or "",
            sender=sender or "",
            full_analysis=result,
        )
    except Exception:  # noqa: BLE001
        logger.exception("Saving scan detail failed (scan itself was still saved)")

    return jsonify(result)


# ---------------------------------------------------------------------
# API: Investigation detail (Phase 6)
#
# Returns the FULL structured analysis for one scan (evidence, risk
# contribution breakdown, explainable AI) when it was created via
# /api/v2/analyze-unified. For older scans that predate scan_details
# (e.g. from a Phase 1 endpoint), degrades honestly to whatever the
# `scans` table actually has, flagged via has_full_detail=false, rather
# than fabricating the missing fields.
# ---------------------------------------------------------------------

@bp.route("/api/v2/scan/<int:scan_id>", methods=["GET"])
def get_scan_v2(scan_id):
    cfg = current_app.config["APP_CONFIG"]
    scan = database.get_scan_by_id(cfg.DATABASE_PATH, scan_id)
    if not scan:
        return jsonify({"success": False, "message": "Scan not found."}), 404

    details = database.get_scan_details(cfg.DATABASE_PATH, scan_id)
    if details and details.get("full_analysis"):
        full = dict(details["full_analysis"])
        full["scan_id"] = scan_id
        full["success"] = True
        full["timestamp"] = scan.get("timestamp")
        full["has_full_detail"] = True
        return jsonify(full)

    # Legacy fallback — only fields actually present in the `scans` row
    # are used; nothing about evidence/URLs/context is invented.
    return jsonify({
        "success": True,
        "has_full_detail": False,
        "scan_id": scan_id,
        "timestamp": scan.get("timestamp"),
        "threat": {
            "primary": scan.get("threat_type", "UNKNOWN"),
            "secondary": [],
            "label": (scan.get("threat_type") or "UNKNOWN").replace("_", " ").title(),
            "emoji": "",
        },
        "risk": {
            "score": scan.get("risk_score", 0),
            "level": scan.get("risk_level", "LOW"),
            "contributions": [],
            "explanation": scan.get("explanation", ""),
        },
        "context_analysis": {
            "source_app": scan.get("input_type", "unknown"),
            "sender": None,
        },
        "evidence": {
            "total_items": len(scan.get("indicators", []) or []),
            "critical": [], "high": [], "medium": [], "low": [],
            "summary": scan.get("summary", ""),
        },
        "recommendations": scan.get("recommendations", []) or [],
        "legacy_indicators": scan.get("indicators", []) or [],
        "explainable_ai": None,
    })


# ---------------------------------------------------------------------
# API: AI Cyber Copilot (Phase 7)
#
# Deterministic, evidence-grounded Q&A scoped to one stored investigation.
# See backend/engines/copilot_engine.py for why this never calls an
# external LLM (no dependency to fail, no prompt-injection surface).
# ---------------------------------------------------------------------

@bp.route("/api/v2/copilot", methods=["POST"])
def copilot_endpoint():
    cfg = current_app.config["APP_CONFIG"]
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    question = (data.get("question") or "").strip()

    if not scan_id:
        return jsonify({
            "success": True,
            "answer": copilot_engine.NO_SELECTION_MESSAGE,
            "grounded": False,
        })

    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError):
        return jsonify({"success": False, "message": "Invalid scan_id."}), 400

    details = database.get_scan_details(cfg.DATABASE_PATH, scan_id)
    if not details or not details.get("full_analysis"):
        return jsonify({
            "success": True,
            "answer": (
                "Detailed evidence isn't available for this older scan, so I "
                "can't answer in depth. Try selecting a more recent investigation."
            ),
            "grounded": False,
        })

    answer = copilot_engine.answer_question(details["full_analysis"], question)
    return jsonify({"success": True, "answer": answer, "grounded": True, "scan_id": scan_id})


# ---------------------------------------------------------------------
# API: Extended analytics (Phase 7)
#
# Adds threats-by-application on top of the existing /api/dashboard
# stats (which already has threats-by-category across ALL scans). Left
# as a separate endpoint rather than changing /api/dashboard's response
# shape, so nothing that already reads /api/dashboard is affected.
# ---------------------------------------------------------------------

@bp.route("/api/v2/analytics", methods=["GET"])
def analytics_endpoint():
    cfg = current_app.config["APP_CONFIG"]
    stats = database.get_dashboard_stats(cfg.DATABASE_PATH)
    app_distribution = database.get_app_distribution(cfg.DATABASE_PATH)
    detail_stats = database.get_detail_stats(cfg.DATABASE_PATH)
    return jsonify({
        "success": True,
        "stats": stats,
        "app_distribution": app_distribution,
        "detail_stats": detail_stats,
    })


# ---------------------------------------------------------------------
# API: History + dashboard
# ---------------------------------------------------------------------

@bp.route("/api/history", methods=["GET"])
def history():
    cfg = current_app.config["APP_CONFIG"]
    limit = request.args.get("limit", default=50, type=int)
    scans = database.get_history(cfg.DATABASE_PATH, limit=limit)
    return jsonify({"success": True, "scans": scans})


@bp.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    cfg = current_app.config["APP_CONFIG"]
    scan = database.get_scan_by_id(cfg.DATABASE_PATH, scan_id)
    if not scan:
        return jsonify({"success": False, "message": "Scan not found."}), 404
    return jsonify({"success": True, "scan": scan})


@bp.route("/api/dashboard", methods=["GET"])
def dashboard():
    cfg = current_app.config["APP_CONFIG"]
    stats = database.get_dashboard_stats(cfg.DATABASE_PATH)
    return jsonify({"success": True, "stats": stats})


@bp.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "success": True,
        "status": "ok",
        "ocr_available": ocr_processor.is_ocr_available(),
    })
