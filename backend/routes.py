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

logger = logging.getLogger(__name__)
bp = Blueprint("main", __name__)


# ---------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------

@bp.route("/")
def index():
    return render_template("index.html")


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
