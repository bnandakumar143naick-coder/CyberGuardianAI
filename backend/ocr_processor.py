"""
CyberGuardian AI - OCR Processor

Extracts visible text from an uploaded image using Tesseract OCR
(via pytesseract). Falls back gracefully if OCR is unavailable or
fails - the app must never crash because of a bad/blurry image.
"""

import re
import logging

logger = logging.getLogger(__name__)

try:
    import pytesseract
    from PIL import Image, ImageOps, ImageFilter

    _OCR_AVAILABLE = True
except ImportError:  # pragma: no cover
    _OCR_AVAILABLE = False


def is_ocr_available() -> bool:
    if not _OCR_AVAILABLE:
        return False
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False


def _preprocess(image: "Image.Image") -> "Image.Image":
    """Light preprocessing to improve OCR accuracy on screenshots/photos."""
    gray = ImageOps.grayscale(image)
    gray = gray.filter(ImageFilter.SHARPEN)
    # Upscale small images - helps OCR pick up small phone-screenshot text
    if gray.width < 1000:
        scale = 1000 / gray.width
        gray = gray.resize((int(gray.width * scale), int(gray.height * scale)))
    return gray


def clean_text(raw_text: str) -> str:
    """Normalise whitespace and strip OCR noise characters."""
    if not raw_text:
        return ""
    text = raw_text.replace("\r", "\n")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{2,}", "\n", text)
    return text.strip()


def extract_text(image_path: str) -> dict:
    """
    Extract text from an image file.

    Returns:
        {
            "success": bool,
            "text": str,
            "message": str  # user-facing status message
        }
    """
    if not _OCR_AVAILABLE:
        return {
            "success": False,
            "text": "",
            "message": (
                "OCR engine is not installed on this server. "
                "Install tesseract-ocr and pytesseract to enable text extraction."
            ),
        }

    try:
        image = Image.open(image_path)
        image = image.convert("RGB")
        processed = _preprocess(image)
        raw_text = pytesseract.image_to_string(processed)
        text = clean_text(raw_text)

        if not text or len(text) < 3:
            return {
                "success": False,
                "text": "",
                "message": "Text could not be reliably extracted. Please upload a clearer image.",
            }

        return {"success": True, "text": text, "message": "Text extracted successfully."}

    except Exception as exc:  # noqa: BLE001 - must never crash the pipeline
        logger.warning("OCR extraction failed: %s", exc)
        return {
            "success": False,
            "text": "",
            "message": "Text could not be reliably extracted. Please upload a clearer image.",
        }
