"""
CyberGuardian AI - QR Code Processor

Detects and decodes QR codes from an uploaded image using OpenCV's
built-in QRCodeDetector (no external system library like zbar needed).
"""

import logging

logger = logging.getLogger(__name__)

try:
    import cv2
    import numpy as np

    _CV_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CV_AVAILABLE = False


def detect_and_decode(image_path: str) -> dict:
    """
    Detect and decode a QR code in the given image.

    Returns:
        {
            "found": bool,
            "content": str,
            "message": str
        }
    """
    if not _CV_AVAILABLE:
        return {
            "found": False,
            "content": "",
            "message": "QR scanning module is unavailable. Continuing with text and URL analysis.",
        }

    try:
        image = cv2.imread(image_path)
        if image is None:
            return {
                "found": False,
                "content": "",
                "message": "QR code not detected. Continuing with text and image analysis.",
            }

        detector = cv2.QRCodeDetector()

        # Try multi-detect first (handles multiple / rotated QR codes better)
        try:
            ok, decoded_info, _points, _straight_qrcode = detector.detectAndDecodeMulti(image)
            if ok:
                contents = [d for d in decoded_info if d]
                if contents:
                    return {
                        "found": True,
                        "content": contents[0],
                        "all_contents": contents,
                        "message": "QR code detected and decoded.",
                    }
        except Exception:
            pass  # fall through to single-detect

        data, _points, _straight = detector.detectAndDecode(image)
        if data:
            return {
                "found": True,
                "content": data,
                "all_contents": [data],
                "message": "QR code detected and decoded.",
            }

        return {
            "found": False,
            "content": "",
            "message": "No QR code detected in the image.",
        }

    except Exception as exc:  # noqa: BLE001
        logger.warning("QR detection failed: %s", exc)
        return {
            "found": False,
            "content": "",
            "message": "QR code not detected. Continuing with text and image analysis.",
        }
