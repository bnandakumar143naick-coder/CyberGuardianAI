"""
CyberGuardian AI - Configuration
"""

import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:

    # Flask
    SECRET_KEY = os.environ.get(
        "SECRET_KEY",
        "dev-secret-change-in-production"
    )

    DEBUG = os.environ.get("FLASK_DEBUG", "False") == "True"

    # ---------------------------------
    # Uploads
    # ---------------------------------

    # Vercel filesystem is not persistent.
    # /tmp is writable during the function execution.
    if os.environ.get("VERCEL"):
        UPLOAD_FOLDER = "/tmp/cyberguardian_uploads"
        DATABASE_PATH = "/tmp/cyberguardian.db"
    else:
        UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
        DATABASE_PATH = os.path.join(
            BASE_DIR,
            "database",
            "cyberguardian.db"
        )

    ALLOWED_EXTENSIONS = {
        "jpg",
        "jpeg",
        "png",
        "webp"
    }

    MAX_CONTENT_LENGTH = 8 * 1024 * 1024

    # Keep uploaded images?
    KEEP_UPLOADS = (
        os.environ.get("KEEP_UPLOADS", "False") == "True"
    )

    # ---------------------------------
    # AI / LLM
    # ---------------------------------

    AI_API_KEY = os.environ.get("AI_API_KEY", "")

    AI_MODEL = os.environ.get(
        "AI_MODEL",
        "claude-sonnet-4-6"
    )

    AI_API_URL = (
        "https://api.anthropic.com/v1/messages"
    )

    # ---------------------------------
    # Risk bands
    # ---------------------------------

    RISK_BANDS = [
        (0, 30, "LOW", "🟢"),
        (31, 60, "MEDIUM", "🟡"),
        (61, 80, "HIGH", "🟠"),
        (81, 100, "CRITICAL", "🔴"),
    ]