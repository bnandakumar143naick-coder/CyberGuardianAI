"""
CyberGuardian AI - Configuration
Loads settings from environment variables. Never hardcode secrets here.
"""

import os
from dotenv import load_dotenv

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


class Config:
    # Flask
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
    DEBUG = os.environ.get("FLASK_DEBUG", "True") == "True"

    # Uploads
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "webp"}
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024  # 8 MB max upload

    # Whether to keep uploaded images after analysis (privacy-first: default False)
    KEEP_UPLOADS = os.environ.get("KEEP_UPLOADS", "False") == "True"

    # Database
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "cyberguardian.db")

    # AI / LLM
    AI_API_KEY = os.environ.get("AI_API_KEY", "")
    AI_MODEL = os.environ.get("AI_MODEL", "claude-sonnet-4-6")
    AI_API_URL = "https://api.anthropic.com/v1/messages"

    # Risk bands
    RISK_BANDS = [
        (0, 30, "LOW", "🟢"),
        (31, 60, "MEDIUM", "🟡"),
        (61, 80, "HIGH", "🟠"),
        (81, 100, "CRITICAL", "🔴"),
    ]
