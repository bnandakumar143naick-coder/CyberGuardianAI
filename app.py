"""
CyberGuardian AI - Application Entry Point

Run with:
    python app.py
or:
    flask --app app run
"""

import os
import logging
from flask import Flask
from flask_cors import CORS

from config import Config
from backend.routes import bp as main_bp
from backend.database import init_db

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.from_object(Config)
    app.config["APP_CONFIG"] = Config
    app.config["MAX_CONTENT_LENGTH"] = Config.MAX_CONTENT_LENGTH

    CORS(app)

    # Ensure required directories exist
    os.makedirs(Config.UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(os.path.dirname(Config.DATABASE_PATH), exist_ok=True)

    # Initialise database schema
    init_db(Config.DATABASE_PATH)

    app.register_blueprint(main_bp)

    @app.errorhandler(413)
    def too_large(_e):
        from flask import jsonify
        return jsonify({
            "success": False,
            "message": "File is too large. Please upload an image under 8 MB.",
        }), 413

    @app.errorhandler(500)
    def server_error(_e):
        from flask import jsonify
        return jsonify({
            "success": False,
            "message": "An unexpected error occurred. Please try again.",
        }), 500

    return app


app = create_app()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=Config.DEBUG)
