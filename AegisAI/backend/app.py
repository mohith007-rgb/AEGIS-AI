"""
app.py — AEGIS-AI Flask backend.

Endpoints
---------
POST /api/scan        — Upload a file → OCR → AI → JSON result
POST /api/scan-url    — Analyse a URL or pasted text
GET  /health          — Liveness probe

Development:
    python app.py

Production:
    gunicorn wsgi:app
"""

from __future__ import annotations

import logging
import os
import re
import traceback
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, jsonify, request
from flask_cors import CORS


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

_env_path = os.path.join(
    os.path.dirname(__file__),
    ".env",
)

load_dotenv(_env_path)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# App factory
# ---------------------------------------------------------------------------

def create_app() -> Flask:

    app = Flask(__name__)

    # -----------------------------------------------------------------------
    # CORS
    # -----------------------------------------------------------------------

    allowed_origins = os.environ.get(
        "CORS_ORIGINS",
        "*",
    )

    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": allowed_origins
            }
        },
    )

    # -----------------------------------------------------------------------
    # Maximum upload size
    # -----------------------------------------------------------------------

    app.config["MAX_CONTENT_LENGTH"] = (
        10 * 1024 * 1024
    )


    # -----------------------------------------------------------------------
    # Error handlers
    # -----------------------------------------------------------------------

    @app.errorhandler(413)
    def request_entity_too_large(_):

        return (
            jsonify({
                "error": (
                    "File is too large. "
                    "Maximum allowed size is 10 MB."
                )
            }),
            413,
        )


    @app.errorhandler(404)
    def not_found(_):

        return (
            jsonify({
                "error": "Endpoint not found."
            }),
            404,
        )


    @app.errorhandler(405)
    def method_not_allowed(_):

        return (
            jsonify({
                "error": "Method not allowed."
            }),
            405,
        )


    # -----------------------------------------------------------------------
    # Health endpoint
    # -----------------------------------------------------------------------

    @app.route(
        "/health",
        methods=["GET"],
    )
    def health():

        return jsonify({
            "status": "ok"
        }), 200


    # -----------------------------------------------------------------------
    # URL / text scanning
    # -----------------------------------------------------------------------

    @app.route(
        "/api/scan-url",
        methods=["POST"],
    )
    def scan_url():

        from analysis import (
            analyse_text,
            AnalysisError,
        )

        body = request.get_json(
            silent=True
        ) or {}

        url_input = str(
            body.get("url", "") or ""
        ).strip()

        text_input = str(
            body.get("text", "") or ""
        ).strip()

        if not url_input and not text_input:

            return jsonify({
                "error": (
                    "Provide 'url' or 'text' "
                    "in the request body."
                )
            }), 400


        scan_id = str(
            uuid.uuid4()
        )


        # -------------------------------------------------------------------
        # URL supplied
        # -------------------------------------------------------------------

        if url_input:

            if not re.match(
                r"^https?://",
                url_input,
                re.IGNORECASE,
            ):

                url_input = (
                    "https://" + url_input
                )


            logger.info(
                "Scan %s — fetching URL %r",
                scan_id,
                url_input[:120],
            )


            try:

                req = urllib.request.Request(
                    url_input,
                    headers={
                        "User-Agent":
                            "AEGIS-AI-Scanner/1.0"
                    },
                )


                with urllib.request.urlopen(
                    req,
                    timeout=8,
                ) as resp:

                    raw_bytes = resp.read(
                        50_000
                    )

                    content_type = (
                        resp.headers.get(
                            "Content-Type"
                        ) or ""
                    ).lower()


                # -----------------------------------------------------------
                # Determine charset
                # -----------------------------------------------------------

                charset = "utf-8"

                if "charset=" in content_type:

                    charset = (
                        content_type
                        .split("charset=")[-1]
                        .split(";")[0]
                        .strip()
                    )


                try:

                    fetched_text = raw_bytes.decode(
                        charset,
                        errors="replace",
                    )

                except LookupError:

                    fetched_text = raw_bytes.decode(
                        "utf-8",
                        errors="replace",
                    )


                # -----------------------------------------------------------
                # Remove HTML
                # -----------------------------------------------------------

                fetched_text = re.sub(
                    r"<[^>]+>",
                    " ",
                    fetched_text,
                )

                fetched_text = re.sub(
                    r"\s{2,}",
                    " ",
                    fetched_text,
                ).strip()


                analysis_input = (
                    f"URL: {url_input}\n\n"
                    f"{fetched_text[:4000]}"
                )


            except urllib.error.URLError as exc:

                logger.warning(
                    "Scan %s — URL fetch failed: %s",
                    scan_id,
                    exc,
                )

                analysis_input = (
                    f"URL to analyse: "
                    f"{url_input}"
                )


            except Exception as exc:

                logger.warning(
                    "Scan %s — URL fetch error: %s",
                    scan_id,
                    exc,
                )

                analysis_input = (
                    f"URL to analyse: "
                    f"{url_input}"
                )


        # -------------------------------------------------------------------
        # Plain text supplied
        # -------------------------------------------------------------------

        else:

            analysis_input = text_input

            logger.info(
                "Scan %s — analysing pasted text (%d chars)",
                scan_id,
                len(text_input),
            )


        # -------------------------------------------------------------------
        # AI analysis
        # -------------------------------------------------------------------

        try:

            analysis = analyse_text(
                analysis_input
            )

        except AnalysisError as exc:

            logger.error(
                "Scan %s — analysis failed: %s",
                scan_id,
                exc,
            )

            return jsonify({
                "error": str(exc)
            }), 502


        except Exception as exc:

            logger.error(
                "Scan %s — unexpected analysis error:\n%s",
                scan_id,
                traceback.format_exc(),
            )

            return jsonify({
                "error": (
                    "Unexpected error during analysis: "
                    f"{exc}"
                )
            }), 500


        # -------------------------------------------------------------------
        # Response
        # -------------------------------------------------------------------

        response_payload = {

            "extracted_text":
                analysis_input[:500]
                + (
                    "…"
                    if len(analysis_input) > 500
                    else ""
                ),

            "risk_level":
                analysis["risk_level"],

            "threat_category":
                analysis["threat_category"],

            "explanation":
                analysis["explanation"],

            "recommendations":
                analysis["recommendations"],

            "scan_id":
                scan_id,

            "timestamp":
                datetime.now(
                    timezone.utc
                ).isoformat(),
        }


        logger.info(
            "Scan %s complete — risk=%s category=%r",
            scan_id,
            analysis["risk_level"],
            analysis["threat_category"],
        )


        return jsonify(
            response_payload
        ), 200


    # -----------------------------------------------------------------------
    # File scanning
    # -----------------------------------------------------------------------

    @app.route(
        "/api/scan",
        methods=["POST"],
    )
    def scan():

        from validators import (
            validate_upload,
            validate_scan_result,
            ValidationError,
        )


        # -------------------------------------------------------------------
        # Validate upload
        # -------------------------------------------------------------------

        if "file" not in request.files:

            return jsonify({
                "error":
                    "No file field in request."
            }), 400


        file = request.files["file"]


        try:

            file_bytes, mime_type = (
                validate_upload(file)
            )

        except ValidationError as exc:

            return jsonify({
                "error": str(exc)
            }), 400


        scan_id = str(
            uuid.uuid4()
        )


        logger.info(
            "Scan %s started — file=%r mime=%s size=%d",
            scan_id,
            file.filename,
            mime_type,
            len(file_bytes),
        )


        # -------------------------------------------------------------------
        # OCR
        # -------------------------------------------------------------------

        from ocr import (
            extract_text,
            OCRError,
        )


        try:

            extracted_text = extract_text(
                file_bytes,
                mime_type,
            )

        except OCRError as exc:

            logger.error(
                "Scan %s — OCR failed: %s",
                scan_id,
                exc,
            )

            return jsonify({
                "error": (
                    "Text extraction failed. "
                    "Please check that Tesseract OCR "
                    "is installed and try again."
                )
            }), 422


        except Exception as exc:

            logger.error(
                "Scan %s — unexpected OCR error:\n%s",
                scan_id,
                traceback.format_exc(),
            )

            return jsonify({
                "error":
                    "Unexpected error during "
                    f"text extraction: {exc}"
            }), 500


        logger.info(
            "Scan %s — extracted %d chars",
            scan_id,
            len(extracted_text),
        )


        # -------------------------------------------------------------------
        # AI analysis
        # -------------------------------------------------------------------

        from analysis import (
            analyse_text,
            AnalysisError,
        )


        try:

            analysis = analyse_text(
                extracted_text
            )

        except AnalysisError as exc:

            logger.error(
                "Scan %s — analysis failed: %s",
                scan_id,
                exc,
            )

            return jsonify({
                "error": str(exc)
            }), 502


        except Exception as exc:

            logger.error(
                "Scan %s — unexpected analysis error:\n%s",
                scan_id,
                traceback.format_exc(),
            )

            return jsonify({
                "error": (
                    "Unexpected error during analysis: "
                    f"{exc}"
                )
            }), 500


        # -------------------------------------------------------------------
        # Build result
        # -------------------------------------------------------------------

        raw_result = {

            "extracted_text":
                extracted_text,

            "risk_level":
                analysis["risk_level"],

            "threat_category":
                analysis["threat_category"],

            "explanation":
                analysis["explanation"],

            "recommendations":
                analysis["recommendations"],
        }


        # -------------------------------------------------------------------
        # Validate result
        # -------------------------------------------------------------------

        try:

            validated = validate_scan_result(
                raw_result
            )

        except ValueError as exc:

            logger.error(
                "Scan %s — response validation failed: %s",
                scan_id,
                exc,
            )

            return jsonify({
                "error":
                    "Analysis returned invalid data: "
                    f"{exc}"
            }), 502


        # -------------------------------------------------------------------
        # Final response
        # -------------------------------------------------------------------

        response_payload = dict(
            validated
        )

        response_payload["scan_id"] = (
            scan_id
        )

        response_payload["timestamp"] = (
            datetime.now(
                timezone.utc
            ).isoformat()
        )


        logger.info(
            "Scan %s complete — risk=%s category=%r",
            scan_id,
            validated["risk_level"],
            validated["threat_category"],
        )


        return jsonify(
            response_payload
        ), 200


    return app


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------

app = create_app()


# ---------------------------------------------------------------------------
# Development server
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000,
        )
    )

    debug = (
        os.environ.get(
            "FLASK_DEBUG",
            "false",
        ).lower()
        == "true"
    )


    if debug:

        logger.warning(
            "DEBUG mode is ON — "
            "do not use in production."
        )


    logger.info(
        "Starting AEGIS-AI backend "
        "on port %d (debug=%s)",
        port,
        debug,
    )


    app.run(
        host="0.0.0.0",
        port=port,
        debug=debug,
    )