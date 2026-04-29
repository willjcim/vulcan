from __future__ import annotations

import io
import os
import secrets
import tempfile
import traceback
from datetime import UTC, datetime
from http import HTTPStatus
from typing import Any

from flask import Flask, Response, g, jsonify, request, send_file
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from pydantic import ValidationError
from werkzeug.exceptions import HTTPException, RequestEntityTooLarge
from werkzeug.middleware.proxy_fix import ProxyFix

from vulcan import __version__
from vulcan.config import Settings
from vulcan.logger import (
    clear_request_id,
    configure_logging,
    get_logger,
    set_request_id,
)
from vulcan.models import PacketsRequest
from vulcan.utils import safe_filename
from vulcan.vulcan import VulcanSessionManager

logger = get_logger(__name__)


def create_app(settings: Settings | None = None) -> Flask:
    settings = settings or Settings.from_env()
    configure_logging(level=settings.log_level, json_logs=settings.json_logs)

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_content_length_bytes
    app.config["JSON_SORT_KEYS"] = False
    app.extensions["vulcan_settings"] = settings
    app.extensions["vulcan_start_time"] = datetime.now(tz=UTC)

    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

    CORS(
        app,
        resources={r"/*": {"origins": settings.cors_origins or []}},
        supports_credentials=False,
    )

    limiter = Limiter(
        key_func=get_remote_address,
        app=app,
        default_limits=[settings.rate_limit_default],
        storage_uri=settings.rate_limit_storage_uri,
    )

    _register_request_lifecycle(app, settings)
    _register_routes(app, settings, limiter)
    _register_error_handlers(app)

    return app


# request IDs + auth
_REQUEST_ID_HEADER = "X-Request-ID"

def _register_request_lifecycle(app: Flask, settings: Settings) -> None:
    @app.before_request
    def _before():
        rid = request.headers.get(_REQUEST_ID_HEADER) or secrets.token_hex(8)
        g.request_id = rid
        set_request_id(rid)

        if settings.api_token:
            if request.endpoint in {"healthz", "static"}:
                return None
            provided = request.headers.get("X-API-Token") or _bearer_token(
                request.headers.get("Authorization")
            )
            if not provided or not secrets.compare_digest(provided, settings.api_token):
                logger.warning("Rejected unauthenticated request to %s", request.path)
                return _error("Unauthorized", HTTPStatus.UNAUTHORIZED)

        return None

    @app.after_request
    def _after(response: Response) -> Response:
        rid = getattr(g, "request_id", None)
        if rid:
            response.headers[_REQUEST_ID_HEADER] = rid
        return response

    @app.teardown_request
    def _teardown(_exc: BaseException | None) -> None:
        clear_request_id()


def _bearer_token(value: str | None) -> str | None:
    if not value:
        return None
    parts = value.split(None, 1)
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1].strip()
    return None


# routes
def _register_routes(app: Flask, settings: Settings, limiter: Limiter) -> None:
    @app.route("/healthz", methods=["GET"], strict_slashes=False)
    def healthz() -> Response:
        return jsonify({"status": "ok", "version": __version__})

    @app.route("/get-uptime", methods=["GET"], strict_slashes=False)
    def get_uptime() -> Response:
        start = app.extensions["vulcan_start_time"]
        delta = datetime.now(tz=UTC) - start
        return jsonify({"success": f"uptime: {delta}"})

    @app.route("/create-pcap", methods=["POST"], strict_slashes=False)
    @limiter.limit(settings.rate_limit_create_pcap)
    def create_pcap() -> Response:
        if not request.is_json:
            return _error("Invalid or missing JSON body", HTTPStatus.BAD_REQUEST)

        try:
            payload = request.get_json(silent=False)
        except HTTPException:
            raise
        except Exception:
            return _error("Failed to parse JSON body", HTTPStatus.BAD_REQUEST)

        if not isinstance(payload, list):
            return _error("Request body must be a JSON list of packet objects", HTTPStatus.BAD_REQUEST)

        try:
            validated = PacketsRequest.model_validate(payload)
        except ValidationError as exc:
            return _validation_error(exc)

        packets = validated.to_kwargs_list()

        with tempfile.TemporaryDirectory(prefix="vulcan-") as tmpdir:
            file_name = safe_filename()
            file_path = os.path.join(tmpdir, file_name)

            try:
                session = VulcanSessionManager(packets, file_path)
                session.assemble()
                session.write_cap()
            except ValueError as exc:
                logger.info("Validation error in create-pcap: %s", exc)
                return _error(str(exc), HTTPStatus.BAD_REQUEST)
            except Exception:
                logger.error("Unhandled error in create-pcap:\n%s", traceback.format_exc())
                return _error(
                    "Internal error while assembling packets",
                    HTTPStatus.INTERNAL_SERVER_ERROR,
                )

            if not os.path.isfile(file_path):
                logger.error("Expected pcap %s missing after write_cap()", file_path)
                return _error("Internal error: pcap not produced", HTTPStatus.INTERNAL_SERVER_ERROR)

            with open(file_path, "rb") as fh:
                buf = io.BytesIO(fh.read())

        return send_file(
            buf,
            mimetype="application/vnd.tcpdump.pcap",
            as_attachment=True,
            download_name=file_name,
        )

    @app.route("/edit-pcap", methods=["POST"], strict_slashes=False)
    def edit_pcap() -> tuple[Response, int]:
        return jsonify({"error": "This endpoint isn't ready yet"}), HTTPStatus.NOT_IMPLEMENTED


# error handling
def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(RequestEntityTooLarge)
    def _too_large(_exc: RequestEntityTooLarge):
        return _error("Request body too large", HTTPStatus.REQUEST_ENTITY_TOO_LARGE)

    @app.errorhandler(HTTPException)
    def _http_exc(exc: HTTPException):
        # Preserve Werkzeug's status code but redact the body.
        return _error(exc.name or "HTTP error", exc.code or HTTPStatus.INTERNAL_SERVER_ERROR)

    @app.errorhandler(Exception)
    def _unhandled(exc: Exception):
        logger.error("Unhandled exception: %s\n%s", exc, traceback.format_exc())
        return _error("Internal server error", HTTPStatus.INTERNAL_SERVER_ERROR)


def _error(message: str, status: int) -> tuple[Response, int]:
    body: dict[str, Any] = {"error": message}
    rid = getattr(g, "request_id", None)
    if rid:
        body["request_id"] = rid
    return jsonify(body), status


def _validation_error(exc: ValidationError) -> tuple[Response, int]:
    body: dict[str, Any] = {
        "error": "Request validation failed",
        "details": [
            {"loc": list(err.get("loc", ())), "msg": err.get("msg", ""), "type": err.get("type", "")}
            for err in exc.errors()
        ],
    }
    rid = getattr(g, "request_id", None)
    if rid:
        body["request_id"] = rid
    return jsonify(body), HTTPStatus.UNPROCESSABLE_ENTITY


# entrypoints
app = create_app()


def run_dev() -> None:
    """Local development server"""
    app.run(host=os.environ.get("VULCAN_HOST", "127.0.0.1"), port=int(os.environ.get("VULCAN_PORT", "5000")))


if __name__ == "__main__":
    run_dev()
