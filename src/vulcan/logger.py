"""
logging helpers
"""

from __future__ import annotations

import json
import logging
import os
import sys
from contextvars import ContextVar
from typing import Any

_REQUEST_ID_CTX: ContextVar[str | None] = ContextVar("vulcan_request_id", default=None)
_CONFIGURED = False


def set_request_id(request_id: str | None) -> None:
    """Bind a request ID to the current context"""
    _REQUEST_ID_CTX.set(request_id)


def clear_request_id() -> None:
    _REQUEST_ID_CTX.set(None)


def get_request_id() -> str | None:
    return _REQUEST_ID_CTX.get()


class _RequestIdFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _REQUEST_ID_CTX.get()
        return True


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        request_id = getattr(record, "request_id", None)
        if request_id:
            payload["request_id"] = request_id
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str)


def configure_logging(level: str | int = "INFO", json_logs: bool = True) -> None:
    """
    configure the root logger

    subsequent calls update the level/format but don't duplicate handlers
    """
    global _CONFIGURED

    if isinstance(level, str):
        level = logging.getLevelName(level.upper())
        if not isinstance(level, int):
            level = logging.INFO

    handler = logging.StreamHandler(sys.stdout)
    if json_logs:
        handler.setFormatter(_JsonFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
    handler.addFilter(_RequestIdFilter())

    root = logging.getLogger()
    if _CONFIGURED:
        for existing in list(root.handlers):
            root.removeHandler(existing)
    root.addHandler(handler)
    root.setLevel(level)

    logging.getLogger("scapy").setLevel(logging.ERROR)
    logging.getLogger("docker.utils.config").setLevel(logging.WARNING)

    _CONFIGURED = True


def get_logger(name: str | None = None) -> logging.Logger:
    """return a named logger"""
    if not _CONFIGURED:
        configure_logging(
            level=os.environ.get("VULCAN_LOG_LEVEL", "INFO"),
            json_logs=os.environ.get("VULCAN_JSON_LOGS", "true").lower() in {"1", "true", "yes", "on"},
        )
    return logging.getLogger(name)
