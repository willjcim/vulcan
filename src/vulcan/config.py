"""
Runtime configuration loaded from environment variables
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _csv(value: str | None) -> list[str]:
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _int(value: str | None, default: int) -> int:
    if value is None or value == "":
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _bool(value: str | None, default: bool) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """All runtime tunables, sourced from environment variables"""

    log_level: str = "INFO"
    json_logs: bool = True
    cors_origins: list[str] = field(default_factory=list)
    api_token: str | None = None
    max_content_length_bytes: int = 1 * 1024 * 1024
    rate_limit_default: str = "60/minute"
    rate_limit_create_pcap: str = "10/minute"
    rate_limit_storage_uri: str = "memory://"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            log_level=os.environ.get("VULCAN_LOG_LEVEL", "INFO").upper(),
            json_logs=_bool(os.environ.get("VULCAN_JSON_LOGS"), True),
            cors_origins=_csv(os.environ.get("VULCAN_CORS_ORIGINS")),
            api_token=os.environ.get("VULCAN_API_TOKEN") or None,
            max_content_length_bytes=_int(
                os.environ.get("VULCAN_MAX_CONTENT_LENGTH"),
                1 * 1024 * 1024,
            ),
            rate_limit_default=os.environ.get("VULCAN_RATE_LIMIT_DEFAULT", "60/minute"),
            rate_limit_create_pcap=os.environ.get("VULCAN_RATE_LIMIT_CREATE_PCAP", "10/minute"),
            rate_limit_storage_uri=os.environ.get("VULCAN_RATE_LIMIT_STORAGE_URI", "memory://"),
        )
