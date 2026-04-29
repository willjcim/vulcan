"""pytest fixtures"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from flask.testing import FlaskClient

from vulcan.app import create_app
from vulcan.config import Settings


@pytest.fixture
def settings() -> Settings:
    return Settings(
        log_level="WARNING",
        json_logs=False,
        cors_origins=[],
        api_token=None,
        max_content_length_bytes=1 * 1024 * 1024,
        rate_limit_default="10000/minute",
        rate_limit_create_pcap="10000/minute",
        rate_limit_storage_uri="memory://",
    )


@pytest.fixture
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture
def client(app) -> FlaskClient:
    return app.test_client()


@pytest.fixture
def authed_app() -> Any:
    return create_app(
        Settings(
            log_level="WARNING",
            json_logs=False,
            cors_origins=[],
            api_token="test-token",
            max_content_length_bytes=1 * 1024 * 1024,
            rate_limit_default="10000/minute",
            rate_limit_create_pcap="10000/minute",
            rate_limit_storage_uri="memory://",
        )
    )


@pytest.fixture
def authed_client(authed_app) -> FlaskClient:
    return authed_app.test_client()


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).resolve().parents[1] / "examples"


@pytest.fixture
def tcp_example(examples_dir: Path) -> list[dict[str, Any]]:
    with (examples_dir / "tcp_handshake.json").open() as fh:
        return json.load(fh)


@pytest.fixture
def http_request_example(examples_dir: Path) -> list[dict[str, Any]]:
    with (examples_dir / "http_request.json").open() as fh:
        return json.load(fh)


@pytest.fixture
def raw_payload_example(examples_dir: Path) -> list[dict[str, Any]]:
    with (examples_dir / "raw_payload.json").open() as fh:
        return json.load(fh)
