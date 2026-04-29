"""tests for vulcan.app"""

from __future__ import annotations

import json

import pytest


class TestHealthAndUptime:
    def test_healthz(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "ok"

    def test_uptime(self, client):
        resp = client.get("/get-uptime")
        assert resp.status_code == 200
        assert "uptime" in resp.get_json()["success"]


class TestRequestId:
    def test_response_includes_request_id(self, client):
        resp = client.get("/healthz")
        assert "X-Request-ID" in resp.headers

    def test_request_id_propagates_when_supplied(self, client):
        resp = client.get("/healthz", headers={"X-Request-ID": "custom-rid"})
        assert resp.headers["X-Request-ID"] == "custom-rid"


class TestCreatePcap:
    def test_rejects_non_json(self, client):
        resp = client.post("/create-pcap", data="not json")
        assert resp.status_code == 400

    def test_rejects_non_list(self, client):
        resp = client.post("/create-pcap", json={"foo": "bar"})
        assert resp.status_code == 400

    def test_validation_error_returns_message(self, client):
        resp = client.post("/create-pcap", json=[{"ip": {"version": "4"}}])
        assert resp.status_code == 400
        assert "ETH" in resp.get_json()["error"]

    def test_returns_pcap_bytes(self, client, tcp_example):
        resp = client.post("/create-pcap", json=tcp_example)
        assert resp.status_code == 200
        assert resp.headers["Content-Type"] == "application/vnd.tcpdump.pcap"
        assert resp.data[:4] == b"\xd4\xc3\xb2\xa1"


class TestEditPcap:
    def test_returns_501_with_body(self, client):
        resp = client.post("/edit-pcap", json={})
        assert resp.status_code == 501
        assert resp.get_json()["error"]


class TestSizeLimit:
    def test_rejects_oversize_body(self, client, app):
        oversize = "X" * (app.config["MAX_CONTENT_LENGTH"] + 100)
        big_payload = json.dumps([{"raw": {"payload": oversize}}]).encode()
        resp = client.post(
            "/create-pcap",
            data=big_payload,
            headers={
                "Content-Type": "application/json",
                "Content-Length": str(len(big_payload)),
            },
        )
        assert resp.status_code == 413


class TestErrorPayloadDoesNotLeakInternals:
    def test_unhandled_exception_redacted(self, client, monkeypatch):
        from vulcan import vulcan as vulcan_module

        class Boom(Exception):
            pass

        def raiser(*_a, **_kw):
            raise Boom("internal stack trace details")

        monkeypatch.setattr(vulcan_module.VulcanSessionManager, "assemble", raiser)

        resp = client.post(
            "/create-pcap",
            json=[
                {
                    "ether": {"type": "ipv4"},
                    "ip": {"version": "4"},
                    "tcp": {"sport": "12345", "dport": "80", "flags": "S"},
                }
            ],
        )
        assert resp.status_code == 500
        body = resp.get_json()
        assert "internal stack trace details" not in body["error"]
        assert body["request_id"]


class TestAuth:
    def test_unauthenticated_rejected(self, authed_client):
        resp = authed_client.post("/create-pcap", json=[])
        assert resp.status_code == 401

    def test_x_api_token_accepted(self, authed_client, tcp_example):
        resp = authed_client.post(
            "/create-pcap",
            json=tcp_example,
            headers={"X-API-Token": "test-token"},
        )
        assert resp.status_code == 200

    def test_bearer_accepted(self, authed_client, tcp_example):
        resp = authed_client.post(
            "/create-pcap",
            json=tcp_example,
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 200

    def test_wrong_token_rejected(self, authed_client):
        resp = authed_client.post(
            "/create-pcap",
            json=[],
            headers={"X-API-Token": "wrong"},
        )
        assert resp.status_code == 401

    def test_healthz_does_not_require_auth(self, authed_client):
        resp = authed_client.get("/healthz")
        assert resp.status_code == 200


class TestRateLimit:
    @pytest.fixture
    def limited_app(self):
        from vulcan.app import create_app
        from vulcan.config import Settings

        return create_app(
            Settings(
                log_level="WARNING",
                json_logs=False,
                cors_origins=[],
                api_token=None,
                max_content_length_bytes=1024,
                rate_limit_default="2/minute",
                rate_limit_create_pcap="2/minute",
                rate_limit_storage_uri="memory://",
            )
        )

    def test_create_pcap_rate_limited(self, limited_app, tcp_example):
        client = limited_app.test_client()
        client.post("/create-pcap", json=tcp_example)
        client.post("/create-pcap", json=tcp_example)
        resp = client.post("/create-pcap", json=tcp_example)
        assert resp.status_code == 429
