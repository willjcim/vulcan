"""tests for vulcan.models"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from vulcan.models import (
    EtherModel,
    HTTPRequestModel,
    IPModel,
    PacketModel,
    PacketsRequest,
    TCPModel,
)


class TestEtherModel:
    def test_defaults(self):
        ether = EtherModel()
        assert ether.type == "ipv4"

    def test_rejects_unknown_field(self):
        with pytest.raises(ValidationError):
            EtherModel.model_validate({"src": "00:11:22:33:44:55", "evil": "x"})


class TestIPModel:
    def test_defaults(self):
        ip = IPModel()
        assert ip.version == 4
        assert ip.ttl == 64

    @pytest.mark.parametrize("v", [3, 5, "abc"])
    def test_invalid_version(self, v):
        with pytest.raises(ValidationError):
            IPModel.model_validate({"version": v})

    def test_ttl_out_of_range(self):
        with pytest.raises(ValidationError):
            IPModel.model_validate({"ttl": 999})


class TestTCPModel:
    def test_string_inputs_round_trip(self):
        m = TCPModel.model_validate({"sport": "12345", "dport": "80", "flags": "S"})
        assert m.sport == "12345"
        assert m.dport == "80"
        assert m.flags == "S"

    def test_unknown_field(self):
        with pytest.raises(ValidationError):
            TCPModel.model_validate({"options": [("MSS", 1460)]})


class TestPacketModel:
    def test_minimal(self):
        m = PacketModel.model_validate({"ether": {"type": "ipv4"}})
        assert m.ether is not None

    def test_unknown_top_level_key(self):
        with pytest.raises(ValidationError):
            PacketModel.model_validate({"badkey": {}})

    def test_to_kwargs_strips_none(self):
        m = PacketModel.model_validate(
            {
                "session": {"id": "abc"},
                "ether": {"type": "ipv4"},
            }
        )
        kwargs = m.to_kwargs()
        assert "ip" not in kwargs
        assert kwargs["session"] == {"id": "abc"}


class TestPacketsRequest:
    def test_empty_list_rejected(self):
        with pytest.raises(ValidationError):
            PacketsRequest.model_validate([])

    def test_round_trip(self, tcp_example):
        req = PacketsRequest.model_validate(tcp_example)
        kwargs = req.to_kwargs_list()
        assert len(kwargs) == len(tcp_example)
        assert kwargs[0]["autofill"] == {"enabled": False}


class TestHTTPRequestModel:
    def test_dict_headers(self):
        m = HTTPRequestModel.model_validate({"headers": {"X-A": "1"}})
        assert m.headers == {"X-A": "1"}

    def test_string_headers(self):
        m = HTTPRequestModel.model_validate({"headers": "X-A: 1|X-B: 2"})
        assert m.headers == "X-A: 1|X-B: 2"

    def test_invalid_method(self):
        with pytest.raises(ValidationError):
            HTTPRequestModel.model_validate({"method": "TEAPOT"})


class TestEndpointReturnsValidationError:
    def test_unknown_field_returns_422(self, client):
        resp = client.post("/create-pcap", json=[{"evil": "x"}])
        assert resp.status_code == 422
        body = resp.get_json()
        assert body["error"]
        assert isinstance(body["details"], list)
        assert any("evil" in str(d["loc"]) for d in body["details"])
