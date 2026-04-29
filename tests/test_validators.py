"""tests for vulcan.vulcan"""

from __future__ import annotations

import pytest

from vulcan.vulcan import (
    Vulcan_DNS,
    Vulcan_Ether,
    Vulcan_ICMP,
    Vulcan_IP,
    Vulcan_IPv6,
    Vulcan_TCP,
    Vulcan_UDP,
    VulcanHTTPRequest,
    VulcanHTTPResponse,
    _decode_payload,
    _normalize_headers,
)


class TestVulcanEther:
    def test_explicit_macs(self):
        ether = Vulcan_Ether(src="00:11:22:33:44:55", dst="aa:bb:cc:dd:ee:ff", type="ipv4")
        assert ether.src == "00:11:22:33:44:55"
        assert ether.dst == "aa:bb:cc:dd:ee:ff"
        assert ether.type == 0x0800

    def test_vendor_keyword(self):
        ether = Vulcan_Ether(src="vmware", dst="cisco", type="ipv6")
        assert ether.src.lower().startswith("00:05:69")
        assert ether.dst.lower().startswith("00:27:0d")
        assert ether.type == 0x86DD

    def test_invalid_mac(self):
        with pytest.raises(ValueError, match="Invalid MAC"):
            Vulcan_Ether(src="not-a-mac")

    def test_invalid_ether_type(self):
        with pytest.raises(ValueError, match="Unsupported ether type"):
            Vulcan_Ether(type="ipx")


class TestVulcanIP:
    def test_explicit_ipv4(self):
        ip = Vulcan_IP(src="10.0.0.1", dst="10.0.0.2", ttl=32)
        assert ip.src == "10.0.0.1"
        assert ip.dst == "10.0.0.2"
        assert ip.ttl == 32

    def test_home_net(self):
        ip = Vulcan_IP(src="$home_net", dst="$external_net")
        assert ip.src.split(".")[0] in {"10", "172", "192"}
        assert isinstance(ip.dst, str)

    def test_cidr(self):
        ip = Vulcan_IP(src="10.0.0.0/24", dst="10.0.0.0/24")
        assert ip.src.startswith("10.0.0.")
        assert ip.dst.startswith("10.0.0.")

    def test_invalid_octet_cidr(self):
        with pytest.raises(ValueError, match="CIDR"):
            Vulcan_IP(src="999.999.999.999/8")

    def test_invalid_ip(self):
        with pytest.raises(ValueError, match="Invalid IPv4"):
            Vulcan_IP(src="not-an-ip")

    def test_invalid_ttl(self):
        with pytest.raises(ValueError, match="TTL"):
            Vulcan_IP(ttl=999)

    def test_v6_rejected(self):
        with pytest.raises(ValueError, match="IPv6"):
            Vulcan_IP(version=6)


class TestVulcanIPv6:
    def test_explicit(self):
        ip = Vulcan_IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=32)
        assert ip.src == "2001:db8::1"
        assert ip.dst == "2001:db8::2"
        assert ip.hlim == 32

    def test_home_net(self):
        ip = Vulcan_IPv6(src="$home_net")
        # Unique-local fc00::/7
        first = int(ip.src.split(":")[0], 16)
        assert (first & 0xFE00) == 0xFC00

    def test_invalid(self):
        with pytest.raises(ValueError):
            Vulcan_IPv6(src="not-an-address")


class TestVulcanTCP:
    def test_defaults(self):
        tcp = Vulcan_TCP()
        assert tcp.dport == 80

    def test_string_inputs(self):
        tcp = Vulcan_TCP(sport="12345", dport="80", seq="0", ack="0", flags="S", window="65535")
        assert tcp.sport == 12345
        assert tcp.window == 65535
        assert int(tcp.flags) == 0x02

    def test_modern_flags(self):
        for combo in ["FA", "ECN", "AE"]:
            Vulcan_TCP(flags=combo)

    @pytest.mark.parametrize("flags", ["SS", "AAAA", "X", "", "Q"])
    def test_invalid_flags(self, flags):
        with pytest.raises(ValueError, match="flags"):
            Vulcan_TCP(flags=flags)

    def test_invalid_port(self):
        with pytest.raises(ValueError):
            Vulcan_TCP(sport="bad")


class TestVulcanUDP:
    def test_defaults(self):
        udp = Vulcan_UDP()
        assert udp.dport == 53


class TestVulcanICMP:
    def test_defaults(self):
        icmp = Vulcan_ICMP()
        assert icmp.type == 8

    def test_invalid_type(self):
        with pytest.raises(ValueError, match="ICMP type"):
            Vulcan_ICMP(type=999)

    def test_invalid_code(self):
        with pytest.raises(ValueError, match="ICMP code"):
            Vulcan_ICMP(code=99)


class TestVulcanDNS:
    def test_query(self):
        dns = Vulcan_DNS(qname="example.com", qtype="A", qr=0)
        assert dns.qr == 0

    def test_response_requires_answers(self):
        with pytest.raises(ValueError, match="answers empty"):
            Vulcan_DNS(qr=1)

    def test_response_string_answers(self):
        dns = Vulcan_DNS(qname="example.com", qtype="A", qr=1, answers="1.2.3.4,5.6.7.8")
        assert dns.qr == 1
        assert dns.ancount == 2

    def test_response_no_mutable_default(self):
        a = Vulcan_DNS(qname="a", qtype="A", qr=1, answers=["1.1.1.1"])
        b = Vulcan_DNS(qname="b", qtype="A", qr=1, answers=["2.2.2.2"])
        assert a.an[0].rdata != b.an[0].rdata


class TestPayloadDecoding:
    def test_hex(self):
        assert _decode_payload("0x41 0x42 43") == b"ABC"

    def test_hex_escaped(self):
        assert _decode_payload("\\x41\\x42") == b"AB"

    def test_text_normalises_lf(self):
        assert _decode_payload("GET /\n\n") == b"GET /\r\n\r\n"

    def test_text_preserves_crlf(self):
        assert _decode_payload("GET /\r\n\r\n") == b"GET /\r\n\r\n"


class TestNormalizeHeaders:
    def test_dict(self):
        assert _normalize_headers({"X-A": "1"}) == {"X-A": "1"}

    def test_pipe_string(self):
        assert _normalize_headers("X-A: 1|X-B: 2") == {"X-A": "1", "X-B": "2"}

    def test_value_with_colon(self):
        result = _normalize_headers("Location: https://example.com:8080/path")
        assert result == {"Location": "https://example.com:8080/path"}

    def test_list(self):
        assert _normalize_headers(["X-A: 1", "X-B: 2"]) == {"X-A": "1", "X-B": "2"}

    def test_invalid(self):
        with pytest.raises(ValueError):
            _normalize_headers(123)


class TestHTTPRequest:
    def test_basic(self):
        raw = VulcanHTTPRequest(headers={}, method="GET", path="/", version="1.1").build_request()
        rendered = raw.load.decode()
        assert rendered.startswith("GET / HTTP/1.1\r\n")
        assert rendered.endswith("\r\n\r\n")

    def test_body_sets_content_length_and_type(self):
        raw = VulcanHTTPRequest(headers={}, method="POST", path="/x", body="hello").build_request()
        rendered = raw.load.decode()
        assert "Content-Length: 5" in rendered
        assert "Content-Type:" in rendered
        assert rendered.endswith("hello")

    def test_http2_lowercases_headers(self):
        raw = VulcanHTTPRequest(
            headers={"X-Custom": "v"}, method="GET", path="/", version="2"
        ).build_request()
        assert b"x-custom: v" in raw.load


class TestHTTPResponse:
    def test_basic(self):
        raw = VulcanHTTPResponse(headers={}, code=200, reason="OK").build_response()
        rendered = raw.load.decode()
        assert rendered.startswith("HTTP/1.1 200 OK\r\n")
        assert "Content-Length: 0" in rendered

    def test_with_body(self):
        raw = VulcanHTTPResponse(headers={}, code=200, body="hello world").build_response()
        rendered = raw.load.decode()
        assert "Content-Length: 11" in rendered
        assert rendered.endswith("hello world")
