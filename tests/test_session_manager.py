"""tests for vulcan.vulcan"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest
from scapy.all import ICMP, TCP, UDP, Ether, rdpcap

from vulcan.vulcan import VulcanPacket, VulcanSessionManager


def _write_pcap(packets) -> Path:
    tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
    tmp.close()
    path = Path(tmp.name)
    mgr = VulcanSessionManager(packets, str(path))
    mgr.assemble()
    mgr.write_cap()
    return path


class TestSessionParsing:
    def test_session_id_read_from_session_key(self):
        pkt = VulcanPacket(
            {
                "session": {"id": "abc"},
                "ether": {"type": "ipv4"},
                "ip": {"version": "4"},
                "tcp": {"sport": "12345", "dport": "80", "flags": "S"},
            }
        )
        assert pkt.session_id == "abc"
        assert pkt.stream == "abc"  # backwards-compat alias

    def test_empty_session_treated_as_none(self):
        pkt = VulcanPacket(
            {
                "session": {"id": ""},
                "ether": {"type": "ipv4"},
                "ip": {"version": "4"},
                "tcp": {"sport": "12345", "dport": "80", "flags": "S"},
            }
        )
        assert pkt.session_id is None

    def test_missing_ether_raises(self):
        with pytest.raises(ValueError, match="ETH frame"):
            VulcanPacket({"ip": {"version": "4"}})

    def test_autofill_supplies_defaults(self):
        pkt = VulcanPacket({"autofill": {"enabled": True}})
        assert pkt.ether_frame is not None
        assert pkt.ip_frame is not None


class TestTcpHandshakeExample:
    def test_writes_valid_pcap(self, tcp_example):
        path = _write_pcap(tcp_example)
        try:
            packets = rdpcap(str(path))
        finally:
            os.unlink(path)

        assert len(packets) == len(tcp_example)
        for pkt in packets:
            assert isinstance(pkt, Ether)
            assert pkt.payload.__class__.__name__ in {"IP", "Vulcan_IP"}
            assert pkt.haslayer(TCP)
        timestamps = [float(p.time) for p in packets]
        assert timestamps == sorted(timestamps)
        assert timestamps[0] > 1_000_000_000


class TestTcpAutofill:
    def test_handshake_and_close(self):
        packets = [
            {
                "session": {"id": "stream-1"},
                "autofill": {"enabled": True},
                "ether": {"type": "ipv4"},
                "ip": {"version": "4", "src": "10.0.0.1", "dst": "10.0.0.2"},
                "tcp": {"sport": "12345", "dport": "80", "flags": "PA"},
                "raw": {"payload": "GET / HTTP/1.1\r\n\r\n"},
            },
        ]
        path = _write_pcap(packets)
        try:
            scapy_packets = rdpcap(str(path))
        finally:
            os.unlink(path)

        flags = [int(p[TCP].flags) for p in scapy_packets if p.haslayer(TCP)]
        # we're expecting SYN(2) -> SYN/ACK(18) -> ACK(16) -> PSH/ACK(24) -> ACK(16) -> FIN/ACK(17) -> ACK(16) once stream is flushed
        assert flags[0] == 0x02
        assert flags[1] == 0x12
        assert flags[2] == 0x10
        assert 0x11 in flags  # FIN/ACK appears at end

    def test_two_streams_close_first_when_second_starts(self):
        packets = [
            {
                "session": {"id": "stream-1"},
                "autofill": {"enabled": True},
                "ether": {"type": "ipv4"},
                "ip": {"version": "4", "src": "10.0.0.1", "dst": "10.0.0.2"},
                "tcp": {"sport": "12345", "dport": "80", "flags": "PA"},
                "raw": {"payload": "first"},
            },
            {
                "session": {"id": "stream-2"},
                "autofill": {"enabled": True},
                "ether": {"type": "ipv4"},
                "ip": {"version": "4", "src": "10.0.0.3", "dst": "10.0.0.4"},
                "tcp": {"sport": "23456", "dport": "443", "flags": "PA"},
                "raw": {"payload": "second"},
            },
        ]
        path = _write_pcap(packets)
        try:
            scapy_packets = rdpcap(str(path))
        finally:
            os.unlink(path)

        # should see the FIN/ACK for stream-1 before the SYN of stream-2
        fin_indices = [
            i for i, p in enumerate(scapy_packets) if p.haslayer(TCP) and int(p[TCP].flags) == 0x11
        ]
        syn_indices = [
            i for i, p in enumerate(scapy_packets) if p.haslayer(TCP) and int(p[TCP].flags) == 0x02
        ]
        assert fin_indices, "expected at least one FIN/ACK"
        assert syn_indices[1] > fin_indices[0]


class TestIcmpAutofill:
    def test_request_produces_request_and_reply(self):
        packets = [
            {
                "session": {"id": "p1"},
                "autofill": {"enabled": True},
                "ether": {"type": "ipv4"},
                "ip": {"version": "4", "src": "10.0.0.1", "dst": "10.0.0.2"},
                "icmp": {"type": "8", "code": "0", "id": "1", "seq": "1"},
            }
        ]
        path = _write_pcap(packets)
        try:
            scapy_packets = rdpcap(str(path))
        finally:
            os.unlink(path)

        assert len(scapy_packets) == 2
        assert scapy_packets[0][ICMP].type == 8
        assert scapy_packets[1][ICMP].type == 0


class TestUdpDns:
    def test_dns_query(self):
        packets = [
            {
                "session": {"id": "1"},
                "ether": {"type": "ipv4"},
                "ip": {"version": "4", "src": "10.0.0.1", "dst": "8.8.8.8"},
                "udp": {"sport": "12345", "dport": "53"},
                "dns": {"qname": "example.com", "qtype": "A"},
            }
        ]
        path = _write_pcap(packets)
        try:
            scapy_packets = rdpcap(str(path))
        finally:
            os.unlink(path)

        assert scapy_packets[0].haslayer(UDP)
