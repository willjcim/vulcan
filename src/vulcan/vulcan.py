from __future__ import annotations

import ipaddress
import random
import re
import secrets
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal

import magic
from scapy.all import (
    DNS,
    DNSQR,
    DNSRR,
    ICMP,
    IP,
    TCP,
    UDP,
    Ether,
    IPv6,
    Raw,
    conf,
    wrpcap,
)

from vulcan import constants
from vulcan.logger import get_logger
from vulcan.utils import check_port

logger = get_logger(__name__)


_VALID_TCP_FLAGS = set("FSRPAUECN")

# session manager

class VulcanSessionManager:
    """Aggregates a list of packet definitions into ordered Scapy packets"""

    def __init__(self, packets: Iterable[Mapping[str, Any]], file_name: str):
        self.vulcan_packets: list[VulcanPacket] = [VulcanPacket(pkt) for pkt in packets]
        self.sessions: list[Any] = []
        self.tcp_state: dict[Any, dict[str, Any]] = {}
        self.icmp_state: dict[Any, Any] = {}
        self.pcap_file = file_name
        self.previous_pkt: VulcanPacket | None = None

    def assemble(self) -> None:
        for pkt in self.vulcan_packets:
            if not pkt.session_id:
                pkt.session_id = f"auto-{secrets.token_hex(4)}"

            if pkt.transport_frame is None:
                self.sessions.append(pkt.vpkt)
                continue

            protocol = getattr(pkt.transport_frame, "protocol", None)

            if protocol == "tcp":
                if pkt.autofill:
                    self._process_tcp(pkt)
                else:
                    self.sessions.append(pkt.vpkt)
            elif protocol == "udp":
                self.sessions.append(pkt.vpkt)
            elif protocol == "icmp":
                if pkt.autofill:
                    self._process_icmp(pkt)
                else:
                    self.sessions.append(pkt.vpkt)
            else:
                self.sessions.append(pkt.vpkt)

        if self.tcp_state and self.previous_pkt is not None:
            self._close_tcp_session()

    def _process_icmp(self, pkt: VulcanPacket) -> None:
        """Construct icmp request/response pairs"""
        if pkt.session_id not in self.icmp_state:
            self._initialize_icmp_session(pkt)
            self.icmp_state[pkt.session_id] = True

    def _initialize_icmp_session(self, pkt: VulcanPacket) -> None:
        """Form the request/response pair from a single ICMP packet"""
        if not isinstance(pkt.ip_frame, Vulcan_IP):
            raise ValueError("ICMP autofill currently supports IPv4 only")

        smac, dmac, eth_type_int = (
            pkt.ether_frame.src,
            pkt.ether_frame.dst,
            pkt.ether_frame.type,
        )
        ip_ver, sip, dip, ip_ttl = (
            pkt.ip_frame.version,
            pkt.ip_frame.src,
            pkt.ip_frame.dst,
            pkt.ip_frame.ttl,
        )
        icmp_type = pkt.transport_frame.type
        icmp_code = pkt.transport_frame.code
        icmp_id = pkt.transport_frame.id
        icmp_seq = pkt.transport_frame.seq

        if eth_type_int == 0x0800:
            eth_type = "ipv4"
        elif eth_type_int == 0x86DD:
            eth_type = "ipv6"
        else:
            raise ValueError(f"ICMP autofill got unexpected ether type ({eth_type_int})")

        icmp_request_type = 8
        icmp_response_type = 0

        if icmp_type == icmp_request_type:
            req_ether, req_ip = (smac, dmac), (sip, dip)
            reply_ether, reply_ip = (dmac, smac), (dip, sip)
            req_type, reply_type = icmp_request_type, icmp_response_type
        elif icmp_type == icmp_response_type:
            req_ether, req_ip = (dmac, smac), (dip, sip)
            reply_ether, reply_ip = (smac, dmac), (sip, dip)
            req_type, reply_type = icmp_request_type, icmp_response_type
        else:
            logger.warning("ICMP type (%s) is not echo request/reply; passing through", icmp_type)
            self.sessions.append(pkt.vpkt)
            return

        request = (
            Vulcan_Ether(src=req_ether[0], dst=req_ether[1], type=eth_type)
            / Vulcan_IP(version=ip_ver, src=req_ip[0], dst=req_ip[1], ttl=ip_ttl)
            / Vulcan_ICMP(type=req_type, code=icmp_code, id=icmp_id, seq=icmp_seq)
        )
        reply = (
            Vulcan_Ether(src=reply_ether[0], dst=reply_ether[1], type=eth_type)
            / Vulcan_IP(version=ip_ver, src=reply_ip[0], dst=reply_ip[1], ttl=ip_ttl)
            / Vulcan_ICMP(type=reply_type, code=icmp_code, id=icmp_id, seq=icmp_seq)
        )

        self.sessions.append(request)
        self.sessions.append(reply)

    def _process_tcp(self, pkt: VulcanPacket) -> None:
        if not self.tcp_state or pkt.session_id not in self.tcp_state:
            if self.tcp_state and self.previous_pkt is not None:
                self._close_tcp_session()
            self._initialize_tcp_session(pkt)
        self._continue_tcp_session(pkt)

    def _initialize_tcp_session(self, pkt: VulcanPacket) -> None:
        """Inject a SYN / SYN-ACK / ACK handshake for a new stream"""
        sport = pkt.transport_frame.sport
        dport = pkt.transport_frame.dport

        syn = Vulcan_TCP(sport=sport, dport=dport, seq=0, ack=0, flags="S", window=65535)
        self.sessions.append(pkt.ether_frame / pkt.ip_frame / syn)

        synack = Vulcan_TCP(sport=dport, dport=sport, seq=0, ack=syn.seq + 1, flags="SA", window=65535)
        self.sessions.append(
            Vulcan_Ether(src=pkt.ether_frame.dst, dst=pkt.ether_frame.src)
            / Vulcan_IP(src=pkt.ip_frame.dst, dst=pkt.ip_frame.src)
            / synack
        )

        ack = Vulcan_TCP(sport=sport, dport=dport, seq=syn.seq + 1, ack=synack.seq + 1, flags="A")
        self.sessions.append(pkt.ether_frame / pkt.ip_frame / ack)

        self.tcp_state[pkt.session_id] = {
            "sport": sport,
            "dport": dport,
            "client": {"seq": ack.seq, "ack": ack.ack},
            "server": {"seq": ack.ack, "ack": ack.seq},
        }

    def _continue_tcp_session(self, pkt: VulcanPacket) -> None:
        stream = pkt.session_id
        direction = "client" if pkt.transport_frame.sport == self.tcp_state[stream]["sport"] else "server"
        opposite = "server" if direction == "client" else "client"

        pkt.vpkt[Vulcan_TCP].seq = self.tcp_state[stream][direction]["seq"]
        pkt.vpkt[Vulcan_TCP].ack = self.tcp_state[stream][opposite]["seq"]
        self.sessions.append(pkt.vpkt)

        payload_length = len(pkt.vpkt[Raw].load) if Raw in pkt.vpkt else 0
        self.tcp_state[stream][direction]["seq"] += payload_length
        self.tcp_state[stream][opposite]["ack"] += payload_length

        self._ack_packet(pkt)

    def _ack_packet(self, pkt: VulcanPacket) -> None:
        stream = pkt.session_id
        direction = "client" if pkt.transport_frame.sport == self.tcp_state[stream]["sport"] else "server"
        opposite = "server" if direction == "client" else "client"

        if direction == "client":
            sport = pkt.transport_frame.dport
            dport = pkt.transport_frame.sport
            ether_ip = Vulcan_Ether(src=pkt.ether_frame.dst, dst=pkt.ether_frame.src) / Vulcan_IP(
                src=pkt.ip_frame.dst, dst=pkt.ip_frame.src
            )
        else:
            sport = pkt.transport_frame.sport
            dport = pkt.transport_frame.dport
            ether_ip = pkt.ether_frame / pkt.ip_frame

        ack = Vulcan_TCP(
            sport=sport,
            dport=dport,
            seq=self.tcp_state[stream][opposite]["seq"],
            ack=self.tcp_state[stream][direction]["seq"],
            flags="A",
        )

        self.sessions.append(ether_ip / ack)
        self.tcp_state[stream][direction]["ack"] = ack.seq

        logger.debug(
            "[Stream %s] %s -> %s A seq=%s ack=%s len=%s",
            stream,
            ack.sport,
            ack.dport,
            ack.seq,
            ack.ack,
            len(ack.payload),
        )
        self.previous_pkt = pkt

    def _close_tcp_session(self) -> None:
        if self.previous_pkt is None:
            return

        stream = self.previous_pkt.session_id
        if stream not in self.tcp_state:
            return

        finack = Vulcan_TCP(
            sport=self.previous_pkt.transport_frame.sport,
            dport=self.previous_pkt.transport_frame.dport,
            seq=self.tcp_state[stream]["client"]["seq"],
            ack=self.tcp_state[stream]["server"]["seq"],
            flags="FA",
        )
        ack = Vulcan_TCP(
            sport=self.previous_pkt.transport_frame.dport,
            dport=self.previous_pkt.transport_frame.sport,
            seq=self.tcp_state[stream]["server"]["seq"] + 1,
            ack=self.tcp_state[stream]["client"]["seq"] + 1,
            flags="A",
        )

        self.sessions.append(self.previous_pkt.ether_frame / self.previous_pkt.ip_frame / finack)
        self.sessions.append(
            Vulcan_Ether(src=self.previous_pkt.ether_frame.dst, dst=self.previous_pkt.ether_frame.src)
            / Vulcan_IP(src=self.previous_pkt.ip_frame.dst, dst=self.previous_pkt.ip_frame.src)
            / ack
        )

        logger.debug(
            "[Stream %s] FIN/ACK %s -> %s seq=%s ack=%s",
            stream,
            finack.sport,
            finack.dport,
            finack.seq,
            finack.ack,
        )

    def write_cap(self) -> None:
        """Stamp packets with monotonic real-clock timestamps and write the pcap"""
        base = time.time()
        offset = 0.0
        for p in self.sessions:
            p.time = base + offset
            offset += random.uniform(0.001, 0.05)
        wrpcap(self.pcap_file, self.sessions)


# packet builder
class VulcanPacket:
    """Builds a single Scapy packet (``vpkt``) from a JSON-style dict"""

    def __init__(self, packet: Mapping[str, Any]):
        self.packet = packet
        self.ether_frame: Ether | None = None
        self.ip_frame: IP | IPv6 | None = None
        self.transport_frame: Any | None = None
        self.application_frame: Any | None = None
        self._payload: bytes | None = None

        session_id = packet.get("session", {}).get("id")
        # Treat empty strings (which the README's own examples use) as "no session".
        self.session_id: str | None = session_id if session_id else None
        self.autofill: bool = bool(packet.get("autofill", {}).get("enabled", False))

        self.build_frames()
        self.assemble()

    # Backwards-compatible alias for the original attribute name.
    @property
    def stream(self) -> str | None:
        return self.session_id

    @stream.setter
    def stream(self, value: str | None) -> None:
        self.session_id = value

    def build_frames(self) -> None:
        if self.packet.get("ether"):
            self.ether_frame = Vulcan_Ether(**self.packet["ether"])
        elif self.autofill:
            self.ether_frame = Vulcan_Ether()
        else:
            raise ValueError("Missing ETH frame")

        ip_data = self.packet.get("ip")
        if ip_data:
            ip_data = dict(ip_data)
            version = int(ip_data.get("version", 4))
            if version == 6:
                ip_data.pop("version", None)
                ttl = ip_data.pop("ttl", None)
                if ttl is not None and "hlim" not in ip_data:
                    ip_data["hlim"] = ttl
                self.ip_frame = Vulcan_IPv6(**ip_data)
            else:
                self.ip_frame = Vulcan_IP(**ip_data)
        elif self.autofill:
            self.ip_frame = Vulcan_IP()
        else:
            raise ValueError("Missing IP frame")

        if self.packet.get("tcp"):
            self.transport_frame = Vulcan_TCP(**self.packet["tcp"])
        elif self.packet.get("udp"):
            self.transport_frame = Vulcan_UDP(**self.packet["udp"])
        elif self.packet.get("icmp"):
            self.transport_frame = Vulcan_ICMP(**self.packet["icmp"])

        if self.packet.get("http_request"):
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_TCP()
            self.application_frame = VulcanHTTPRequest(**self.packet["http_request"]).build_request()
        elif self.packet.get("http_response"):
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_TCP()
            self.application_frame = VulcanHTTPResponse(**self.packet["http_response"]).build_response()
        elif self.packet.get("dns"):
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_UDP()
            self.application_frame = Vulcan_DNS(**self.packet["dns"])

        payload = self.packet.get("raw", {}).get("payload")
        if payload:
            if self.autofill and not self.transport_frame:
                self.transport_frame = Vulcan_TCP()
            self._payload = _decode_payload(payload)

    def assemble(self) -> None:
        if not self.ether_frame:
            raise ValueError("Cannot assemble packet without an Ethernet frame")
        self.vpkt = self.ether_frame
        if self.ip_frame:
            self.vpkt /= self.ip_frame
            if self.transport_frame:
                self.vpkt /= self.transport_frame
                if self.application_frame:
                    self.vpkt /= self.application_frame
        if self._payload:
            self.vpkt /= Raw(load=self._payload)


# frame helpers

_HEX_PATTERN = re.compile(r"^((\\x|0x)?[a-fA-F0-9]{2}\s?)+$")
_HEX_EXTRACT = re.compile(r"(?:\\x|0x)?([a-fA-F0-9]{2})[\s,]?")


def _decode_payload(payload: str) -> bytes:
    """Decode a user-supplied payload string into bytes"""
    if _HEX_PATTERN.match(payload):
        return bytes.fromhex("".join(_HEX_EXTRACT.findall(payload)))

    payload = payload.replace("\\r", "\r").replace("\\n", "\n")
    payload = re.sub(r"(?<!\r)\n", "\r\n", payload)
    return payload.encode()


class Vulcan_Ether(Ether):
    """Ethernet frame with MAC selection by vendor or random fallback"""

    def __init__(
        self,
        src: Any = "00:1b:44:11:3a:b7",
        dst: str = "2c:54:91:88:c9:e3",
        type: str = "ipv4",
        **kwargs: Any,
    ):
        if isinstance(src, (bytes, bytearray, memoryview)):
            super().__init__(bytes(src), **kwargs)
            return
        if "_pkt" in kwargs:
            super().__init__(**kwargs)
            return

        if not isinstance(src, str) or not isinstance(dst, str) or not isinstance(type, str):
            raise ValueError("Ethernet src/dst/type must be strings.")

        if src.lower() in constants.MAC_ADDRESS:
            src = self._generate_mac(constants.MAC_ADDRESS[src.lower()])
        if dst.lower() in constants.MAC_ADDRESS:
            dst = self._generate_mac(constants.MAC_ADDRESS[dst.lower()])

        for loc in (src, dst):
            if not self._valid_mac(loc):
                raise ValueError(f"Invalid MAC address format: {loc}")

        if type.lower() not in constants.ETHER_TYPES:
            raise ValueError(f"Unsupported ether type ({type}). Only valid options: IPv4, IPv6")

        super().__init__(src=src, dst=dst, type=constants.ETHER_TYPES[type.lower()], **kwargs)

    @staticmethod
    def _valid_mac(mac: str) -> bool:
        return bool(re.match(r"^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$", mac))

    @staticmethod
    def _generate_mac(prefix: str) -> str:
        return prefix + ":" + ":".join(f"{random.randint(0, 255):02x}" for _ in range(3))


conf.l2types.register(1, Vulcan_Ether)


def _random_ipv4(private: bool = False) -> str:
    if private:
        block_choice = random.choice(["10", "172", "192"])
        if block_choice == "10":
            return f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        if block_choice == "172":
            return f"172.{random.randint(16, 31)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
        return f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}"
    return ".".join(str(random.randint(1, 255)) for _ in range(4))


def _random_ipv6(private: bool = False) -> str:
    if private:
        # Unique-local fc00::/7
        prefix = 0xFC00 | random.randint(0, 0x01FF)
        groups = [prefix] + [random.randint(0, 0xFFFF) for _ in range(7)]
    else:
        # Global unicast 2000::/3
        prefix = 0x2000 | random.randint(0, 0x1FFF)
        groups = [prefix] + [random.randint(0, 0xFFFF) for _ in range(7)]
    return ":".join(f"{g:x}" for g in groups)


class Vulcan_IP(IP):
    """IPv4 frame with $variable substitution and CIDR sampling"""

    protocol = "ip"

    def __init__(
        self,
        version: Any = 4,
        src: str = "$home_net",
        dst: str = "$home_net",
        ttl: int | str = 64,
        **kwargs: Any,
    ):
        if isinstance(version, (bytes, bytearray, memoryview)):
            super().__init__(bytes(version), **kwargs)
            return
        if "_pkt" in kwargs:
            super().__init__(**kwargs)
            return

        try:
            version_int = int(version)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Unsupported IP version ({version}). Must be int.") from exc
        if version_int != 4:
            raise ValueError("Vulcan_IP only handles IPv4. Use Vulcan_IPv6 for version=6.")

        src = self._process_ipv4(src)
        dst = self._process_ipv4(dst)

        try:
            ttl_int = int(ttl)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid TTL value ({ttl}). Must be int.") from exc
        if not 0 <= ttl_int <= 255:
            raise ValueError(f"Invalid TTL value ({ttl}). Must be in 0-255.")

        super().__init__(src=src, dst=dst, ttl=ttl_int, **kwargs)

    @staticmethod
    def _process_ipv4(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"Invalid IPv4 input: {value!r}")
        lower = value.lower()
        if lower == "$home_net":
            return _random_ipv4(private=True)
        if lower in {"$external_net", "any"}:
            return _random_ipv4()

        if "/" in value:
            try:
                network = ipaddress.IPv4Network(value, strict=False)
            except (ipaddress.AddressValueError, ValueError) as exc:
                raise ValueError(f"Invalid IPv4 CIDR ({value}): {exc}") from exc
            num = network.num_addresses
            if num <= 2:
                return str(network.network_address)
            return str(network[random.randint(1, num - 2)])

        try:
            ipaddress.IPv4Address(value)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise ValueError(f"Invalid IPv4 ($HOME_NET, $EXTERNAL_NET, any, <IP>, <CIDR>): {value}") from exc
        return value


class Vulcan_IPv6(IPv6):
    """IPv6 frame with $variable substitution and prefix sampling"""

    protocol = "ipv6"

    def __init__(
        self,
        src: Any = "$home_net",
        dst: str = "$home_net",
        hlim: int | str = 64,
        **kwargs: Any,
    ):
        if isinstance(src, (bytes, bytearray, memoryview)):
            super().__init__(bytes(src), **kwargs)
            return
        if "_pkt" in kwargs:
            super().__init__(**kwargs)
            return

        src = self._process_ipv6(src)
        dst = self._process_ipv6(dst)

        try:
            hlim_int = int(hlim)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid IPv6 hlim ({hlim}), must be int") from exc
        if not 0 <= hlim_int <= 255:
            raise ValueError(f"Invalid IPv6 hlim ({hlim}), must be in 0-255")

        super().__init__(src=src, dst=dst, hlim=hlim_int, **kwargs)

    @staticmethod
    def _process_ipv6(value: str) -> str:
        if not isinstance(value, str):
            raise ValueError(f"Invalid IPv6 input: {value!r}")
        lower = value.lower()
        if lower == "$home_net":
            return _random_ipv6(private=True)
        if lower in {"$external_net", "any"}:
            return _random_ipv6()

        if "/" in value:
            try:
                network = ipaddress.IPv6Network(value, strict=False)
            except (ipaddress.AddressValueError, ValueError) as exc:
                raise ValueError(f"Invalid IPv6 CIDR ({value}): {exc}") from exc
            offset_max = max(1, min(network.num_addresses - 2, 1 << 32))
            return str(network.network_address + random.randint(1, offset_max))

        try:
            ipaddress.IPv6Address(value)
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise ValueError(f"Invalid IPv6 address: {value}") from exc
        return value


class Vulcan_TCP(TCP):
    protocol = "tcp"

    def __init__(
        self,
        sport: Any = "any",
        dport: int | str = 80,
        seq: int | str = 1,
        ack: int | str = 1,
        flags: str = "PA",
        window: int | str = 8192,
        **kwargs: Any,
    ):
        if isinstance(sport, (bytes, bytearray, memoryview)):
            super().__init__(bytes(sport), **kwargs)
            return
        if "_pkt" in kwargs:
            super().__init__(**kwargs)
            return

        sport = check_port(sport)
        dport = check_port(dport)

        if not self._check_flags(flags):
            raise ValueError(f"Invalid TCP flags ({flags}). Allowed letters: F, S, R, P, A, U, E, C, N")

        seq_int = _coerce_int(seq, "TCP seq")
        ack_int = _coerce_int(ack, "TCP ack")
        window_int = _coerce_int(window, "TCP window")

        super().__init__(
            sport=sport, dport=dport, seq=seq_int, ack=ack_int, flags=flags, window=window_int, **kwargs
        )

    @staticmethod
    def _check_flags(flags: str) -> bool:
        if not isinstance(flags, str) or not flags:
            return False
        upper = flags.upper()
        if any(ch not in _VALID_TCP_FLAGS for ch in upper):
            return False
        return len(set(upper)) == len(upper)


class Vulcan_UDP(UDP):
    protocol = "udp"

    def __init__(
        self,
        sport: Any = "any",
        dport: int | str = 53,
        **kwargs: Any,
    ):
        if isinstance(sport, (bytes, bytearray, memoryview)):
            super().__init__(bytes(sport), **kwargs)
            return
        if "_pkt" in kwargs:
            super().__init__(**kwargs)
            return

        sport = check_port(sport)
        dport = check_port(dport)
        super().__init__(sport=sport, dport=dport, **kwargs)


class Vulcan_ICMP(ICMP):
    protocol = "icmp"

    def __init__(
        self,
        type: Any = 8,
        code: int | str = 0,
        id: int | str = 1,
        seq: int | str = 1,
        **kwargs: Any,
    ):
        if isinstance(type, (bytes, bytearray, memoryview)):
            super().__init__(bytes(type), **kwargs)
            return
        if "_pkt" in kwargs:
            super().__init__(**kwargs)
            return

        type_int = _coerce_int(type, "ICMP type")
        code_int = _coerce_int(code, "ICMP code")
        id_int = _coerce_int(id, "ICMP id")
        seq_int = _coerce_int(seq, "ICMP seq")

        if not 0 <= type_int <= 255:
            raise ValueError(f"Invalid ICMP type ({type}), must be 0-255")
        if not 0 <= code_int <= 15:
            raise ValueError(f"Invalid ICMP code ({code}), must be 0-15")

        super().__init__(type=type_int, code=code_int, id=id_int, seq=seq_int, **kwargs)


class Vulcan_DNS(DNS):
    protocol = "dns"

    def __init__(
        self,
        qname: Any = "example.com",
        qtype: str = "A",
        rd: int | str = 1,
        qr: int | str = 0,
        answers: list[str] | str | None = None,
        **kwargs: Any,
    ):
        if isinstance(qname, (bytes, bytearray, memoryview)):
            super().__init__(bytes(qname), **kwargs)
            return
        if "_pkt" in kwargs:
            super().__init__(**kwargs)
            return

        rd_int = _coerce_int(rd, "DNS rd")
        qr_int = _coerce_int(qr, "DNS qr")

        if not qr_int:
            super().__init__(qr=qr_int, rd=rd_int, qd=DNSQR(qname=qname, qtype=qtype), **kwargs)
            return

        if not answers:
            raise ValueError("DNS answers empty for response (qr=1)")

        if isinstance(answers, str):
            answers_list = [a.strip() for a in answers.split(",") if a.strip()]
        elif isinstance(answers, list):
            answers_list = list(answers)
        else:
            raise ValueError("Invalid DNS answers value, must be list or comma-delimited string")

        answer_records = [DNSRR(rrname=qname, type=qtype, rdata=answer) for answer in answers_list]
        super().__init__(
            qr=1,
            rd=rd_int,
            qd=DNSQR(qname=qname, qtype=qtype),
            ancount=len(answer_records),
            an=answer_records,
            **kwargs,
        )


# HTTP frames

def _normalize_headers(value: Any) -> dict[str, str]:
    """Accept dict, list of strings, or pipe-separated string"""
    if value is None:
        return {}

    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}

    if isinstance(value, (list, tuple)):
        items = value
    elif isinstance(value, str):
        items = [s for s in value.split("|") if s.strip()]
    else:
        raise ValueError("Invalid HTTP header value, must be dict, list, or pipe-separated string")

    headers: dict[str, str] = {}
    for raw in items:
        if not isinstance(raw, str):
            raise ValueError(f"Invalid HTTP header entry: {raw!r}")
        key, sep, val = raw.partition(":")
        if not sep:
            raise ValueError(f"Invalid HTTP header (no ':' separator): {raw}")
        headers[key.strip()] = val.strip()
    return headers


def _has_header(headers: dict[str, str], name: str) -> bool:
    target = name.lower()
    return any(k.lower() == target for k in headers)


def _render_headers(headers: dict[str, str], http2: bool) -> str:
    if http2:
        return "\r\n".join(f"{k.lower()}: {v}" for k, v in headers.items())
    return "\r\n".join(f"{k}: {v}" for k, v in headers.items())


def _detect_mime(body: str | bytes | None) -> str:
    if body is None:
        return "application/octet-stream"
    buf = body.encode() if isinstance(body, str) else body
    return magic.Magic(mime=True).from_buffer(buf)


@dataclass
class VulcanHTTPRequest:
    headers: Any = field(default_factory=dict)
    method: Literal[
        "GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "get", "post", "put", "delete", "head", "patch"
    ] = "GET"
    path: str = "/"
    version: Literal["1.0", "1.1", "2"] = "1.1"
    body: str | None = None
    tls_enabled: bool = False
    protocol: str = "http"

    def build_request(self) -> Raw:
        headers = _normalize_headers(self.headers)
        method = self.method.upper()

        if self.body:
            if not _has_header(headers, "Content-Type"):
                headers["Content-Type"] = _detect_mime(self.body)
            if not _has_header(headers, "Content-Length"):
                headers["Content-Length"] = str(len(self.body.encode()))

        request = f"{method} {self.path} HTTP/{self.version}\r\n"
        rendered = _render_headers(headers, http2=self.version == "2")
        if rendered:
            request += rendered + "\r\n"
        request += "\r\n"
        if self.body:
            request += self.body
        return Raw(load=request.encode())


@dataclass
class VulcanHTTPResponse:
    headers: Any = field(default_factory=dict)
    code: int | str = 200
    reason: str = "OK"
    version: Literal["1.0", "1.1", "2"] = "1.1"
    body: str | None = None
    tls_enabled: bool = False
    protocol: str = "http"

    def build_response(self) -> Raw:
        headers = _normalize_headers(self.headers)

        if self.body:
            if not _has_header(headers, "Content-Type"):
                headers["Content-Type"] = _detect_mime(self.body)
            if not _has_header(headers, "Content-Length"):
                headers["Content-Length"] = str(len(self.body.encode()))
        elif not _has_header(headers, "Content-Length"):
            headers["Content-Length"] = "0"

        response = f"HTTP/{self.version} {self.code} {self.reason}\r\n"
        rendered = _render_headers(headers, http2=self.version == "2")
        if rendered:
            response += rendered + "\r\n"
        response += "\r\n"
        if self.body:
            response += self.body
        return Raw(load=response.encode())


def _coerce_int(value: Any, label: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {label} value ({value!r}), must be int") from exc
