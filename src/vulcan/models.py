from __future__ import annotations

from typing import Any, Literal, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator

PortInput = Union[int, str]
EtherType = Literal["ipv4", "ipv6", "IPv4", "IPv6", "IPV4", "IPV6"]
HTTPMethod = Literal[
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "HEAD",
    "PATCH",
    "OPTIONS",
    "get",
    "post",
    "put",
    "delete",
    "head",
    "patch",
    "options",
]
HTTPVersion = Literal["1.0", "1.1", "2"]


class _StrictModel(BaseModel):
    """Ban unknown keys"""
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class SessionModel(_StrictModel):
    id: str | None = None


class AutofillModel(_StrictModel):
    enabled: bool = False


class EtherModel(_StrictModel):
    src: str = "00:1b:44:11:3a:b7"
    dst: str = "2c:54:91:88:c9:e3"
    type: EtherType = "ipv4"


class IPModel(_StrictModel):
    version: int | str = 4
    src: str = "$home_net"
    dst: str = "$home_net"
    ttl: int | str = 64

    @field_validator("version")
    @classmethod
    def _validate_version(cls, v: Any) -> int:
        try:
            i = int(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"IPv must be 4 or 6, got {v!r}") from exc
        if i not in (4, 6):
            raise ValueError(f"IPv must be 4 or 6, got {i}")
        return i

    @field_validator("ttl")
    @classmethod
    def _validate_ttl(cls, v: Any) -> int:
        try:
            i = int(v)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"TTL must be int, got {v!r}") from exc
        if not 0 <= i <= 255:
            raise ValueError(f"TTL must be in 0-255, got {i}")
        return i


class TCPModel(_StrictModel):
    sport: PortInput = "any"
    dport: PortInput = 80
    seq: int | str = 0
    ack: int | str = 0
    flags: str = "PA"
    window: int | str = 8192


class UDPModel(_StrictModel):
    sport: PortInput = "any"
    dport: PortInput = 53


class ICMPModel(_StrictModel):
    type: int | str = 8
    code: int | str = 0
    id: int | str = 1
    seq: int | str = 1


class DNSModel(_StrictModel):
    qname: str = "example.com"
    qtype: str = "A"
    rd: int | str = 1
    qr: int | str = 0
    answers: list[str] | str | None = None


class HTTPRequestModel(_StrictModel):
    headers: dict[str, str] | list[str] | str = Field(default_factory=dict)
    method: HTTPMethod = "GET"
    path: str = "/"
    version: HTTPVersion = "1.1"
    body: str | None = None
    tls_enabled: bool = False


class HTTPResponseModel(_StrictModel):
    headers: dict[str, str] | list[str] | str = Field(default_factory=dict)
    code: int | str = 200
    reason: str = "OK"
    version: HTTPVersion = "1.1"
    body: str | None = None
    tls_enabled: bool = False


class RawModel(_StrictModel):
    payload: str


class PacketModel(_StrictModel):
    """A single packet description"""

    session: SessionModel | None = None
    autofill: AutofillModel | None = None
    ether: EtherModel | None = None
    ip: IPModel | None = None
    tcp: TCPModel | None = None
    udp: UDPModel | None = None
    icmp: ICMPModel | None = None
    dns: DNSModel | None = None
    http_request: HTTPRequestModel | None = None
    http_response: HTTPResponseModel | None = None
    raw: RawModel | None = None

    def to_kwargs(self) -> dict[str, Any]:
        """Return the dict shape form VulcanPacket"""
        return self.model_dump(exclude_none=True, mode="python")


class PacketsRequest(RootModel[list[PacketModel]]):
    @field_validator("root")
    @classmethod
    def _non_empty(cls, v: list[PacketModel]) -> list[PacketModel]:
        if not v:
            raise ValueError("Request body must contain at least one packet")
        return v

    def to_kwargs_list(self) -> list[dict[str, Any]]:
        return [pkt.to_kwargs() for pkt in self.root]
