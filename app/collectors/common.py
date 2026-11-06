"""Shared helpers for flow collectors"""
import ipaddress
import socket
import struct
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple, Union

from app.collectors.protocols import protocol_name
from app.schemas import IPDRRecordCreate

# Re-export for collectors
__all__ = [
    "protocol_name",
    "ipv4_to_str",
    "ipv6_to_str",
    "normalize_ip",
    "detect_ip_version",
    "unix_ts",
    "build_ipdr_record",
    "IE_IN_BYTES",
    "IE_IN_PKTS",
    "IE_PROTOCOL",
    "IE_L4_SRC_PORT",
    "IE_IPV4_SRC_ADDR",
    "IE_L4_DST_PORT",
    "IE_IPV4_DST_ADDR",
    "IE_SRC_AS",
    "IE_DST_AS",
    "IE_LAST_SWITCHED",
    "IE_FIRST_SWITCHED",
    "IE_IPV6_SRC_ADDR",
    "IE_IPV6_DST_ADDR",
    "IE_FLOW_LABEL",
    "IE_IP_PROTOCOL_VERSION",
    "IE_DIRECTION",
    "IE_OCTET_DELTA",
    "IE_PACKET_DELTA",
    "IE_FLOW_START_SEC",
    "IE_FLOW_END_SEC",
    "IE_FLOW_START_MS",
    "IE_FLOW_END_MS",
    "IE_FLOW_START_USEC",
    "IE_FLOW_END_USEC",
    "IE_POST_OCTETS",
    "IE_POST_PACKETS",
]


def ipv4_to_str(addr: int) -> str:
    return socket.inet_ntoa(struct.pack("!I", addr & 0xFFFFFFFF))


def ipv6_to_str(raw: bytes) -> str:
    if len(raw) != 16:
        raise ValueError("IPv6 address must be 16 bytes")
    return str(ipaddress.IPv6Address(raw))


def create_udp_socket(host: str, port: int) -> socket.socket:
    """
    Create a UDP socket. Binding to 0.0.0.0/:: uses dual-stack IPv4+IPv6
    when the platform supports IPV6_V6ONLY=0.
    """
    host = host or "0.0.0.0"
    if host in ("0.0.0.0", "::", "*"):
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        except OSError:
            pass
        sock.bind(("::", port))
        return sock

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        family, _, _, _, sockaddr = infos[0]
        sock = socket.socket(family, socket.SOCK_DGRAM)
        if family == socket.AF_INET6:
            try:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
            except OSError:
                pass
        sock.bind(sockaddr)
        return sock
    except OSError:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((host, port))
        return sock


def normalize_ip(value: Union[str, bytes, int, None], default: str = "0.0.0.0") -> str:
    """Normalize IPv4/IPv6 to compact canonical string."""
    if value is None or value == "":
        return default
    try:
        if isinstance(value, int):
            return ipv4_to_str(value)
        if isinstance(value, (bytes, bytearray)):
            raw = bytes(value)
            if len(raw) == 4:
                return socket.inet_ntoa(raw)
            if len(raw) == 16:
                return ipv6_to_str(raw)
            return default
        return str(ipaddress.ip_address(str(value).strip()))
    except (ValueError, OSError):
        return str(value).strip() or default


def peer_ip(addr: Tuple) -> str:
    """Extract peer IP from socket address (handles IPv4-mapped IPv6)."""
    host = addr[0] if addr else ""
    if isinstance(host, bytes):
        host = host.decode(errors="ignore")
    host = str(host)
    if host.startswith("::ffff:"):
        host = host[7:]
    return normalize_ip(host, default=host or "0.0.0.0")


def detect_ip_version(*ips: str) -> int:
    """Return 6 if any address is IPv6, else 4."""
    for ip in ips:
        try:
            if ipaddress.ip_address(ip).version == 6:
                return 6
        except ValueError:
            if ":" in str(ip):
                return 6
    return 4


def unix_ts(seconds: float) -> datetime:
    """Return timezone-aware UTC datetime (required for LEA time-bounded lookups)."""
    try:
        return datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return datetime.now(timezone.utc)


def build_ipdr_record(
    *,
    source_ip: str,
    source_port: int,
    destination_ip: str,
    destination_port: int,
    protocol: Union[str, int],
    total_bytes: int,
    total_packets: int,
    session_start_time: datetime,
    session_end_time: Optional[datetime] = None,
    duration_seconds: int = 0,
    router_ip: str = "",
    source: str = "netflow",
    protocol_number: Optional[int] = None,
    ip_version: Optional[int] = None,
    is_sampled: bool = False,
    sampling_rate: int = 1,
    sampled_bytes: int = 0,
    sampled_packets: int = 0,
    sample_pool: Optional[int] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> IPDRRecordCreate:
    src = normalize_ip(source_ip)
    dst = normalize_ip(destination_ip)
    rtr = normalize_ip(router_ip, default="") if router_ip else ""

    if isinstance(protocol, int):
        proto_num = protocol & 0xFF
        proto_name = protocol_name(proto_num)
    else:
        proto_name = str(protocol or "UNKNOWN")
        proto_num = protocol_number
        if proto_num is None:
            # reverse lookup by name
            from app.collectors.protocols import PROTOCOL_NAMES

            lower = proto_name.upper()
            proto_num = next((n for n, name in PROTOCOL_NAMES.items() if name.upper() == lower), None)
            if proto_num is None and lower.startswith("PROTO_"):
                try:
                    proto_num = int(lower.split("_", 1)[1])
                except ValueError:
                    proto_num = None

    ver = ip_version or detect_ip_version(src, dst)

    info: Dict[str, Any] = {
        "router_ip": rtr,
        "source": source,
        "ip_version": ver,
    }
    if proto_num is not None:
        info["protocol_number"] = int(proto_num)
    if extra:
        info.update(extra)

    rate = max(int(sampling_rate or 1), 1)
    return IPDRRecordCreate(
        source_ip=src,
        source_port=int(source_port or 0),
        destination_ip=dst,
        destination_port=int(destination_port or 0),
        protocol=proto_name,
        protocol_number=proto_num,
        ip_version=ver,
        bytes_uploaded=int(total_bytes or 0),
        bytes_downloaded=0,
        total_bytes=int(total_bytes or 0),
        packets_uploaded=int(total_packets or 0),
        packets_downloaded=0,
        total_packets=int(total_packets or 0),
        is_sampled=bool(is_sampled or rate > 1),
        sampling_rate=rate,
        sampled_bytes=int(sampled_bytes or 0),
        sampled_packets=int(sampled_packets or 0),
        sample_pool=int(sample_pool) if sample_pool is not None else None,
        session_start_time=session_start_time,
        session_end_time=session_end_time,
        duration_seconds=int(duration_seconds or 0),
        additional_info=info,
    )


# NetFlow v9 / IPFIX information element IDs
IE_IN_BYTES = 1
IE_IN_PKTS = 2
IE_PROTOCOL = 4
IE_L4_SRC_PORT = 7
IE_IPV4_SRC_ADDR = 8
IE_L4_DST_PORT = 11
IE_IPV4_DST_ADDR = 12
IE_SRC_AS = 16
IE_DST_AS = 17
IE_LAST_SWITCHED = 21
IE_FIRST_SWITCHED = 22
IE_POST_OCTETS = 23
IE_POST_PACKETS = 24
IE_IPV6_SRC_ADDR = 27
IE_IPV6_DST_ADDR = 28
IE_FLOW_LABEL = 31
IE_IP_PROTOCOL_VERSION = 60
IE_DIRECTION = 61
IE_IPV6_NEXT_HOP = 62
IE_BGP_IPV6_NEXT_HOP = 63
IE_OCTET_DELTA = 85
IE_PACKET_DELTA = 86
IE_FLOW_START_SEC = 150
IE_FLOW_END_SEC = 151
IE_FLOW_START_MS = 152
IE_FLOW_END_MS = 153
IE_FLOW_START_USEC = 154
IE_FLOW_END_USEC = 155
IE_SRC_MAC = 56
IE_DST_MAC = 57
