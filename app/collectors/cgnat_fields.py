"""
IPFIX / NetFlow information elements used for CGNAT / NAT logging and PBA.

References:
  - IANA IPFIX (natEvent, postNAT*, portRange*)
  - Cisco ASR CGN Port Block Allocation (PBA) high-speed logging via IPFIX
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional

from app.collectors.common import (
    IE_FLOW_END_MS,
    IE_FLOW_END_SEC,
    IE_FLOW_START_MS,
    IE_FLOW_START_SEC,
    IE_IPV4_SRC_ADDR,
    IE_IPV6_SRC_ADDR,
    IE_PROTOCOL,
    ipv4_to_str,
    ipv6_to_str,
    normalize_ip,
    protocol_name,
    unix_ts,
)

# IANA IPFIX NAT / port-range IEs
IE_POST_NAT_SRC_IPV4 = 225
IE_POST_NAT_DST_IPV4 = 226
IE_POST_NAPT_SRC_PORT = 227
IE_POST_NAPT_DST_PORT = 228
IE_NAT_ORIGINATING_REALM = 229
IE_NAT_EVENT = 230
IE_INGRESS_VRF_ID = 234
IE_EGRESS_VRF_ID = 235
IE_POST_NAT_SRC_IPV6 = 281
IE_POST_NAT_DST_IPV6 = 282
IE_NAT_POOL_ID = 283
IE_PORT_RANGE_START = 361
IE_PORT_RANGE_END = 362
IE_PORT_RANGE_STEP = 363
IE_PORT_RANGE_NUM_PORTS = 364

# natEvent values commonly seen (RFC 8158 + vendor practice)
NAT_EVENT_MAP = {
    1: "create",
    2: "delete",
    3: "pool_exhausted",
    4: "quota_exceeded",
    5: "create",
    6: "delete",
    # Vendor / CGN PBA-oriented aliases treated in normalize_event_type
}


def is_cgnat_pba_record(values: Dict[int, Any]) -> bool:
    """
    True when the template row looks like NAT/PBA rather than a normal flow.
    """
    has_port_block = (
        IE_PORT_RANGE_START in values
        or IE_PORT_RANGE_END in values
        or IE_PORT_RANGE_NUM_PORTS in values
    )
    has_post_nat = (
        IE_POST_NAT_SRC_IPV4 in values
        or IE_POST_NAT_SRC_IPV6 in values
        or IE_POST_NAPT_SRC_PORT in values
    )
    has_nat_event = IE_NAT_EVENT in values
    return bool(has_port_block or (has_nat_event and has_post_nat) or (has_post_nat and has_port_block))


def normalize_event_type(nat_event: Optional[int], explicit: Optional[str] = None) -> str:
    if explicit:
        e = explicit.lower().strip()
        if e in ("allocate", "allocation", "pba_alloc", "port_block_alloc"):
            return "allocate"
        if e in ("deallocate", "deallocation", "pba_dealloc", "port_block_dealloc", "release"):
            return "deallocate"
        if e in ("create", "delete", "unknown"):
            return e
    if nat_event is None:
        return "allocate"
    mapped = NAT_EVENT_MAP.get(int(nat_event))
    if mapped == "create":
        return "allocate"
    if mapped == "delete":
        return "deallocate"
    return mapped or "unknown"


def _addr_from_values(values: Dict[int, Any], v4_ie: int, v6_ie: int) -> Optional[str]:
    if v6_ie in values and isinstance(values[v6_ie], (bytes, bytearray)) and len(values[v6_ie]) == 16:
        return ipv6_to_str(bytes(values[v6_ie]))
    if v4_ie in values and isinstance(values[v4_ie], int):
        return ipv4_to_str(values[v4_ie])
    return None


def values_to_cgnat_dict(
    values: Dict[int, Any],
    router_ip: str,
    unix_secs: int,
    is_ipfix: bool,
) -> Optional[Dict[str, Any]]:
    """Build a CGNAT PBA dict suitable for CGNATPortBlockCreate / service."""
    if not is_cgnat_pba_record(values):
        return None

    inside = _addr_from_values(values, IE_IPV4_SRC_ADDR, IE_IPV6_SRC_ADDR)
    outside = _addr_from_values(values, IE_POST_NAT_SRC_IPV4, IE_POST_NAT_SRC_IPV6)
    if not outside and IE_POST_NAT_DST_IPV4 in values:
        outside = _addr_from_values(values, IE_POST_NAT_DST_IPV4, IE_POST_NAT_DST_IPV6)
    if not inside or not outside:
        return None

    port_start = values.get(IE_PORT_RANGE_START)
    port_end = values.get(IE_PORT_RANGE_END)
    num_ports = values.get(IE_PORT_RANGE_NUM_PORTS)

    # Fallback: single post-NAPT source port as a 1-port "block"
    if port_start is None and IE_POST_NAPT_SRC_PORT in values:
        port_start = values.get(IE_POST_NAPT_SRC_PORT)
        port_end = port_start
        num_ports = 1

    if port_start is None:
        return None
    port_start = int(port_start)
    if port_end is not None:
        port_end = int(port_end)
    elif num_ports is not None:
        port_end = port_start + int(num_ports) - 1
    else:
        port_end = port_start
    if port_end < port_start:
        port_start, port_end = port_end, port_start

    block_size = int(num_ports) if num_ports is not None else (port_end - port_start + 1)

    nat_event = values.get(IE_NAT_EVENT)
    try:
        nat_event_i = int(nat_event) if nat_event is not None else None
    except (TypeError, ValueError):
        nat_event_i = None

    event_type = normalize_event_type(nat_event_i)

    event_time = datetime.utcnow()
    if IE_FLOW_START_MS in values:
        event_time = unix_ts(int(values[IE_FLOW_START_MS]) / 1000.0)
    elif IE_FLOW_START_SEC in values:
        event_time = unix_ts(int(values[IE_FLOW_START_SEC]))
    elif unix_secs:
        event_time = unix_ts(unix_secs)

    released_at = None
    if event_type == "deallocate":
        if IE_FLOW_END_MS in values:
            released_at = unix_ts(int(values[IE_FLOW_END_MS]) / 1000.0)
        elif IE_FLOW_END_SEC in values:
            released_at = unix_ts(int(values[IE_FLOW_END_SEC]))
        else:
            released_at = event_time

    proto_num = values.get(IE_PROTOCOL)
    try:
        proto_num = int(proto_num) if proto_num is not None else None
    except (TypeError, ValueError):
        proto_num = None

    vrf = values.get(IE_INGRESS_VRF_ID)
    if vrf is None:
        vrf = values.get(IE_EGRESS_VRF_ID)
    try:
        vrf = int(vrf) if vrf is not None else None
    except (TypeError, ValueError):
        vrf = None

    ip_version = 6 if ":" in inside or ":" in outside else 4

    return {
        "event_time": event_time,
        "event_type": event_type,
        "inside_ip": normalize_ip(inside),
        "outside_ip": normalize_ip(outside),
        "port_start": port_start,
        "port_end": port_end,
        "port_block_size": block_size,
        "protocol": protocol_name(proto_num) if proto_num is not None else "ANY",
        "protocol_number": proto_num,
        "ip_version": ip_version,
        "vrf_id": vrf,
        "nat_pool_name": None,
        "subscriber_id": None,
        "released_at": released_at,
        "is_active": event_type not in ("deallocate", "delete"),
        "router_ip": normalize_ip(router_ip, default=router_ip),
        "source": "ipfix" if is_ipfix else "netflow_v9",
        "raw_nat_event": nat_event_i,
        "additional_info": {
            "port_range_step": values.get(IE_PORT_RANGE_STEP),
            "nat_pool_id": values.get(IE_NAT_POOL_ID),
            "post_napt_src_port": values.get(IE_POST_NAPT_SRC_PORT),
        },
    }
