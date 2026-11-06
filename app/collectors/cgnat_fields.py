"""
IPFIX / NetFlow v9 IEs for CGNAT / Cisco ASR Bulk Logging (PBA).

Cisco ASR 1000 with Port Block Allocation does NOT export per-session NetFlow
of NAT translations. Instead High-Speed Logging (HSL) sends NetFlow v9 records
only when a port *set* is allocated or freed:

  ip nat log translations flow-export v9 udp destination <ipdr> 2055

Documented HSL fields (IOS-XE Bulk Logging and Port Block Allocation):
  8   sourceIPv4Address          (inside / pre-NAT)
  225 postNATSourceIPv4Address   (outside / public)
  234 ingressVRFID
  4   protocolIdentifier
  230 natEvent                   (1=add/allocate, 2=delete/deallocate)
  323 observationTimeMilliseconds
  361 portRangeStart
  363 portRangeStepSize          (scattered port set)
  364 portRangeNumPorts
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
# Cisco ASR BPA HSL timestamp (observationTimeMilliseconds)
IE_OBSERVATION_TIME_MS = 323
IE_PORT_RANGE_START = 361
IE_PORT_RANGE_END = 362
IE_PORT_RANGE_STEP = 363
IE_PORT_RANGE_NUM_PORTS = 364

# natEvent: Cisco BPA uses 1=Add (allocate), 2=Delete (deallocate)
NAT_EVENT_MAP = {
    0: "unknown",
    1: "allocate",
    2: "deallocate",
    3: "pool_exhausted",
    4: "quota_exceeded",
    5: "allocate",
    6: "deallocate",
}


def port_in_pba_set(
    port: int,
    port_start: int,
    port_end: int,
    port_step: int = 1,
    port_block_size: Optional[int] = None,
) -> bool:
    """
    True if public_port belongs to a Cisco BPA port set.

    Scattered set: start, start+step, start+2*step, ... (count = block_size).
    Contiguous (step<=1): any port in [start, end].
    """
    port = int(port)
    start = int(port_start)
    end = int(port_end)
    step = max(int(port_step or 1), 1)
    if port < start or port > end:
        return False
    if step <= 1:
        return True
    if (port - start) % step != 0:
        return False
    idx = (port - start) // step
    if port_block_size is not None:
        return 0 <= idx < int(port_block_size)
    return True


def is_cgnat_pba_record(values: Dict[int, Any]) -> bool:
    """
    True when the template row looks like NAT/PBA HSL rather than a normal flow.

    Cisco BPA HSL: port-range start (361) + num ports (364) + postNAT / src.
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
    if has_port_block and (has_post_nat or IE_IPV4_SRC_ADDR in values or IE_IPV6_SRC_ADDR in values):
        return True
    # Classic per-translation HSL (overload) — rare with BPA enabled
    return bool(has_nat_event and has_post_nat)


def normalize_event_type(nat_event: Optional[int], explicit: Optional[str] = None) -> str:
    if explicit:
        e = explicit.lower().strip()
        if e in ("allocate", "allocation", "pba_alloc", "port_block_alloc", "add", "create"):
            return "allocate"
        if e in ("deallocate", "deallocation", "pba_dealloc", "port_block_dealloc", "release", "delete"):
            return "deallocate"
        if e in ("unknown",):
            return e
    if nat_event is None:
        return "allocate"
    mapped = NAT_EVENT_MAP.get(int(nat_event))
    if mapped in ("allocate", "deallocate"):
        return mapped
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
    """
    Build a CGNAT PBA dict from Cisco ASR HSL / IPFIX template values.

    Destination / inside_port / 5-tuple are intentionally ignored — BPA HSL
    does not log destinations (Cisco restriction).
    """
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
    try:
        step = int(values.get(IE_PORT_RANGE_STEP) or 1)
    except (TypeError, ValueError):
        step = 1
    if step < 1:
        step = 1

    # Fallback: single post-NAPT source port as a 1-port "block" (overload HSL)
    if port_start is None and IE_POST_NAPT_SRC_PORT in values:
        port_start = values.get(IE_POST_NAPT_SRC_PORT)
        port_end = port_start
        num_ports = 1
        step = 1

    if port_start is None:
        return None
    port_start = int(port_start)

    if num_ports is not None:
        num_ports = int(num_ports)
        # Cisco scattered: last port = start + (n-1)*step
        port_end = port_start + (num_ports - 1) * step
    elif port_end is not None:
        port_end = int(port_end)
        if step <= 1:
            num_ports = port_end - port_start + 1
        else:
            num_ports = ((port_end - port_start) // step) + 1
    else:
        port_end = port_start
        num_ports = 1

    if port_end < port_start:
        port_start, port_end = port_end, port_start

    block_size = int(num_ports)

    nat_event = values.get(IE_NAT_EVENT)
    try:
        nat_event_i = int(nat_event) if nat_event is not None else None
    except (TypeError, ValueError):
        nat_event_i = None

    event_type = normalize_event_type(nat_event_i)

    # Prefer Cisco observationTimeMilliseconds (323)
    event_time = None
    if IE_OBSERVATION_TIME_MS in values:
        try:
            event_time = unix_ts(int(values[IE_OBSERVATION_TIME_MS]) / 1000.0)
        except (TypeError, ValueError):
            event_time = None
    if event_time is None and IE_FLOW_START_MS in values:
        event_time = unix_ts(int(values[IE_FLOW_START_MS]) / 1000.0)
    elif event_time is None and IE_FLOW_START_SEC in values:
        event_time = unix_ts(int(values[IE_FLOW_START_SEC]))
    elif event_time is None and unix_secs:
        event_time = unix_ts(unix_secs)
    if event_time is None:
        event_time = datetime.now(tz=__import__("datetime").timezone.utc)

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

    has_range = (
        IE_PORT_RANGE_START in values
        or IE_PORT_RANGE_END in values
        or IE_PORT_RANGE_NUM_PORTS in values
    )
    mapping_mode = "pba" if has_range and block_size > 1 else "overload"

    return {
        "event_time": event_time,
        "event_type": event_type,
        "inside_ip": normalize_ip(inside),
        "outside_ip": normalize_ip(outside),
        "port_start": port_start,
        "port_end": port_end,
        "port_block_size": block_size,
        "port_step": step,
        "protocol": protocol_name(proto_num) if proto_num is not None else "ANY",
        "protocol_number": proto_num,
        "ip_version": ip_version,
        "vrf_id": vrf,
        "nat_pool_name": None,
        "subscriber_id": None,
        "released_at": released_at,
        "is_active": event_type not in ("deallocate", "delete"),
        "router_ip": normalize_ip(router_ip, default=router_ip),
        "source": "asr_hsl_v9" if not is_ipfix else "ipfix",
        "raw_nat_event": nat_event_i,
        "mapping_mode": mapping_mode,
        "additional_info": {
            "port_range_step": step,
            "nat_pool_id": values.get(IE_NAT_POOL_ID),
            "cisco_bpa": True,
            "note": "PBA HSL: allocate/deallocate port set only; no per-session NetFlow",
        },
    }
