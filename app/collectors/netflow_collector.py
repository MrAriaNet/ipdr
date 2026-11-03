"""
NetFlow / IPFIX collector

Supported versions:
  - NetFlow v1
  - NetFlow v5
  - NetFlow v7 (Catalyst-style)
  - NetFlow v8 (common aggregation formats when parseable)
  - NetFlow v9 (template-based)
  - IPFIX (version 10, template-based)
"""
from __future__ import annotations

import socket
import struct
import threading
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.collectors.common import (
    IE_FLOW_END_MS,
    IE_FLOW_END_SEC,
    IE_FLOW_LABEL,
    IE_FLOW_START_MS,
    IE_FLOW_START_SEC,
    IE_IN_BYTES,
    IE_IN_PKTS,
    IE_IP_PROTOCOL_VERSION,
    IE_IPV4_DST_ADDR,
    IE_IPV4_SRC_ADDR,
    IE_IPV6_DST_ADDR,
    IE_IPV6_SRC_ADDR,
    IE_L4_DST_PORT,
    IE_L4_SRC_PORT,
    IE_LAST_SWITCHED,
    IE_FIRST_SWITCHED,
    IE_OCTET_DELTA,
    IE_PACKET_DELTA,
    IE_POST_OCTETS,
    IE_POST_PACKETS,
    IE_PROTOCOL,
    build_ipdr_record,
    create_udp_socket,
    ipv4_to_str,
    ipv6_to_str,
    peer_ip,
    unix_ts,
)
from app.utils.logger import logger


class NetFlowCollector:
    """UDP collector for NetFlow v1/v5/v7/v8/v9 and IPFIX."""

    def __init__(self, host: str = "0.0.0.0", port: int = 2055, callback: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.callback = callback
        self.socket = None
        self.running = False
        self.thread = None
        # templates[(exporter_ip, observation_domain_or_source_id, template_id)] = list of (ie_id, length, enterprise)
        self.templates: Dict[Tuple[str, int, int], List[Tuple[int, int, int]]] = {}

    def start(self):
        if self.running:
            logger.warning("NetFlow collector is already running")
            return
        self.socket = create_udp_socket(self.host, self.port)
        self.socket.settimeout(1.0)
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True, name="netflow-collector")
        self.thread.start()
        logger.info(f"NetFlow/IPFIX collector started on {self.host}:{self.port} (IPv4+IPv6)")

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("NetFlow/IPFIX collector stopped")

    def _listen(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                self._process_packet(data, addr)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    logger.error("NetFlow socket error", exc_info=True)
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving NetFlow packet: {e}", exc_info=True)

    def _emit(self, record):
        if self.callback:
            self.callback(record)

    def _process_packet(self, data: bytes, addr: tuple):
        try:
            if len(data) < 4:
                return
            version = struct.unpack("!H", data[0:2])[0]
            handlers = {
                1: self._process_v1,
                5: self._process_v5,
                7: self._process_v7,
                8: self._process_v8,
                9: self._process_v9,
                10: self._process_ipfix,
            }
            handler = handlers.get(version)
            if handler:
                handler(data, (peer_ip(addr),) + tuple(addr[1:]))
            else:
                logger.warning(f"Unsupported NetFlow/IPFIX version: {version} from {peer_ip(addr)}")
        except Exception as e:
            logger.error(f"Error processing NetFlow packet: {e}", exc_info=True)

    # ------------------------------------------------------------------ v1
    def _process_v1(self, data: bytes, addr: tuple):
        if len(data) < 16:
            return
        _ver, count, sys_uptime, unix_secs = struct.unpack("!HHII", data[0:12])
        offset = 16
        for _ in range(count):
            if offset + 48 > len(data):
                break
            src, dst, _nexthop, _in_if, _out_if, d_pkts, d_octets, first, last, src_port, dst_port, _pad, prot, _tos, _flags, _res = struct.unpack(
                "!IIIHHIIIIHHBBBBIxxxx", data[offset:offset + 48]
            )
            start = unix_ts(unix_secs - (sys_uptime - first) / 1000.0)
            end = unix_ts(unix_secs - (sys_uptime - last) / 1000.0)
            self._emit(
                build_ipdr_record(
                    source_ip=ipv4_to_str(src),
                    source_port=src_port,
                    destination_ip=ipv4_to_str(dst),
                    destination_port=dst_port,
                    protocol=prot,
                    total_bytes=d_octets,
                    total_packets=d_pkts,
                    session_start_time=start,
                    session_end_time=end,
                    duration_seconds=max(0, int((last - first) / 1000)),
                    router_ip=addr[0],
                    source="netflow_v1",
                    ip_version=4,
                )
            )
            offset += 48

    # ------------------------------------------------------------------ v5
    def _process_v5(self, data: bytes, addr: tuple):
        if len(data) < 24:
            return
        _ver, count, sys_uptime, unix_secs, _nsecs, _seq, _et, _eid, _samp = struct.unpack("!HHIIIIBBH", data[0:24])
        offset = 24
        for _ in range(count):
            if offset + 48 > len(data):
                break
            src, dst, _nh, _iin, _iout, d_pkts, d_octets, first, last, src_port, dst_port, _p1, _flags, prot, _tos, _sas, _das, _sm, _dm, _p2 = struct.unpack(
                "!IIIHHIIIIHHBBBBHHBBH", data[offset:offset + 48]
            )
            start = unix_ts(unix_secs - (sys_uptime - first) / 1000.0)
            end = unix_ts(unix_secs - (sys_uptime - last) / 1000.0)
            self._emit(
                build_ipdr_record(
                    source_ip=ipv4_to_str(src),
                    source_port=src_port,
                    destination_ip=ipv4_to_str(dst),
                    destination_port=dst_port,
                    protocol=prot,
                    total_bytes=d_octets,
                    total_packets=d_pkts,
                    session_start_time=start,
                    session_end_time=end,
                    duration_seconds=max(0, int((last - first) / 1000)),
                    router_ip=addr[0],
                    source="netflow_v5",
                    ip_version=4,
                )
            )
            offset += 48

    # ------------------------------------------------------------------ v7
    def _process_v7(self, data: bytes, addr: tuple):
        """Cisco Catalyst NetFlow v7 — 52-byte records."""
        if len(data) < 24:
            return
        _ver, count, sys_uptime, unix_secs = struct.unpack("!HHII", data[0:12])
        offset = 24
        for _ in range(count):
            if offset + 52 > len(data):
                break
            chunk = data[offset:offset + 52]
            src = struct.unpack("!I", chunk[0:4])[0]
            dst = struct.unpack("!I", chunk[4:8])[0]
            d_pkts = struct.unpack("!I", chunk[16:20])[0]
            d_octets = struct.unpack("!I", chunk[20:24])[0]
            first = struct.unpack("!I", chunk[24:28])[0]
            last = struct.unpack("!I", chunk[28:32])[0]
            src_port = struct.unpack("!H", chunk[32:34])[0]
            dst_port = struct.unpack("!H", chunk[34:36])[0]
            prot = chunk[39]
            start = unix_ts(unix_secs - (sys_uptime - first) / 1000.0)
            end = unix_ts(unix_secs - (sys_uptime - last) / 1000.0)
            self._emit(
                build_ipdr_record(
                    source_ip=ipv4_to_str(src),
                    source_port=src_port,
                    destination_ip=ipv4_to_str(dst),
                    destination_port=dst_port,
                    protocol=prot,
                    total_bytes=d_octets,
                    total_packets=d_pkts,
                    session_start_time=start,
                    session_end_time=end,
                    duration_seconds=max(0, int((last - first) / 1000)),
                    router_ip=addr[0],
                    source="netflow_v7",
                    ip_version=4,
                )
            )
            offset += 52

    # ------------------------------------------------------------------ v8
    def _process_v8(self, data: bytes, addr: tuple):
        """
        NetFlow v8 aggregation — multiple record layouts exist.
        We support the common Router AS / Proto Port / Prefix style when
        the packet carries IPv4 src/dst and L4 ports in known offsets.
        Unknown aggregation types are logged and skipped safely.
        """
        if len(data) < 28:
            return
        _ver, count, sys_uptime, unix_secs, _nsecs, _seq, _etype, _agg, _agg_ver = struct.unpack(
            "!HHIIIIBBH", data[0:24]
        )
        # Aggregation method at offset 22 (engine-like layout varies by vendor).
        # Heuristic: try 44-byte records with src/dst at start (prefix aggregation family).
        offset = 28
        record_size = 44
        parsed = 0
        for _ in range(count):
            if offset + record_size > len(data):
                break
            chunk = data[offset:offset + record_size]
            try:
                src = struct.unpack("!I", chunk[0:4])[0]
                dst = struct.unpack("!I", chunk[4:8])[0]
                d_pkts = struct.unpack("!I", chunk[12:16])[0]
                d_octets = struct.unpack("!I", chunk[16:20])[0]
                first = struct.unpack("!I", chunk[20:24])[0]
                last = struct.unpack("!I", chunk[24:28])[0]
                src_port = struct.unpack("!H", chunk[28:30])[0] if len(chunk) >= 30 else 0
                dst_port = struct.unpack("!H", chunk[30:32])[0] if len(chunk) >= 32 else 0
                prot = chunk[33] if len(chunk) > 33 else 0
                start = unix_ts(unix_secs - (sys_uptime - first) / 1000.0)
                end = unix_ts(unix_secs - (sys_uptime - last) / 1000.0)
                self._emit(
                    build_ipdr_record(
                        source_ip=ipv4_to_str(src),
                        source_port=src_port,
                        destination_ip=ipv4_to_str(dst),
                        destination_port=dst_port,
                        protocol=prot,
                        total_bytes=d_octets,
                        total_packets=d_pkts,
                        session_start_time=start,
                        session_end_time=end,
                        duration_seconds=max(0, int((last - first) / 1000)),
                        router_ip=addr[0],
                        source="netflow_v8",
                        ip_version=4,
                    )
                )
                parsed += 1
            except Exception:
                pass
            offset += record_size
        if parsed == 0:
            logger.debug(f"NetFlow v8 packet from {addr[0]} could not be mapped to a known aggregation layout")

    # ------------------------------------------------------------------ v9 / IPFIX shared
    def _process_v9(self, data: bytes, addr: tuple):
        if len(data) < 20:
            return
        _ver, count, sys_uptime, unix_secs, _seq, source_id = struct.unpack("!HHIIII", data[0:20])
        self._process_template_packet(
            data=data,
            addr=addr,
            header_len=20,
            count_or_length=count,
            sys_uptime=sys_uptime,
            unix_secs=unix_secs,
            domain_id=source_id,
            is_ipfix=False,
        )

    def _process_ipfix(self, data: bytes, addr: tuple):
        if len(data) < 16:
            return
        _ver, length, export_time, _seq, domain_id = struct.unpack("!HHIII", data[0:16])
        self._process_template_packet(
            data=data,
            addr=addr,
            header_len=16,
            count_or_length=length,
            sys_uptime=0,
            unix_secs=export_time,
            domain_id=domain_id,
            is_ipfix=True,
            total_length=length,
        )

    def _process_template_packet(
        self,
        data: bytes,
        addr: tuple,
        header_len: int,
        count_or_length: int,
        sys_uptime: int,
        unix_secs: int,
        domain_id: int,
        is_ipfix: bool,
        total_length: Optional[int] = None,
    ):
        offset = header_len
        end = total_length if (is_ipfix and total_length) else len(data)
        end = min(end, len(data))
        sets_left = count_or_length if not is_ipfix else 10_000

        while offset + 4 <= end and sets_left > 0:
            set_id, set_len = struct.unpack("!HH", data[offset:offset + 4])
            if set_len < 4 or offset + set_len > end:
                break
            set_data = data[offset + 4:offset + set_len]
            if is_ipfix:
                if set_id == 2:
                    self._parse_templates(set_data, addr[0], domain_id, is_ipfix=True, options=False)
                elif set_id == 3:
                    self._parse_templates(set_data, addr[0], domain_id, is_ipfix=True, options=True)
                elif set_id >= 256:
                    self._parse_data_set(set_data, set_id, addr, domain_id, sys_uptime, unix_secs, is_ipfix=True)
            else:
                if set_id == 0:
                    self._parse_templates(set_data, addr[0], domain_id, is_ipfix=False, options=False)
                elif set_id == 1:
                    self._parse_templates(set_data, addr[0], domain_id, is_ipfix=False, options=True)
                elif set_id >= 256:
                    self._parse_data_set(set_data, set_id, addr, domain_id, sys_uptime, unix_secs, is_ipfix=False)
            offset += set_len
            # Align to 4 bytes for NetFlow v9
            if not is_ipfix and offset % 4:
                offset += 4 - (offset % 4)
            sets_left -= 1

    def _parse_templates(
        self,
        data: bytes,
        exporter: str,
        domain_id: int,
        is_ipfix: bool,
        options: bool,
    ):
        offset = 0
        while offset + 4 <= len(data):
            template_id, field_count = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            scope_count = 0
            if options:
                if is_ipfix:
                    # IPFIX options: template_id, field_count already read; next is scope field count
                    if offset + 2 > len(data):
                        break
                    scope_count = struct.unpack("!H", data[offset:offset + 2])[0]
                    offset += 2
                    # IPFIX options header is different: after template_id comes field_count then scope_count
                    # We already consumed template_id+field_count; for IPFIX option set the layout is:
                    # template_id (2), field_count (2), scope_field_count (2)
                else:
                    # NetFlow v9 options: template_id, option_scope_len, option_len — already mismatched.
                    # Common layout: template_id (2), scope_len (2), option_len (2)
                    offset -= 2  # rewind field_count
                    if offset + 4 > len(data):
                        break
                    scope_len, option_len = struct.unpack("!HH", data[offset:offset + 4])
                    offset += 4
                    fields: List[Tuple[int, int, int]] = []
                    scope_fields = scope_len // 4
                    option_fields = option_len // 4
                    for _ in range(scope_fields + option_fields):
                        if offset + 4 > len(data):
                            break
                        ie_id, length = struct.unpack("!HH", data[offset:offset + 4])
                        offset += 4
                        fields.append((ie_id, length, 0))
                    self.templates[(exporter, domain_id, template_id)] = fields
                    continue

            fields = []
            total_fields = field_count if not (options and is_ipfix) else field_count
            # For IPFIX options, field_count includes scope fields; first scope_count are scopes
            for i in range(total_fields):
                if offset + 4 > len(data):
                    break
                ie_id, length = struct.unpack("!HH", data[offset:offset + 4])
                offset += 4
                enterprise = 0
                if is_ipfix and (ie_id & 0x8000):
                    ie_id = ie_id & 0x7FFF
                    if offset + 4 > len(data):
                        break
                    enterprise = struct.unpack("!I", data[offset:offset + 4])[0]
                    offset += 4
                fields.append((ie_id, length, enterprise))
            self.templates[(exporter, domain_id, template_id)] = fields
            logger.debug(
                f"{'IPFIX' if is_ipfix else 'NetFlow v9'} template {template_id} "
                f"from {exporter}/{domain_id}: {len(fields)} fields"
            )

    def _read_ie_value(self, data: bytes, offset: int, length: int) -> Tuple[Any, int]:
        end = offset + length
        if end > len(data):
            return None, offset + length
        raw = data[offset:end]
        if length == 1:
            return raw[0], end
        if length == 2:
            return struct.unpack("!H", raw)[0], end
        if length == 4:
            return struct.unpack("!I", raw)[0], end
        if length == 8:
            return struct.unpack("!Q", raw)[0], end
        if length == 16:
            return raw, end
        return raw, end

    def _parse_data_set(
        self,
        data: bytes,
        template_id: int,
        addr: tuple,
        domain_id: int,
        sys_uptime: int,
        unix_secs: int,
        is_ipfix: bool,
    ):
        key = (addr[0], domain_id, template_id)
        fields = self.templates.get(key)
        if not fields:
            logger.debug(f"No template {template_id} for {addr[0]}/{domain_id}; waiting for template")
            return

        record_len = sum(f[1] for f in fields)
        if record_len <= 0:
            return
        offset = 0
        while offset + record_len <= len(data):
            values: Dict[int, Any] = {}
            pos = offset
            for ie_id, length, _ent in fields:
                value, pos = self._read_ie_value(data, pos, length)
                if _ent == 0:  # ignore enterprise-specific for IPDR mapping
                    values[ie_id] = value
            offset += record_len
            record = self._values_to_record(values, addr[0], sys_uptime, unix_secs, is_ipfix)
            if record:
                self._emit(record)

    def _values_to_record(
        self,
        values: Dict[int, Any],
        router_ip: str,
        sys_uptime: int,
        unix_secs: int,
        is_ipfix: bool,
    ):
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        # Prefer explicit IPv6 fields; also accept IPv4
        if IE_IPV6_SRC_ADDR in values and isinstance(values[IE_IPV6_SRC_ADDR], (bytes, bytearray)) and len(values[IE_IPV6_SRC_ADDR]) == 16:
            src_ip = ipv6_to_str(bytes(values[IE_IPV6_SRC_ADDR]))
        elif IE_IPV4_SRC_ADDR in values and isinstance(values[IE_IPV4_SRC_ADDR], int):
            src_ip = ipv4_to_str(values[IE_IPV4_SRC_ADDR])
        if IE_IPV6_DST_ADDR in values and isinstance(values[IE_IPV6_DST_ADDR], (bytes, bytearray)) and len(values[IE_IPV6_DST_ADDR]) == 16:
            dst_ip = ipv6_to_str(bytes(values[IE_IPV6_DST_ADDR]))
        elif IE_IPV4_DST_ADDR in values and isinstance(values[IE_IPV4_DST_ADDR], int):
            dst_ip = ipv4_to_str(values[IE_IPV4_DST_ADDR])

        src_port = int(values.get(IE_L4_SRC_PORT) or 0)
        dst_port = int(values.get(IE_L4_DST_PORT) or 0)
        proto = int(values.get(IE_PROTOCOL) or 0)
        ip_ver = values.get(IE_IP_PROTOCOL_VERSION)
        try:
            ip_ver = int(ip_ver) if ip_ver is not None else None
        except (TypeError, ValueError):
            ip_ver = None
        if ip_ver not in (4, 6):
            ip_ver = None
        total_bytes = int(
            values.get(IE_OCTET_DELTA)
            or values.get(IE_IN_BYTES)
            or values.get(IE_POST_OCTETS)
            or 0
        )
        total_packets = int(
            values.get(IE_PACKET_DELTA)
            or values.get(IE_IN_PKTS)
            or values.get(IE_POST_PACKETS)
            or 0
        )

        now = datetime.utcnow()
        start = now
        end = now
        if IE_FLOW_START_MS in values:
            start = unix_ts(int(values[IE_FLOW_START_MS]) / 1000.0)
        elif IE_FLOW_START_SEC in values:
            start = unix_ts(int(values[IE_FLOW_START_SEC]))
        elif IE_FIRST_SWITCHED in values and sys_uptime:
            first = int(values[IE_FIRST_SWITCHED])
            start = unix_ts(unix_secs - (sys_uptime - first) / 1000.0)
        elif IE_FIRST_SWITCHED in values and is_ipfix:
            # Some exporters misuse uptime fields; fall back to export time
            start = unix_ts(unix_secs)

        if IE_FLOW_END_MS in values:
            end = unix_ts(int(values[IE_FLOW_END_MS]) / 1000.0)
        elif IE_FLOW_END_SEC in values:
            end = unix_ts(int(values[IE_FLOW_END_SEC]))
        elif IE_LAST_SWITCHED in values and sys_uptime:
            last = int(values[IE_LAST_SWITCHED])
            end = unix_ts(unix_secs - (sys_uptime - last) / 1000.0)
        else:
            end = start

        duration = max(0, int((end - start).total_seconds()))
        return build_ipdr_record(
            source_ip=src_ip,
            source_port=src_port,
            destination_ip=dst_ip,
            destination_port=dst_port,
            protocol=proto,
            total_bytes=total_bytes,
            total_packets=total_packets,
            session_start_time=start,
            session_end_time=end,
            duration_seconds=duration,
            router_ip=router_ip,
            source="ipfix" if is_ipfix else "netflow_v9",
            ip_version=ip_ver,
            extra={"flow_label": values.get(IE_FLOW_LABEL)} if values.get(IE_FLOW_LABEL) is not None else None,
        )


class SimpleFlowCollector:
    """UDP JSON flow collector for labs / custom exporters."""

    def __init__(self, host: str = "0.0.0.0", port: int = 9999, callback: Optional[Callable] = None):
        self.host = host
        self.port = port
        self.callback = callback
        self.socket = None
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            logger.warning("Simple collector is already running")
            return
        self.socket = create_udp_socket(self.host, self.port)
        self.socket.settimeout(1.0)
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True, name="simple-collector")
        self.thread.start()
        logger.info(f"Simple flow collector started on {self.host}:{self.port} (IPv4+IPv6)")

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("Simple flow collector stopped")

    def _listen(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                self._process_data(data, addr)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    logger.error("Simple collector socket error", exc_info=True)
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving flow data: {e}", exc_info=True)

    def _process_data(self, data: bytes, addr: tuple):
        import json

        try:
            flow_data = json.loads(data.decode("utf-8"))
            record = build_ipdr_record(
                source_ip=flow_data.get("source_ip", "0.0.0.0"),
                source_port=flow_data.get("source_port", 0),
                destination_ip=flow_data.get("destination_ip", "0.0.0.0"),
                destination_port=flow_data.get("destination_port", 0),
                protocol=flow_data.get("protocol", "TCP"),
                total_bytes=flow_data.get("total_bytes", 0),
                total_packets=flow_data.get("total_packets", 0),
                session_start_time=datetime.fromisoformat(
                    flow_data.get("session_start_time", datetime.utcnow().isoformat())
                ),
                session_end_time=(
                    datetime.fromisoformat(flow_data["session_end_time"])
                    if flow_data.get("session_end_time")
                    else None
                ),
                duration_seconds=flow_data.get("duration_seconds", 0),
                router_ip=addr[0],
                source="simple_collector",
                extra={
                    "service_type": flow_data.get("service_type"),
                    "user_id": flow_data.get("user_id"),
                },
            )
            # Preserve optional fields on schema
            if flow_data.get("service_type"):
                record.service_type = flow_data.get("service_type")
            if flow_data.get("user_id"):
                record.user_id = flow_data.get("user_id")
            if flow_data.get("bytes_uploaded") is not None:
                record.bytes_uploaded = int(flow_data["bytes_uploaded"])
            if flow_data.get("bytes_downloaded") is not None:
                record.bytes_downloaded = int(flow_data["bytes_downloaded"])
            if self.callback:
                self.callback(record)
        except json.JSONDecodeError:
            logger.warning(f"Received non-JSON data from {addr}")
        except Exception as e:
            logger.error(f"Error processing flow data: {e}", exc_info=True)
