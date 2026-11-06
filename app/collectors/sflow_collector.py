"""
sFlow collector (v2 / v4 / v5 datagrams)

sFlow is *sampled* telemetry — it does NOT capture 100% of packets.
When extrapolate=True (default), observed sample sizes are multiplied by
sampling_rate so total_bytes / total_packets approximate full traffic volume.

Example: sample rate 128, one 1500-byte sample frame →
  sampled_bytes=1500, total_bytes=1500*128 (≈100% volume estimate).

You still only store the *sampled* flow identities (not every session).
Default listen port: 6343
"""
from __future__ import annotations

import os
import socket
import struct
import threading
from datetime import datetime
from typing import Callable, Optional, Tuple

from app.collectors.common import build_ipdr_record, create_udp_socket
from app.utils.logger import logger

FLOW_SAMPLE = 1
COUNTER_SAMPLE = 2
EXPANDED_FLOW_SAMPLE = 3
EXPANDED_COUNTER_SAMPLE = 4

RAW_PACKET_HEADER = 1
ETHERNET_FRAME = 2
IPV4 = 3
IPV6 = 4


class SFlowCollector:
    """UDP collector for sFlow v2/v4/v5 with optional volume extrapolation."""

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 6343,
        callback: Optional[Callable] = None,
        extrapolate: Optional[bool] = None,
    ):
        self.host = host
        self.port = port
        self.callback = callback
        # Default: extrapolate volumes to approximate 100% traffic
        if extrapolate is None:
            env = os.getenv("SFLOW_EXTRAPOLATE", "true").strip().lower()
            extrapolate = env in ("1", "true", "yes", "on")
        self.extrapolate = bool(extrapolate)
        self.socket = None
        self.running = False
        self.thread = None

    def start(self):
        if self.running:
            logger.warning("sFlow collector is already running")
            return
        self.socket = create_udp_socket(self.host, self.port)
        self.socket.settimeout(1.0)
        self.running = True
        self.thread = threading.Thread(target=self._listen, daemon=True, name="sflow-collector")
        self.thread.start()
        mode = "extrapolated (~100% volume)" if self.extrapolate else "raw samples only"
        logger.info(f"sFlow collector started on {self.host}:{self.port} [{mode}]")

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except OSError:
                pass
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("sFlow collector stopped")

    def _listen(self):
        while self.running:
            try:
                data, addr = self.socket.recvfrom(65535)
                self._process_datagram(data, addr)
            except socket.timeout:
                continue
            except OSError:
                if self.running:
                    logger.error("sFlow socket error", exc_info=True)
            except Exception as e:
                if self.running:
                    logger.error(f"Error receiving sFlow datagram: {e}", exc_info=True)

    def _emit(self, record):
        if self.callback:
            self.callback(record)

    def _process_datagram(self, data: bytes, addr: tuple):
        try:
            if len(data) < 28:
                return
            version = struct.unpack("!I", data[0:4])[0]
            if version not in (2, 4, 5):
                logger.debug(f"Ignoring non-sFlow version {version} on sFlow port from {addr[0]}")
                return

            offset = 4
            addr_type = struct.unpack("!I", data[offset:offset + 4])[0]
            offset += 4
            if addr_type == 1:
                agent = socket.inet_ntoa(data[offset:offset + 4])
                offset += 4
            elif addr_type == 2:
                agent = socket.inet_ntop(socket.AF_INET6, data[offset:offset + 16])
                offset += 16
            else:
                logger.debug(f"Unknown sFlow agent address type {addr_type}")
                return

            _sub_agent, _seq, _uptime, sample_count = struct.unpack("!IIII", data[offset:offset + 16])
            offset += 16

            for _ in range(sample_count):
                if offset + 8 > len(data):
                    break
                sample_type, sample_len = struct.unpack("!II", data[offset:offset + 8])
                offset += 8
                stype = sample_type & 0xFFF
                sample_data = data[offset:offset + sample_len]
                offset += sample_len
                if stype in (FLOW_SAMPLE, EXPANDED_FLOW_SAMPLE):
                    self._parse_flow_sample(
                        sample_data,
                        addr[0],
                        agent,
                        expanded=(stype == EXPANDED_FLOW_SAMPLE),
                    )
        except Exception as e:
            logger.error(f"Error processing sFlow datagram: {e}", exc_info=True)

    def _parse_flow_sample(self, data: bytes, router_ip: str, agent: str, expanded: bool):
        try:
            if expanded:
                if len(data) < 36:
                    return
                _seq, _sid_type, _sid_idx, sampling_rate, sample_pool, drops, _inp, _outp, record_count = struct.unpack(
                    "!IIIIIIIII", data[0:36]
                )
                offset = 36
            else:
                if len(data) < 32:
                    return
                _seq, _source_id, sampling_rate, sample_pool, drops, _inp, _outp, record_count = struct.unpack(
                    "!IIIIIIII", data[0:32]
                )
                offset = 32

            sampling_rate = max(int(sampling_rate or 1), 1)
            sample_pool = int(sample_pool or 0) or None
            drops = int(drops or 0)

            for _ in range(record_count):
                if offset + 8 > len(data):
                    break
                data_format, data_len = struct.unpack("!II", data[offset:offset + 8])
                offset += 8
                record = data[offset:offset + data_len]
                offset += data_len
                fmt = data_format & 0xFFF
                parsed = None
                if fmt == RAW_PACKET_HEADER:
                    parsed = self._parse_raw_header(record)
                elif fmt == IPV4:
                    parsed = self._parse_sampled_ipv4(record)
                elif fmt == IPV6:
                    parsed = self._parse_sampled_ipv6(record)
                elif fmt == ETHERNET_FRAME:
                    parsed = self._parse_ethernet_frame(record)

                if not parsed:
                    continue

                src_ip, dst_ip, src_port, dst_port, proto, frame_len = parsed
                sampled_bytes = int(frame_len or 0)
                sampled_packets = 1

                if self.extrapolate and sampling_rate > 1:
                    total_bytes = sampled_bytes * sampling_rate
                    total_packets = sampled_packets * sampling_rate
                    volume_mode = "extrapolated"
                else:
                    total_bytes = sampled_bytes
                    total_packets = sampled_packets
                    volume_mode = "raw_sample"

                now = datetime.utcnow()
                self._emit(
                    build_ipdr_record(
                        source_ip=src_ip,
                        source_port=src_port,
                        destination_ip=dst_ip,
                        destination_port=dst_port,
                        protocol=proto,
                        total_bytes=total_bytes,
                        total_packets=total_packets,
                        session_start_time=now,
                        session_end_time=now,
                        duration_seconds=0,
                        router_ip=router_ip,
                        source="sflow",
                        is_sampled=True,
                        sampling_rate=sampling_rate,
                        sampled_bytes=sampled_bytes,
                        sampled_packets=sampled_packets,
                        sample_pool=sample_pool,
                        extra={
                            "agent": agent,
                            "sflow_format": fmt,
                            "volume_mode": volume_mode,
                            "sflow_drops": drops,
                            "note": (
                                "Volumes extrapolated by sampling_rate to approximate full traffic; "
                                "flow records themselves remain sampled (not every packet/session)."
                                if volume_mode == "extrapolated"
                                else "Raw sFlow sample sizes only (not extrapolated)."
                            ),
                        },
                    )
                )
        except Exception as e:
            logger.error(f"Error parsing sFlow flow sample: {e}", exc_info=True)

    def _parse_raw_header(self, data: bytes) -> Optional[Tuple[str, str, int, int, int, int]]:
        if len(data) < 16:
            return None
        header_protocol, frame_length, _stripped, header_size = struct.unpack("!IIII", data[0:16])
        header = data[16:16 + header_size]
        if header_protocol == 1:
            return self._parse_ethernet_payload(header, frame_length)
        return None

    def _parse_ethernet_frame(self, data: bytes) -> Optional[Tuple[str, str, int, int, int, int]]:
        if len(data) < 16:
            return None
        length = struct.unpack("!I", data[0:4])[0]
        if len(data) > 20:
            return self._parse_ethernet_payload(data[4:], length)
        return None

    def _parse_ethernet_payload(self, header: bytes, frame_length: int) -> Optional[Tuple[str, str, int, int, int, int]]:
        if len(header) < 14:
            return None
        ethertype = struct.unpack("!H", header[12:14])[0]
        offset = 14
        if ethertype == 0x8100 and len(header) >= 18:
            ethertype = struct.unpack("!H", header[16:18])[0]
            offset = 18
        if ethertype == 0x0800:
            return self._decode_ipv4(header[offset:], frame_length)
        if ethertype == 0x86DD:
            return self._decode_ipv6(header[offset:], frame_length)
        return None

    def _parse_sampled_ipv4(self, data: bytes) -> Optional[Tuple[str, str, int, int, int, int]]:
        if len(data) < 16:
            return None
        length, protocol, src, dst = struct.unpack("!IIII", data[0:16])
        src_port = dst_port = 0
        if len(data) >= 20:
            src_port, dst_port = struct.unpack("!HH", data[16:20])
        return (
            socket.inet_ntoa(struct.pack("!I", src)),
            socket.inet_ntoa(struct.pack("!I", dst)),
            src_port,
            dst_port,
            protocol & 0xFF,
            length,
        )

    def _parse_sampled_ipv6(self, data: bytes) -> Optional[Tuple[str, str, int, int, int, int]]:
        if len(data) < 40:
            return None
        length = struct.unpack("!I", data[0:4])[0]
        protocol = data[7] if len(data) > 7 else 0
        try:
            src = socket.inet_ntop(socket.AF_INET6, data[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, data[24:40])
            src_port = dst_port = 0
            if len(data) >= 44:
                src_port, dst_port = struct.unpack("!HH", data[40:44])
            return src, dst, src_port, dst_port, protocol, length
        except OSError:
            return None

    def _decode_ipv4(self, pkt: bytes, frame_length: int) -> Optional[Tuple[str, str, int, int, int, int]]:
        if len(pkt) < 20:
            return None
        ihl = (pkt[0] & 0x0F) * 4
        protocol = pkt[9]
        src = socket.inet_ntoa(pkt[12:16])
        dst = socket.inet_ntoa(pkt[16:20])
        src_port = dst_port = 0
        if protocol in (6, 17) and len(pkt) >= ihl + 4:
            src_port, dst_port = struct.unpack("!HH", pkt[ihl:ihl + 4])
        total_len = struct.unpack("!H", pkt[2:4])[0]
        return src, dst, src_port, dst_port, protocol, frame_length or total_len

    def _decode_ipv6(self, pkt: bytes, frame_length: int) -> Optional[Tuple[str, str, int, int, int, int]]:
        if len(pkt) < 40:
            return None
        next_header = pkt[6]
        src = socket.inet_ntop(socket.AF_INET6, pkt[8:24])
        dst = socket.inet_ntop(socket.AF_INET6, pkt[24:40])
        src_port = dst_port = 0
        if next_header in (6, 17) and len(pkt) >= 44:
            src_port, dst_port = struct.unpack("!HH", pkt[40:44])
        payload_len = struct.unpack("!H", pkt[4:6])[0]
        return src, dst, src_port, dst_port, next_header, frame_length or (payload_len + 40)
