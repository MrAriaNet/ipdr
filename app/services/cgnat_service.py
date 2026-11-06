"""
CGNAT Port Block Allocation (PBA) service — store and look up subscriber mappings.

PBA mode (unlike classic NAT overload / PAT):
  - There is NO per-connection translation (XLATE) table to log.
  - CGN only allocates / deallocates contiguous public port blocks to a subscriber.
  - Security mapping needs only: public_ip + public_port + time → inside_ip
    (no inside_port, no 5-tuple, no session id).
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.collectors.cgnat_fields import port_in_pba_set
from app.collectors.common import normalize_ip
from app.models import CGNATEventType, CGNATPortBlock
from app.schemas import (
    CGNATLookupResponse,
    CGNATMatchItem,
    CGNATPortBlockCreate,
    CGNATSubscriberBlockItem,
    CGNATSubscriberBlocksResponse,
)
from app.utils.hashutil import sha256_hex
from app.utils.logger import logger
from app.utils.timeutil import ensure_utc, utcnow

# Ownership events — only these rows "hold" a port block (not deallocate rows)
_OWNERSHIP = (CGNATEventType.ALLOCATE, CGNATEventType.CREATE)


class CGNATService:
    @staticmethod
    def create_block(db: Session, data: CGNATPortBlockCreate) -> CGNATPortBlock:
        """
        Ingest one PBA lifecycle event (Cisco ASR HSL allocate/deallocate).
        No connection/session fields — only inside_ip, outside_ip, port set + step.
        """
        inside = normalize_ip(data.inside_ip)
        outside = normalize_ip(data.outside_ip)
        port_start = int(data.port_start)
        port_end = int(data.port_end)
        port_step = max(int(data.port_step or 1), 1)
        if port_end < port_start:
            port_start, port_end = port_end, port_start
        if data.port_block_size:
            block_size = int(data.port_block_size)
            # Prefer Cisco formula for end when step known
            if port_step > 1:
                port_end = port_start + (block_size - 1) * port_step
        elif port_step > 1:
            block_size = ((port_end - port_start) // port_step) + 1
        else:
            block_size = port_end - port_start + 1

        event_type = data.event_type
        is_active = True if data.is_active is None else bool(data.is_active)
        released_at = ensure_utc(data.released_at)
        event_time = ensure_utc(data.event_time) or utcnow()
        mapping_mode = (data.mapping_mode or "pba").lower()
        if block_size <= 1 and mapping_mode == "pba":
            # Single-port create/delete from classic NAT HSL
            if data.raw_nat_event is not None or mapping_mode == "overload":
                mapping_mode = "overload"

        if event_type in (CGNATEventType.DEALLOCATE, CGNATEventType.DELETE):
            is_active = False
            if released_at is None:
                released_at = event_time
            CGNATService._deactivate_matching(
                db,
                inside_ip=inside,
                outside_ip=outside,
                port_start=port_start,
                port_end=port_end,
                released_at=released_at,
            )

        content_hash = sha256_hex(
            {
                "event_time": event_time.isoformat(),
                "event_type": event_type.value if hasattr(event_type, "value") else str(event_type),
                "inside_ip": inside,
                "outside_ip": outside,
                "port_start": port_start,
                "port_end": port_end,
                "port_step": port_step,
                "port_block_size": block_size,
                "mapping_mode": mapping_mode,
            }
        )

        row = CGNATPortBlock(
            event_time=event_time,
            event_type=event_type,
            inside_ip=inside,
            outside_ip=outside,
            port_start=port_start,
            port_end=port_end,
            port_block_size=block_size,
            port_step=port_step,
            protocol=data.protocol or "ANY",
            protocol_number=data.protocol_number,
            ip_version=data.ip_version or (6 if ":" in inside else 4),
            vrf_id=data.vrf_id,
            nat_pool_name=data.nat_pool_name,
            subscriber_id=data.subscriber_id,
            released_at=released_at,
            is_active=is_active,
            router_ip=normalize_ip(data.router_ip, default="") if data.router_ip else None,
            source=data.source or "api",
            raw_nat_event=data.raw_nat_event,
            additional_info=json.dumps(data.additional_info) if data.additional_info else None,
            mapping_mode=mapping_mode,
            content_hash=content_hash,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        logger.info(
            f"CGNAT PBA {event_type.value}: {inside} -> {outside}:{port_start}-{port_end} "
            f"(size={block_size}, step={port_step}, mode={mapping_mode})"
        )
        return row

    @staticmethod
    def create_from_dict(db: Session, payload: dict) -> CGNATPortBlock:
        payload = dict(payload)
        et = payload.get("event_type", "allocate")
        if isinstance(et, str):
            try:
                et = CGNATEventType(et.lower())
            except ValueError:
                et = CGNATEventType.UNKNOWN
        payload["event_type"] = et
        # Spool replay may store ISO strings
        for key in ("event_time", "released_at"):
            val = payload.get(key)
            if isinstance(val, str):
                payload[key] = ensure_utc(
                    datetime.fromisoformat(val.replace("Z", "+00:00"))
                )
        return CGNATService.create_block(db, CGNATPortBlockCreate(**payload))

    @staticmethod
    def _deactivate_matching(
        db: Session,
        *,
        inside_ip: str,
        outside_ip: str,
        port_start: int,
        port_end: int,
        released_at: datetime,
    ):
        q = db.query(CGNATPortBlock).filter(
            CGNATPortBlock.is_active.is_(True),
            CGNATPortBlock.outside_ip == outside_ip,
            CGNATPortBlock.port_start == port_start,
            CGNATPortBlock.port_end == port_end,
            CGNATPortBlock.event_type.in_(list(_OWNERSHIP)),
        )
        if inside_ip:
            q = q.filter(CGNATPortBlock.inside_ip == inside_ip)
        for row in q.all():
            row.is_active = False
            row.released_at = released_at
        db.commit()

    @staticmethod
    def list_blocks(
        db: Session,
        *,
        inside_ip: Optional[str] = None,
        outside_ip: Optional[str] = None,
        is_active: Optional[bool] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[CGNATPortBlock]:
        q = db.query(CGNATPortBlock)
        if inside_ip:
            q = q.filter(CGNATPortBlock.inside_ip == normalize_ip(inside_ip))
        if outside_ip:
            q = q.filter(CGNATPortBlock.outside_ip == normalize_ip(outside_ip))
        if is_active is not None:
            q = q.filter(CGNATPortBlock.is_active.is_(is_active))
        if start_time:
            q = q.filter(CGNATPortBlock.event_time >= ensure_utc(start_time))
        if end_time:
            q = q.filter(CGNATPortBlock.event_time <= ensure_utc(end_time))
        return (
            q.order_by(CGNATPortBlock.event_time.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )

    @staticmethod
    def _block_valid_at(row: CGNATPortBlock, at: datetime) -> bool:
        et = ensure_utc(row.event_time)
        rt = ensure_utc(row.released_at)
        if et and et > at:
            return False
        if rt is not None and rt < at:
            return False
        return True

    @staticmethod
    def _row_to_match(row: CGNATPortBlock) -> CGNATMatchItem:
        return CGNATMatchItem(
            inside_ip=row.inside_ip,
            outside_ip=row.outside_ip,
            port_start=row.port_start,
            port_end=row.port_end,
            port_block_size=row.port_block_size,
            port_step=getattr(row, "port_step", None) or 1,
            protocol=row.protocol,
            event_time=row.event_time,
            released_at=row.released_at,
            subscriber_id=row.subscriber_id,
            block_id=row.id,
            mapping_mode=getattr(row, "mapping_mode", None) or "pba",
        )

    @staticmethod
    def _row_owns_port(row: CGNATPortBlock, port: int) -> bool:
        return port_in_pba_set(
            port,
            row.port_start,
            row.port_end,
            getattr(row, "port_step", None) or 1,
            row.port_block_size,
        )

    @staticmethod
    def lookup(
        db: Session,
        *,
        public_ip: str,
        public_port: int,
        at_time: Optional[datetime] = None,
    ) -> CGNATLookupResponse:
        """
        Map public_ip:public_port → subscriber (inside) IP using PBA history only.

        Returns ALL matching blocks. If more than one distinct inside_ip matches,
        ambiguous=True (forensic review required — never silently pick one).
        """
        at = ensure_utc(at_time) or utcnow()
        outside = normalize_ip(public_ip)
        port = int(public_port)

        # Wide span filter in SQL, then honour Cisco scattered step in Python
        candidates = (
            db.query(CGNATPortBlock)
            .filter(
                CGNATPortBlock.outside_ip == outside,
                CGNATPortBlock.port_start <= port,
                CGNATPortBlock.port_end >= port,
                CGNATPortBlock.event_type.in_(list(_OWNERSHIP)),
                CGNATPortBlock.event_time <= at,
                or_(
                    CGNATPortBlock.released_at.is_(None),
                    CGNATPortBlock.released_at >= at,
                ),
            )
            .order_by(CGNATPortBlock.event_time.desc())
            .limit(100)
            .all()
        )
        rows = [r for r in candidates if CGNATService._row_owns_port(r, port)]

        if not rows:
            candidates = (
                db.query(CGNATPortBlock)
                .filter(
                    CGNATPortBlock.outside_ip == outside,
                    CGNATPortBlock.port_start <= port,
                    CGNATPortBlock.port_end >= port,
                    CGNATPortBlock.event_type.in_(list(_OWNERSHIP)),
                    CGNATPortBlock.event_time <= at,
                )
                .order_by(CGNATPortBlock.event_time.desc())
                .limit(100)
                .all()
            )
            rows = [
                c
                for c in candidates
                if CGNATService._block_valid_at(c, at) and CGNATService._row_owns_port(c, port)
            ]

        matches = [CGNATService._row_to_match(r) for r in rows]
        # Deduplicate identical blocks (same inside + range) keeping newest
        seen = set()
        unique_matches: List[CGNATMatchItem] = []
        for m in matches:
            key = (m.inside_ip, m.outside_ip, m.port_start, m.port_end)
            if key in seen:
                continue
            seen.add(key)
            unique_matches.append(m)

        if not unique_matches:
            return CGNATLookupResponse(
                found=False,
                public_ip=outside,
                public_port=port,
                at_time=at,
                match_count=0,
                ambiguous=False,
                matches=[],
                message=(
                    "No CGNAT port block found for this public IP/port at the given time "
                    "(PBA has no per-connection table; only allocate/deallocate blocks are searched)"
                ),
            )

        distinct_inside = {m.inside_ip for m in unique_matches}
        ambiguous = len(distinct_inside) > 1
        primary = unique_matches[0]

        if ambiguous:
            msg = (
                f"AMBIGUOUS — {len(unique_matches)} overlapping block(s) / "
                f"{len(distinct_inside)} inside IPs; human review required"
            )
        else:
            msg = (
                "OK — mapped via port-block allocation "
                "(no NAT connection/XLATE entry required)"
            )

        return CGNATLookupResponse(
            found=True,
            public_ip=outside,
            public_port=port,
            at_time=at,
            inside_ip=None if ambiguous else primary.inside_ip,
            outside_ip=primary.outside_ip,
            port_start=primary.port_start,
            port_end=primary.port_end,
            port_block_size=primary.port_block_size,
            port_step=primary.port_step,
            protocol=primary.protocol,
            event_time=primary.event_time,
            released_at=primary.released_at,
            subscriber_id=None if ambiguous else primary.subscriber_id,
            block_id=None if ambiguous else primary.block_id,
            mapping_mode=primary.mapping_mode,
            match_count=len(unique_matches),
            ambiguous=ambiguous,
            matches=unique_matches,
            message=msg,
        )

    @staticmethod
    def lookup_by_subscriber(
        db: Session,
        *,
        inside_ip: str,
        at_time: Optional[datetime] = None,
    ) -> CGNATSubscriberBlocksResponse:
        at = ensure_utc(at_time) or utcnow()
        inside = normalize_ip(inside_ip)

        rows = (
            db.query(CGNATPortBlock)
            .filter(
                CGNATPortBlock.inside_ip == inside,
                CGNATPortBlock.event_type.in_(list(_OWNERSHIP)),
                CGNATPortBlock.event_time <= at,
                or_(
                    CGNATPortBlock.released_at.is_(None),
                    CGNATPortBlock.released_at >= at,
                ),
            )
            .order_by(CGNATPortBlock.event_time.desc())
            .all()
        )

        blocks = [
            CGNATSubscriberBlockItem(
                block_id=r.id,
                outside_ip=r.outside_ip,
                port_start=r.port_start,
                port_end=r.port_end,
                port_block_size=r.port_block_size,
                port_step=getattr(r, "port_step", None) or 1,
                protocol=r.protocol,
                event_time=r.event_time,
                released_at=r.released_at,
                is_active=r.is_active,
                subscriber_id=r.subscriber_id,
                mapping_mode=getattr(r, "mapping_mode", None),
            )
            for r in rows
        ]

        return CGNATSubscriberBlocksResponse(
            found=bool(blocks),
            inside_ip=inside,
            at_time=at,
            blocks=blocks,
            message=(
                f"OK — {len(blocks)} port block(s) held by subscriber at that time"
                if blocks
                else "No active/held port blocks for this subscriber at the given time"
            ),
        )

    @staticmethod
    def set_legal_hold(
        db: Session,
        *,
        block_ids: List[int],
        case_id: str,
        hold: bool = True,
    ) -> int:
        q = db.query(CGNATPortBlock).filter(CGNATPortBlock.id.in_(block_ids))
        n = 0
        for row in q.all():
            row.legal_hold = hold
            row.hold_case_id = case_id if hold else None
            n += 1
        db.commit()
        return n
