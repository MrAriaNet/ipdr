"""
CGNAT Port Block Allocation (PBA) service — store and look up subscriber mappings.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.collectors.common import normalize_ip
from app.models import CGNATEventType, CGNATPortBlock
from app.schemas import CGNATLookupResponse, CGNATPortBlockCreate
from app.utils.logger import logger


class CGNATService:
    @staticmethod
    def create_block(db: Session, data: CGNATPortBlockCreate) -> CGNATPortBlock:
        inside = normalize_ip(data.inside_ip)
        outside = normalize_ip(data.outside_ip)
        port_start = int(data.port_start)
        port_end = int(data.port_end)
        if port_end < port_start:
            port_start, port_end = port_end, port_start
        block_size = data.port_block_size or (port_end - port_start + 1)

        event_type = data.event_type
        is_active = True if data.is_active is None else bool(data.is_active)
        released_at = data.released_at

        if event_type in (CGNATEventType.DEALLOCATE, CGNATEventType.DELETE):
            is_active = False
            if released_at is None:
                released_at = data.event_time
            # Close any matching active block for same outside/ports/inside
            CGNATService._deactivate_matching(
                db,
                inside_ip=inside,
                outside_ip=outside,
                port_start=port_start,
                port_end=port_end,
                released_at=released_at,
            )

        row = CGNATPortBlock(
            event_time=data.event_time,
            event_type=event_type,
            inside_ip=inside,
            outside_ip=outside,
            port_start=port_start,
            port_end=port_end,
            port_block_size=block_size,
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
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        logger.info(
            f"CGNAT PBA {event_type.value}: {inside} -> {outside}:{port_start}-{port_end} "
            f"(size={block_size})"
        )
        return row

    @staticmethod
    def create_from_dict(db: Session, payload: dict) -> CGNATPortBlock:
        # Coerce event_type string
        et = payload.get("event_type", "allocate")
        if isinstance(et, str):
            try:
                et = CGNATEventType(et.lower())
            except ValueError:
                et = CGNATEventType.UNKNOWN
        payload = {**payload, "event_type": et}
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
            q = q.filter(CGNATPortBlock.event_time >= start_time)
        if end_time:
            q = q.filter(CGNATPortBlock.event_time <= end_time)
        return (
            q.order_by(CGNATPortBlock.event_time.desc())
            .offset(offset)
            .limit(limit)
            .all()
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
        Map public_ip:public_port to the subscriber (inside) IP that held the
        port block at at_time (default: now). Used by network security / LEA.
        """
        at = at_time or datetime.utcnow()
        outside = normalize_ip(public_ip)
        port = int(public_port)

        # Block must contain the port and be valid at 'at'
        # active OR (event_time <= at AND (released_at is null OR released_at >= at))
        q = (
            db.query(CGNATPortBlock)
            .filter(
                CGNATPortBlock.outside_ip == outside,
                CGNATPortBlock.port_start <= port,
                CGNATPortBlock.port_end >= port,
                CGNATPortBlock.event_time <= at,
                or_(
                    CGNATPortBlock.released_at.is_(None),
                    CGNATPortBlock.released_at >= at,
                ),
            )
            .order_by(CGNATPortBlock.event_time.desc())
        )
        row = q.first()
        if not row:
            # Fallback: any allocate covering the port closest before at
            row = (
                db.query(CGNATPortBlock)
                .filter(
                    CGNATPortBlock.outside_ip == outside,
                    CGNATPortBlock.port_start <= port,
                    CGNATPortBlock.port_end >= port,
                    CGNATPortBlock.event_time <= at,
                    CGNATPortBlock.event_type.in_(
                        [CGNATEventType.ALLOCATE, CGNATEventType.CREATE]
                    ),
                )
                .order_by(CGNATPortBlock.event_time.desc())
                .first()
            )
            if row and row.released_at and row.released_at < at:
                row = None

        if not row:
            return CGNATLookupResponse(
                found=False,
                public_ip=outside,
                public_port=port,
                at_time=at,
                message="No CGNAT port block found for this public IP/port at the given time",
            )

        return CGNATLookupResponse(
            found=True,
            public_ip=outside,
            public_port=port,
            at_time=at,
            inside_ip=row.inside_ip,
            outside_ip=row.outside_ip,
            port_start=row.port_start,
            port_end=row.port_end,
            port_block_size=row.port_block_size,
            protocol=row.protocol,
            event_time=row.event_time,
            released_at=row.released_at,
            subscriber_id=row.subscriber_id,
            block_id=row.id,
            message="OK",
        )
