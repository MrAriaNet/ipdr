"""AAA / subscriber session binding: framed_ip + time → legal identity."""
from __future__ import annotations

import json
from datetime import datetime
from typing import List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.collectors.common import normalize_ip
from app.models import SubscriberSession
from app.schemas import (
    SubscriberResolveResponse,
    SubscriberSessionCreate,
)
from app.utils.timeutil import ensure_utc, utcnow


class AAAService:
    @staticmethod
    def create_session(db: Session, data: SubscriberSessionCreate) -> SubscriberSession:
        row = SubscriberSession(
            framed_ip=normalize_ip(data.framed_ip),
            subscriber_id=data.subscriber_id,
            username=data.username,
            account_id=data.account_id,
            msisdn=data.msisdn,
            imsi=data.imsi,
            mac=data.mac,
            circuit_id=data.circuit_id,
            nas_ip=normalize_ip(data.nas_ip) if data.nas_ip else None,
            realm=data.realm,
            session_id=data.session_id,
            valid_from=ensure_utc(data.valid_from) or utcnow(),
            valid_to=ensure_utc(data.valid_to),
            source=data.source or "aaa",
            additional_info=json.dumps(data.additional_info) if data.additional_info else None,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    @staticmethod
    def resolve(
        db: Session,
        *,
        framed_ip: str,
        at_time: Optional[datetime] = None,
    ) -> SubscriberResolveResponse:
        at = ensure_utc(at_time) or utcnow()
        ip = normalize_ip(framed_ip)
        rows = (
            db.query(SubscriberSession)
            .filter(
                SubscriberSession.framed_ip == ip,
                SubscriberSession.valid_from <= at,
                or_(
                    SubscriberSession.valid_to.is_(None),
                    SubscriberSession.valid_to >= at,
                ),
            )
            .order_by(SubscriberSession.valid_from.desc())
            .limit(20)
            .all()
        )
        if not rows:
            return SubscriberResolveResponse(
                found=False,
                framed_ip=ip,
                at_time=at,
                match_count=0,
                message="No AAA/subscriber session for this framed IP at the given time",
            )

        # Unique by subscriber_id
        unique_ids = {r.subscriber_id for r in rows}
        ambiguous = len(unique_ids) > 1
        primary = rows[0]
        return SubscriberResolveResponse(
            found=True,
            framed_ip=ip,
            at_time=at,
            subscriber_id=primary.subscriber_id if not ambiguous else None,
            username=primary.username if not ambiguous else None,
            account_id=primary.account_id if not ambiguous else None,
            msisdn=primary.msisdn if not ambiguous else None,
            imsi=primary.imsi if not ambiguous else None,
            session_id=primary.id if not ambiguous else None,
            match_count=len(rows),
            ambiguous=ambiguous,
            message=(
                "AMBIGUOUS — multiple subscriber identities overlap; human review required"
                if ambiguous
                else "OK"
            ),
        )

    @staticmethod
    def list_sessions(
        db: Session,
        *,
        framed_ip: Optional[str] = None,
        subscriber_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[SubscriberSession]:
        q = db.query(SubscriberSession)
        if framed_ip:
            q = q.filter(SubscriberSession.framed_ip == normalize_ip(framed_ip))
        if subscriber_id:
            q = q.filter(SubscriberSession.subscriber_id == subscriber_id)
        return q.order_by(SubscriberSession.valid_from.desc()).offset(offset).limit(limit).all()
