"""Append-only query audit for LEA / security lookups and exports."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import QueryAuditLog
from app.utils.hashutil import sha256_hex
from app.utils.timeutil import utcnow


class AuditService:
    @staticmethod
    def log(
        db: Session,
        *,
        actor_id: str,
        actor_role: Optional[str],
        action: str,
        request_params: Dict[str, Any],
        result_found: bool = False,
        result_count: int = 0,
        result_summary: Optional[Dict[str, Any]] = None,
        case_ref: Optional[str] = None,
        client_ip: Optional[str] = None,
        response_payload: Optional[Any] = None,
    ) -> QueryAuditLog:
        response_hash = None
        if response_payload is not None:
            if isinstance(response_payload, (dict, list)):
                response_hash = sha256_hex(
                    response_payload if isinstance(response_payload, dict) else {"items": response_payload}
                )
            else:
                response_hash = sha256_hex(str(response_payload))

        row = QueryAuditLog(
            event_time=utcnow(),
            actor_id=actor_id or "anonymous",
            actor_role=actor_role,
            action=action,
            case_ref=case_ref,
            client_ip=client_ip,
            request_params=json.dumps(request_params, default=str),
            result_found=bool(result_found),
            result_count=int(result_count or 0),
            result_summary=json.dumps(result_summary, default=str) if result_summary else None,
            response_hash=response_hash,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        return row

    @staticmethod
    def list_logs(
        db: Session,
        *,
        action: Optional[str] = None,
        case_ref: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[QueryAuditLog]:
        q = db.query(QueryAuditLog)
        if action:
            q = q.filter(QueryAuditLog.action == action)
        if case_ref:
            q = q.filter(QueryAuditLog.case_ref == case_ref)
        return (
            q.order_by(QueryAuditLog.event_time.desc())
            .offset(offset)
            .limit(limit)
            .all()
        )
