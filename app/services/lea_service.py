"""
LEA / network-security investigation workflows:
  public_ip:port + time → CGNAT PBA → AAA identity → related flows → export.
"""
from __future__ import annotations

import csv
import io
import json
from datetime import timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models import IPDRRecord
from app.schemas import (
    LEAExportRequest,
    LEAInvestigateRequest,
    TrafficQuery,
)
from app.services.aaa_service import AAAService
from app.services.cgnat_service import CGNATService
from app.services.ipdr_service import IPDRService
from app.utils.hashutil import sha256_hex
from app.utils.timeutil import ensure_utc, utcnow


class LEAService:
    @staticmethod
    def investigate(db: Session, req: LEAInvestigateRequest) -> Dict[str, Any]:
        at = ensure_utc(req.at) or utcnow()
        cgnat = CGNATService.lookup(
            db,
            public_ip=req.public_ip,
            public_port=req.public_port,
            at_time=at,
        )

        subscriber = None
        flows: List[Dict[str, Any]] = []
        inside_ip = cgnat.inside_ip

        if cgnat.found and not cgnat.ambiguous and inside_ip and req.resolve_subscriber:
            subscriber = AAAService.resolve(db, framed_ip=inside_ip, at_time=at).model_dump()

        if cgnat.found and not cgnat.ambiguous and inside_ip and req.include_flows:
            window = timedelta(seconds=int(req.window_seconds))
            q = TrafficQuery(
                start_time=at - window,
                end_time=at + window,
                source_ip=inside_ip,
                session_overlap=True,
                limit=req.flow_limit,
                offset=0,
            )
            records = IPDRService.get_records(db, q)
            flows = [LEAService._flow_dict(r) for r in records]

            if req.legal_hold and req.case_ref:
                for r in records:
                    r.legal_hold = True
                    r.hold_case_id = req.case_ref
                if cgnat.block_id:
                    CGNATService.set_legal_hold(
                        db, block_ids=[cgnat.block_id], case_id=req.case_ref, hold=True
                    )
                db.commit()

        bundle = {
            "case_ref": req.case_ref,
            "queried_at": utcnow().isoformat(),
            "public_ip": req.public_ip,
            "public_port": req.public_port,
            "at": at.isoformat(),
            "cgnat": cgnat.model_dump(),
            "subscriber": subscriber,
            "flows": flows,
            "flow_count": len(flows),
            "notes": (
                "PBA mapping does not use a NAT connection table. "
                "If ambiguous=true, do not treat inside_ip as definitive."
            ),
        }
        bundle["bundle_hash"] = sha256_hex(bundle)
        return bundle

    @staticmethod
    def _flow_dict(r: IPDRRecord) -> Dict[str, Any]:
        return {
            "id": r.id,
            "source_ip": r.source_ip,
            "source_port": r.source_port,
            "destination_ip": r.destination_ip,
            "destination_port": r.destination_port,
            "protocol": r.protocol,
            "protocol_number": r.protocol_number,
            "ip_version": r.ip_version,
            "session_start_time": r.session_start_time.isoformat() if r.session_start_time else None,
            "session_end_time": r.session_end_time.isoformat() if r.session_end_time else None,
            "total_bytes": r.total_bytes,
            "total_packets": r.total_packets,
            "is_sampled": r.is_sampled,
            "sampling_rate": r.sampling_rate,
            "content_hash": getattr(r, "content_hash", None),
            "user_id": r.user_id,
            "service_type": r.service_type,
        }

    @staticmethod
    def export(db: Session, req: LEAExportRequest) -> Dict[str, Any]:
        """Build warrant-oriented export package with manifest + payload hash."""
        at = ensure_utc(req.at)
        records: List[IPDRRecord] = []
        cgnat_info = None

        if req.public_ip is not None and req.public_port is not None and at is not None:
            inv = LEAService.investigate(
                db,
                LEAInvestigateRequest(
                    public_ip=req.public_ip,
                    public_port=req.public_port,
                    at=at,
                    case_ref=req.case_ref,
                    include_flows=True,
                    resolve_subscriber=True,
                    legal_hold=req.legal_hold,
                    flow_limit=min(req.limit, 5000),
                ),
            )
            payload_obj = inv
            fmt = (req.format or "json").lower()
            body = LEAService._serialize(payload_obj, fmt)
            manifest = {
                "case_ref": req.case_ref,
                "exported_at": utcnow().isoformat(),
                "format": fmt,
                "record_count": inv.get("flow_count", 0),
                "query": req.model_dump(),
                "payload_sha256": sha256_hex(body),
                "bundle_hash": inv.get("bundle_hash"),
            }
            return {"manifest": manifest, "body": body, "content_type": LEAService._ctype(fmt)}

        q = TrafficQuery(
            start_time=ensure_utc(req.start_time),
            end_time=ensure_utc(req.end_time),
            source_ip=req.source_ip,
            destination_ip=req.destination_ip,
            source_port=req.source_port,
            destination_port=req.destination_port,
            session_overlap=True,
            limit=req.limit,
            offset=0,
        )
        records = IPDRService.get_records(db, q)
        if req.legal_hold and req.case_ref:
            for r in records:
                r.legal_hold = True
                r.hold_case_id = req.case_ref
            db.commit()

        rows = [LEAService._flow_dict(r) for r in records]
        payload_obj = {"case_ref": req.case_ref, "cgnat": cgnat_info, "flows": rows}
        fmt = (req.format or "json").lower()
        body = LEAService._serialize(rows if fmt == "csv" else payload_obj, fmt)
        manifest = {
            "case_ref": req.case_ref,
            "exported_at": utcnow().isoformat(),
            "format": fmt,
            "record_count": len(rows),
            "query": req.model_dump(),
            "payload_sha256": sha256_hex(body),
        }
        return {"manifest": manifest, "body": body, "content_type": LEAService._ctype(fmt)}

    @staticmethod
    def _ctype(fmt: str) -> str:
        if fmt == "csv":
            return "text/csv"
        if fmt == "ndjson":
            return "application/x-ndjson"
        return "application/json"

    @staticmethod
    def _serialize(obj: Any, fmt: str) -> str:
        if fmt == "json":
            return json.dumps(obj, default=str, indent=2)
        if fmt == "ndjson":
            items = obj if isinstance(obj, list) else obj.get("flows", [obj])
            return "\n".join(json.dumps(i, default=str) for i in items)
        # csv
        items = obj if isinstance(obj, list) else obj.get("flows", [])
        if not items:
            return ""
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=list(items[0].keys()))
        writer.writeheader()
        for row in items:
            writer.writerow(row)
        return buf.getvalue()
