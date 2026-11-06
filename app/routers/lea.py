"""
LEA / network-security API: investigate, export, AAA, audit, retention.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from app.auth import AuthContext, require_role
from app.database import get_db
from app.schemas import (
    LEAExportRequest,
    LEAInvestigateRequest,
    QueryAuditResponse,
    SubscriberResolveResponse,
    SubscriberSessionCreate,
    SubscriberSessionResponse,
)
from app.services.aaa_service import AAAService
from app.services.audit_service import AuditService
from app.services.lea_service import LEAService
from app.services.retention_service import RetentionService
from app.utils.logger import logger
from app.utils.timeutil import ensure_utc

router = APIRouter(prefix="/api/lea", tags=["LEA-Security"])


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


@router.post("/investigate")
async def investigate(
    body: LEAInvestigateRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("lea")),
):
    """
    Full LEA workflow: public_ip:port + time → CGNAT PBA → AAA → related flows.
    Does not require a NAT connection/XLATE table.
    """
    try:
        result = LEAService.investigate(db, body)
        AuditService.log(
            db,
            actor_id=auth.key_id,
            actor_role=auth.role,
            action="investigate",
            case_ref=body.case_ref,
            client_ip=_client_ip(request),
            request_params=body.model_dump(),
            result_found=bool(result.get("cgnat", {}).get("found")),
            result_count=int(result.get("flow_count") or 0),
            result_summary={
                "ambiguous": result.get("cgnat", {}).get("ambiguous"),
                "inside_ip": result.get("cgnat", {}).get("inside_ip"),
                "bundle_hash": result.get("bundle_hash"),
            },
            response_payload={"bundle_hash": result.get("bundle_hash")},
        )
        return result
    except Exception as e:
        logger.error(f"LEA investigate error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export")
async def export_package(
    body: LEAExportRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("lea")),
):
    """Warrant-oriented export with manifest + SHA-256 of payload."""
    try:
        result = LEAService.export(db, body)
        AuditService.log(
            db,
            actor_id=auth.key_id,
            actor_role=auth.role,
            action="export",
            case_ref=body.case_ref,
            client_ip=_client_ip(request),
            request_params=body.model_dump(),
            result_found=True,
            result_count=int(result["manifest"].get("record_count") or 0),
            result_summary=result["manifest"],
            response_payload=result["manifest"],
        )
        # Return JSON wrapper so clients always get manifest + body
        return {
            "manifest": result["manifest"],
            "body": result["body"],
        }
    except Exception as e:
        logger.error(f"LEA export error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/export/download")
async def export_download(
    body: LEAExportRequest,
    request: Request,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("lea")),
):
    """Same as /export but returns raw file body with Content-Disposition."""
    result = LEAService.export(db, body)
    AuditService.log(
        db,
        actor_id=auth.key_id,
        actor_role=auth.role,
        action="export_download",
        case_ref=body.case_ref,
        client_ip=_client_ip(request),
        request_params=body.model_dump(),
        result_found=True,
        result_count=int(result["manifest"].get("record_count") or 0),
        result_summary=result["manifest"],
        response_payload=result["manifest"],
    )
    ext = body.format if body.format in ("csv", "json", "ndjson") else "json"
    headers = {
        "Content-Disposition": f'attachment; filename="ipdr-{body.case_ref}.{ext}"',
        "X-IPDR-Manifest-SHA256": result["manifest"].get("payload_sha256", ""),
        "X-IPDR-Case-Ref": body.case_ref,
    }
    return Response(content=result["body"], media_type=result["content_type"], headers=headers)


@router.post("/aaa/sessions", response_model=SubscriberSessionResponse, status_code=201)
async def create_aaa_session(
    body: SubscriberSessionCreate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("ops")),
):
    """Ingest AAA/RADIUS/DHCP session (framed_ip → subscriber identity)."""
    return AAAService.create_session(db, body)


@router.get("/aaa/resolve", response_model=SubscriberResolveResponse)
async def resolve_subscriber(
    request: Request,
    framed_ip: str = Query(...),
    at: Optional[datetime] = Query(None),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("lea")),
):
    result = AAAService.resolve(db, framed_ip=framed_ip, at_time=ensure_utc(at))
    AuditService.log(
        db,
        actor_id=auth.key_id,
        actor_role=auth.role,
        action="aaa_resolve",
        client_ip=_client_ip(request),
        request_params={"framed_ip": framed_ip, "at": at},
        result_found=result.found,
        result_count=result.match_count,
        result_summary={"subscriber_id": result.subscriber_id, "ambiguous": result.ambiguous},
    )
    return result


@router.get("/aaa/sessions", response_model=List[SubscriberSessionResponse])
async def list_aaa_sessions(
    framed_ip: Optional[str] = None,
    subscriber_id: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("ops")),
):
    return AAAService.list_sessions(
        db, framed_ip=framed_ip, subscriber_id=subscriber_id, limit=limit, offset=offset
    )


@router.get("/audit", response_model=List[QueryAuditResponse])
async def list_audit(
    action: Optional[str] = None,
    case_ref: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("admin")),
):
    return AuditService.list_logs(
        db, action=action, case_ref=case_ref, limit=limit, offset=offset
    )


@router.post("/retention/purge")
async def retention_purge(
    dry_run: bool = Query(True, description="If true, only count candidates"),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("admin")),
):
    """Purge records older than retention that are not on legal hold."""
    return RetentionService.purge(db, dry_run=dry_run)
