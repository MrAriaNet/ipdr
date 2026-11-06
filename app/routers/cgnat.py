"""
API routes for CGNAT Port Block Allocation (PBA) — security / LEA lookups.

PBA has no per-connection NAT table (unlike NAT overload). Lookups use only
allocate/deallocate port-block history.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.auth import AuthContext, require_role
from app.database import get_db
from app.schemas import (
    CGNATBulkCreate,
    CGNATLookupResponse,
    CGNATPortBlockCreate,
    CGNATPortBlockResponse,
    CGNATSubscriberBlocksResponse,
)
from app.services.audit_service import AuditService
from app.services.cgnat_service import CGNATService
from app.utils.logger import logger
from app.utils.timeutil import ensure_utc

router = APIRouter(prefix="/api/cgnat", tags=["CGNAT-PBA"])


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


@router.post("/blocks", response_model=CGNATPortBlockResponse, status_code=201)
async def create_cgnat_block(
    block: CGNATPortBlockCreate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("collector")),
):
    """Ingest a single CGNAT PBA allocate/deallocate event (API / HSL bridge)."""
    try:
        return CGNATService.create_block(db, block)
    except Exception as e:
        logger.error(f"CGNAT create error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/blocks/bulk", status_code=201)
async def create_cgnat_blocks_bulk(
    body: CGNATBulkCreate,
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("collector")),
):
    """Bulk ingest CGNAT PBA events."""
    created = 0
    errors = []
    for i, rec in enumerate(body.records):
        try:
            CGNATService.create_block(db, rec)
            created += 1
        except Exception as e:
            errors.append({"index": i, "error": str(e)})
    return {"created": created, "failed": len(errors), "errors": errors[:20]}


@router.get("/blocks", response_model=List[CGNATPortBlockResponse])
async def list_cgnat_blocks(
    inside_ip: Optional[str] = Query(None, description="Subscriber / pre-NAT IP"),
    outside_ip: Optional[str] = Query(None, description="Public / post-NAT IP"),
    is_active: Optional[bool] = Query(None, description="Only active port blocks"),
    start_time: Optional[datetime] = Query(None),
    end_time: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("ops")),
):
    """List stored CGNAT port-block events with filters."""
    return CGNATService.list_blocks(
        db,
        inside_ip=inside_ip,
        outside_ip=outside_ip,
        is_active=is_active,
        start_time=start_time,
        end_time=end_time,
        limit=limit,
        offset=offset,
    )


@router.get("/lookup", response_model=CGNATLookupResponse)
async def lookup_subscriber(
    request: Request,
    public_ip: str = Query(..., description="Public (post-NAT / outside) IP seen by security"),
    public_port: int = Query(..., ge=0, le=65535, description="Public port (any port inside the block)"),
    at: Optional[datetime] = Query(
        None,
        description="Time of the incident (ISO8601 with Z/offset). Default: now (UTC).",
    ),
    case_ref: Optional[str] = Query(None, description="Case / warrant reference for audit"),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("lea")),
):
    """
    Security lookup (PBA): public_ip:public_port → subscriber inside_ip.

    No NAT connection / XLATE / inside_port needed — only port-block history.
    If multiple blocks overlap, ambiguous=true and matches[] lists all candidates.
    """
    result = CGNATService.lookup(
        db,
        public_ip=public_ip,
        public_port=public_port,
        at_time=ensure_utc(at),
    )
    AuditService.log(
        db,
        actor_id=auth.key_id,
        actor_role=auth.role,
        action="cgnat_lookup",
        case_ref=case_ref,
        client_ip=_client_ip(request),
        request_params={
            "public_ip": public_ip,
            "public_port": public_port,
            "at": at,
            "case_ref": case_ref,
        },
        result_found=result.found,
        result_count=result.match_count,
        result_summary={
            "inside_ip": result.inside_ip,
            "ambiguous": result.ambiguous,
            "match_count": result.match_count,
        },
        response_payload=result.model_dump(),
    )
    return result


@router.get("/lookup/by-subscriber", response_model=CGNATSubscriberBlocksResponse)
async def lookup_by_subscriber(
    request: Request,
    inside_ip: str = Query(..., description="Subscriber / pre-NAT IP"),
    at: Optional[datetime] = Query(
        None,
        description="Time of interest (ISO8601 with Z/offset). Default: now (UTC).",
    ),
    case_ref: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    auth: AuthContext = Depends(require_role("lea")),
):
    """Reverse PBA lookup: inside_ip → public IP + port block(s) held at that time."""
    result = CGNATService.lookup_by_subscriber(
        db,
        inside_ip=inside_ip,
        at_time=ensure_utc(at),
    )
    AuditService.log(
        db,
        actor_id=auth.key_id,
        actor_role=auth.role,
        action="cgnat_lookup_by_subscriber",
        case_ref=case_ref,
        client_ip=_client_ip(request),
        request_params={"inside_ip": inside_ip, "at": at, "case_ref": case_ref},
        result_found=result.found,
        result_count=len(result.blocks),
        result_summary={"block_count": len(result.blocks)},
        response_payload=result.model_dump(),
    )
    return result
