"""
API routes for CGNAT Port Block Allocation (PBA) — security / LEA lookups.
"""
from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.schemas import (
    CGNATBulkCreate,
    CGNATLookupResponse,
    CGNATPortBlockCreate,
    CGNATPortBlockResponse,
)
from app.services.cgnat_service import CGNATService
from app.utils.logger import logger

router = APIRouter(prefix="/api/cgnat", tags=["CGNAT-PBA"])


@router.post("/blocks", response_model=CGNATPortBlockResponse, status_code=201)
async def create_cgnat_block(block: CGNATPortBlockCreate, db: Session = Depends(get_db)):
    """Ingest a single CGNAT PBA allocate/deallocate event (API / HSL bridge)."""
    try:
        return CGNATService.create_block(db, block)
    except Exception as e:
        logger.error(f"CGNAT create error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/blocks/bulk", status_code=201)
async def create_cgnat_blocks_bulk(body: CGNATBulkCreate, db: Session = Depends(get_db)):
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
    public_ip: str = Query(..., description="Public (post-NAT / outside) IP seen by security"),
    public_port: int = Query(..., ge=0, le=65535, description="Public port"),
    at: Optional[datetime] = Query(
        None,
        description="Time of the incident (ISO8601). Default: now (UTC).",
    ),
    db: Session = Depends(get_db),
):
    """
    Security lookup: map public_ip:public_port → subscriber (inside) IP
    using CGNAT Port Block Allocation history.
    """
    return CGNATService.lookup(
        db,
        public_ip=public_ip,
        public_port=public_port,
        at_time=at,
    )
