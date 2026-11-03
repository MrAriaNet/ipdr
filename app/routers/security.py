"""
API routes for security events management
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.database import get_db
from app.schemas import SecurityEventCreate, SecurityEventResponse
from app.models import SecurityEvent
from app.utils.logger import logger

router = APIRouter(prefix="/api/security", tags=["Security"])


@router.get("/events", response_model=List[SecurityEventResponse])
async def get_security_events(
    start_time: Optional[datetime] = Query(None, description="Start time"),
    end_time: Optional[datetime] = Query(None, description="End time"),
    severity: Optional[str] = Query(None, description="Severity level (low, medium, high, critical)"),
    event_type: Optional[str] = Query(None, description="Event type"),
    is_resolved: Optional[bool] = Query(None, description="Resolution status"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """
    Get list of security events
    """
    query = db.query(SecurityEvent)
    
    if start_time:
        query = query.filter(SecurityEvent.event_time >= start_time)
    if end_time:
        query = query.filter(SecurityEvent.event_time <= end_time)
    if severity:
        query = query.filter(SecurityEvent.severity == severity)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    if is_resolved is not None:
        query = query.filter(SecurityEvent.is_resolved == is_resolved)
    
    events = query.order_by(SecurityEvent.event_time.desc())\
                  .offset(offset)\
                  .limit(limit)\
                  .all()
    
    return events


@router.post("/events", response_model=SecurityEventResponse, status_code=201)
async def create_security_event(
    event: SecurityEventCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new security event
    """
    db_event = SecurityEvent(
        event_time=datetime.now(),
        event_type=event.event_type,
        severity=event.severity,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        description=event.description,
        ipdr_record_id=event.ipdr_record_id
    )
    
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    
    return db_event


@router.patch("/events/{event_id}/resolve")
async def resolve_security_event(
    event_id: int,
    db: Session = Depends(get_db)
):
    """
    Resolve a security event
    """
    event = db.query(SecurityEvent).filter(SecurityEvent.id == event_id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    event.is_resolved = True
    event.resolved_at = datetime.now()
    
    db.commit()
    db.refresh(event)
    
    return {"message": "Event resolved successfully", "event": event}
