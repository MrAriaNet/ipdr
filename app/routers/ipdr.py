"""
API routes for IPDR records management
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from app.database import get_db
from app.schemas import (
    IPDRRecordCreate, IPDRRecordResponse, TrafficQuery, TrafficStatistics
)
from app.services.ipdr_service import IPDRService
from app.services.search_service import SearchService
from app.utils.logger import logger

router = APIRouter(prefix="/api/ipdr", tags=["IPDR"])


@router.get("/protocols")
async def list_protocols():
    """
    Export all supported IP protocol numbers and names (IANA).
    Collectors store every protocol seen; this list is the canonical mapping.
    """
    from app.collectors.protocols import all_protocols

    return {"count": len(all_protocols()), "protocols": all_protocols()}


@router.post("/records", response_model=IPDRRecordResponse, status_code=201)
async def create_ipdr_record(
    record: IPDRRecordCreate,
    db: Session = Depends(get_db)
):
    """
    Create a new IPDR record
    
    This endpoint is used to register network traffic details.
    """
    try:
        logger.info(f"Creating IPDR record: {record.source_ip} -> {record.destination_ip}")
        db_record = IPDRService.create_record(db, record)
        logger.info(f"IPDR record created successfully with ID: {db_record.id}")
        return db_record
    except Exception as e:
        logger.error(f"Error creating IPDR record: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Error creating record: {str(e)}")


@router.get("/records", response_model=List[IPDRRecordResponse])
async def get_ipdr_records(
    start_time: Optional[datetime] = Query(None, description="Start time"),
    end_time: Optional[datetime] = Query(None, description="End time"),
    source_ip: Optional[str] = Query(None, description="Source IPv4 or IPv6 address"),
    destination_ip: Optional[str] = Query(None, description="Destination IPv4 or IPv6 address"),
    source_port: Optional[int] = Query(None, ge=0, le=65535, description="Source port"),
    destination_port: Optional[int] = Query(None, ge=0, le=65535, description="Destination port"),
    protocol: Optional[str] = Query(None, description="Protocol name (TCP, UDP, ICMPv6, GRE, ...)"),
    protocol_number: Optional[int] = Query(None, description="IANA IP protocol number 0-255"),
    ip_version: Optional[int] = Query(None, description="IP version: 4 or 6"),
    service_type: Optional[str] = Query(None, description="Service type"),
    user_id: Optional[str] = Query(None, description="User ID"),
    session_overlap: bool = Query(False, description="Include sessions overlapping the time window"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records"),
    offset: int = Query(0, ge=0, description="Offset"),
    db: Session = Depends(get_db)
):
    """
    Get list of IPDR records with various filters
    """
    query = TrafficQuery(
        start_time=start_time,
        end_time=end_time,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        protocol_number=protocol_number,
        ip_version=ip_version,
        service_type=service_type,
        user_id=user_id,
        session_overlap=session_overlap,
        limit=limit,
        offset=offset
    )
    
    records = IPDRService.get_records(db, query)
    return records


@router.get("/records/{record_id}", response_model=IPDRRecordResponse)
async def get_ipdr_record(
    record_id: int,
    db: Session = Depends(get_db)
):
    """
    Get a specific IPDR record
    """
    from app.models import IPDRRecord
    
    record = db.query(IPDRRecord).filter(IPDRRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Record not found")
    
    return record


@router.get("/statistics", response_model=TrafficStatistics)
async def get_traffic_statistics(
    start_time: Optional[datetime] = Query(None, description="Start time"),
    end_time: Optional[datetime] = Query(None, description="End time"),
    source_ip: Optional[str] = Query(None, description="Source IPv4 or IPv6 address"),
    destination_ip: Optional[str] = Query(None, description="Destination IPv4 or IPv6 address"),
    protocol: Optional[str] = Query(None, description="Protocol"),
    protocol_number: Optional[int] = Query(None, description="IANA IP protocol number"),
    ip_version: Optional[int] = Query(None, description="IP version: 4 or 6"),
    service_type: Optional[str] = Query(None, description="Service type"),
    user_id: Optional[str] = Query(None, description="User ID"),
    db: Session = Depends(get_db)
):
    """
    Get traffic statistics based on filters
    """
    query = TrafficQuery(
        start_time=start_time,
        end_time=end_time,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        protocol_number=protocol_number,
        ip_version=ip_version,
        service_type=service_type,
        user_id=user_id
    )
    
    statistics = IPDRService.get_statistics(db, query)
    return statistics


@router.post("/summaries/create")
async def create_traffic_summary(
    date: Optional[datetime] = Query(None, description="Target date (default: today)"),
    db: Session = Depends(get_db)
):
    """
    Create traffic summary for a day
    """
    if not date:
        date = datetime.now()
    
    logger.info(f"Creating traffic summary for date: {date}")
    IPDRService.create_summary(db, date)
    logger.info("Traffic summary created successfully")
    return {"message": "Traffic summary created successfully", "date": date}


@router.get("/search", response_model=List[IPDRRecordResponse])
async def search_ipdr_records(
    search_query: Optional[str] = Query(None, description="Text search query (searches in IPs, ports, service type, etc.)"),
    start_time: Optional[datetime] = Query(None, description="Start time"),
    end_time: Optional[datetime] = Query(None, description="End time"),
    source_ip: Optional[str] = Query(None, description="Source IPv4 or IPv6 address"),
    destination_ip: Optional[str] = Query(None, description="Destination IPv4 or IPv6 address"),
    protocol: Optional[str] = Query(None, description="Protocol name"),
    protocol_number: Optional[int] = Query(None, description="IANA IP protocol number"),
    ip_version: Optional[int] = Query(None, description="IP version: 4 or 6"),
    service_type: Optional[str] = Query(None, description="Service type"),
    user_id: Optional[str] = Query(None, description="User ID"),
    is_suspicious: Optional[bool] = Query(None, description="Suspicious flag"),
    min_bytes: Optional[int] = Query(None, description="Minimum bytes"),
    max_bytes: Optional[int] = Query(None, description="Maximum bytes"),
    limit: int = Query(100, ge=1, le=1000, description="Number of records"),
    offset: int = Query(0, ge=0, description="Offset"),
    db: Session = Depends(get_db)
):
    """
    Advanced search for IPDR records with text search capability
    
    Supports searching across multiple fields including IP addresses, ports, 
    service types, application names, and user IDs.
    """
    logger.info(f"Advanced search requested: query='{search_query}', filters applied")
    try:
        records = SearchService.search_records(
            db=db,
            search_query=search_query,
            start_time=start_time,
            end_time=end_time,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            protocol_number=protocol_number,
            ip_version=ip_version,
            service_type=service_type,
            user_id=user_id,
            is_suspicious=is_suspicious,
            min_bytes=min_bytes,
            max_bytes=max_bytes,
            limit=limit,
            offset=offset
        )
        logger.info(f"Search returned {len(records)} records")
        return records
    except Exception as e:
        logger.error(f"Error in search: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")


@router.get("/search/count")
async def search_count(
    search_query: Optional[str] = Query(None, description="Text search query"),
    start_time: Optional[datetime] = Query(None, description="Start time"),
    end_time: Optional[datetime] = Query(None, description="End time"),
    source_ip: Optional[str] = Query(None, description="Source IPv4 or IPv6 address"),
    destination_ip: Optional[str] = Query(None, description="Destination IPv4 or IPv6 address"),
    protocol: Optional[str] = Query(None, description="Protocol"),
    protocol_number: Optional[int] = Query(None, description="IANA IP protocol number"),
    ip_version: Optional[int] = Query(None, description="IP version: 4 or 6"),
    service_type: Optional[str] = Query(None, description="Service type"),
    user_id: Optional[str] = Query(None, description="User ID"),
    is_suspicious: Optional[bool] = Query(None, description="Suspicious flag"),
    min_bytes: Optional[int] = Query(None, description="Minimum bytes"),
    max_bytes: Optional[int] = Query(None, description="Maximum bytes"),
    db: Session = Depends(get_db)
):
    """
    Get count of records matching search criteria
    """
    try:
        count = SearchService.search_count(
            db=db,
            search_query=search_query,
            start_time=start_time,
            end_time=end_time,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            protocol_number=protocol_number,
            ip_version=ip_version,
            service_type=service_type,
            user_id=user_id,
            is_suspicious=is_suspicious,
            min_bytes=min_bytes,
            max_bytes=max_bytes
        )
        return {"count": count}
    except Exception as e:
        logger.error(f"Error in search count: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Search error: {str(e)}")
