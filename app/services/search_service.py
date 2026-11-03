"""
Advanced search service for IPDR records
"""
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, func, cast, String
from typing import List, Optional, Dict, Any
from datetime import datetime

from app.models import IPDRRecord
from app.schemas import TrafficQuery


class SearchService:
    """Advanced search service"""

    @staticmethod
    def search_records(
        db: Session,
        search_query: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        protocol_number: Optional[int] = None,
        ip_version: Optional[int] = None,
        service_type: Optional[str] = None,
        user_id: Optional[str] = None,
        is_suspicious: Optional[bool] = None,
        min_bytes: Optional[int] = None,
        max_bytes: Optional[int] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[IPDRRecord]:
        """
        Advanced search for IPDR records with text search capability
        
        Args:
            db: Database session
            search_query: Text search query (searches in IPs, ports, service type, application name)
            start_time: Start time filter
            end_time: End time filter
            source_ip: Source IP filter
            destination_ip: Destination IP filter
            protocol: Protocol filter
            service_type: Service type filter
            user_id: User ID filter
            is_suspicious: Suspicious flag filter
            min_bytes: Minimum bytes filter
            max_bytes: Maximum bytes filter
            limit: Maximum number of records
            offset: Offset for pagination
            
        Returns:
            List of matching records
        """
        query = db.query(IPDRRecord)
        filters = []
        
        # Text search across multiple fields
        if search_query:
            search_pattern = f"%{search_query}%"
            text_filters = [
                IPDRRecord.source_ip.ilike(search_pattern),
                IPDRRecord.destination_ip.ilike(search_pattern),
                IPDRRecord.service_type.ilike(search_pattern),
                IPDRRecord.application_name.ilike(search_pattern),
                IPDRRecord.user_id.ilike(search_pattern),
                IPDRRecord.threat_type.ilike(search_pattern),
                cast(IPDRRecord.source_port, String).ilike(search_pattern),
                cast(IPDRRecord.destination_port, String).ilike(search_pattern),
            ]
            filters.append(or_(*text_filters))
        
        # Time filters
        if start_time:
            filters.append(IPDRRecord.session_start_time >= start_time)
        if end_time:
            filters.append(IPDRRecord.session_start_time <= end_time)
        
        # IP filters
        if source_ip:
            filters.append(IPDRRecord.source_ip == source_ip)
        if destination_ip:
            filters.append(IPDRRecord.destination_ip == destination_ip)
        
        # Protocol and service filters
        if protocol:
            filters.append(IPDRRecord.protocol == protocol)
        if protocol_number is not None:
            filters.append(IPDRRecord.protocol_number == protocol_number)
        if ip_version is not None:
            filters.append(IPDRRecord.ip_version == ip_version)
        if service_type:
            filters.append(IPDRRecord.service_type == service_type)
        if user_id:
            filters.append(IPDRRecord.user_id == user_id)
        
        # Security filter
        if is_suspicious is not None:
            filters.append(IPDRRecord.is_suspicious == is_suspicious)
        
        # Byte range filters
        if min_bytes is not None:
            filters.append(IPDRRecord.total_bytes >= min_bytes)
        if max_bytes is not None:
            filters.append(IPDRRecord.total_bytes <= max_bytes)
        
        # Apply all filters
        if filters:
            query = query.filter(and_(*filters))
        
        # Order and paginate
        return query.order_by(IPDRRecord.session_start_time.desc())\
                   .offset(offset)\
                   .limit(limit)\
                   .all()

    @staticmethod
    def search_count(
        db: Session,
        search_query: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        protocol_number: Optional[int] = None,
        ip_version: Optional[int] = None,
        service_type: Optional[str] = None,
        user_id: Optional[str] = None,
        is_suspicious: Optional[bool] = None,
        min_bytes: Optional[int] = None,
        max_bytes: Optional[int] = None
    ) -> int:
        """
        Count matching records for search query
        
        Args:
            db: Database session
            search_query: Text search query
            Other parameters same as search_records
            
        Returns:
            Count of matching records
        """
        query = db.query(IPDRRecord)
        filters = []
        
        # Text search
        if search_query:
            search_pattern = f"%{search_query}%"
            text_filters = [
                IPDRRecord.source_ip.ilike(search_pattern),
                IPDRRecord.destination_ip.ilike(search_pattern),
                IPDRRecord.service_type.ilike(search_pattern),
                IPDRRecord.application_name.ilike(search_pattern),
                IPDRRecord.user_id.ilike(search_pattern),
                IPDRRecord.threat_type.ilike(search_pattern),
                cast(IPDRRecord.source_port, String).ilike(search_pattern),
                cast(IPDRRecord.destination_port, String).ilike(search_pattern),
            ]
            filters.append(or_(*text_filters))
        
        # Apply same filters as search_records
        if start_time:
            filters.append(IPDRRecord.session_start_time >= start_time)
        if end_time:
            filters.append(IPDRRecord.session_start_time <= end_time)
        if source_ip:
            filters.append(IPDRRecord.source_ip == source_ip)
        if destination_ip:
            filters.append(IPDRRecord.destination_ip == destination_ip)
        if protocol:
            filters.append(IPDRRecord.protocol == protocol)
        if protocol_number is not None:
            filters.append(IPDRRecord.protocol_number == protocol_number)
        if ip_version is not None:
            filters.append(IPDRRecord.ip_version == ip_version)
        if service_type:
            filters.append(IPDRRecord.service_type == service_type)
        if user_id:
            filters.append(IPDRRecord.user_id == user_id)
        if is_suspicious is not None:
            filters.append(IPDRRecord.is_suspicious == is_suspicious)
        if min_bytes is not None:
            filters.append(IPDRRecord.total_bytes >= min_bytes)
        if max_bytes is not None:
            filters.append(IPDRRecord.total_bytes <= max_bytes)
        
        if filters:
            query = query.filter(and_(*filters))
        
        return query.count()

