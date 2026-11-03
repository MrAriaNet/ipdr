"""
IPDR records management service
"""
from sqlalchemy.orm import Session
from sqlalchemy import func, and_
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
import json

from app.models import IPDRRecord, TrafficSummary, SecurityEvent
from app.schemas import IPDRRecordCreate, TrafficQuery, TrafficStatistics
from app.dpi.packet_analyzer import PacketAnalyzer
from app.utils.logger import logger


class IPDRService:
    """IPDR management service"""

    @staticmethod
    def create_record(db: Session, record: IPDRRecordCreate, 
                     packet_data: Optional[bytes] = None) -> IPDRRecord:
        """
        Create a new IPDR record
        
        Args:
            db: Database session
            record: Record data
            packet_data: Packet data for DPI analysis (optional)
            
        Returns:
            Created record
        """
        # DPI analysis if packet data is available
        dpi_data = None
        if packet_data:
            dpi_analysis = PacketAnalyzer.analyze_packet(packet_data)
            dpi_data = dpi_analysis
            
            # Update information from DPI
            if dpi_analysis.get("service_type") and not record.service_type:
                record.service_type = dpi_analysis["service_type"]
            if dpi_analysis.get("application_name") and not record.application_name:
                record.application_name = dpi_analysis["application_name"]
            if dpi_analysis.get("is_suspicious"):
                record.is_suspicious = True
            if dpi_analysis.get("threat_indicators"):
                record.threat_type = ", ".join(dpi_analysis["threat_indicators"])
        
        # Create record
        logger.debug(f"Creating IPDR record: {record.source_ip}:{record.source_port} -> {record.destination_ip}:{record.destination_port}")
        db_record = IPDRRecord(
            source_ip=record.source_ip,
            source_port=record.source_port,
            destination_ip=record.destination_ip,
            destination_port=record.destination_port,
            ip_version=record.ip_version or 4,
            protocol_number=record.protocol_number,
            session_start_time=record.session_start_time,
            session_end_time=record.session_end_time,
            duration_seconds=record.duration_seconds,
            bytes_uploaded=record.bytes_uploaded,
            bytes_downloaded=record.bytes_downloaded,
            total_bytes=record.total_bytes,
            packets_uploaded=record.packets_uploaded,
            packets_downloaded=record.packets_downloaded,
            total_packets=record.total_packets,
            protocol=record.protocol,
            service_type=record.service_type,
            application_name=record.application_name,
            dpi_classification=json.dumps(dpi_data) if dpi_data else None,
            user_agent=record.user_agent,
            user_id=record.user_id,
            billing_model=record.billing_model,
            cost=record.cost,
            is_suspicious=record.is_suspicious,
            threat_type=record.threat_type,
            security_flags=json.dumps(record.security_flags) if record.security_flags else None,
            additional_info=json.dumps(record.additional_info) if record.additional_info else None,
        )
        
        db.add(db_record)
        db.commit()
        db.refresh(db_record)
        
        logger.info(f"IPDR record created: ID={db_record.id}, Bytes={db_record.total_bytes}, Suspicious={db_record.is_suspicious}")
        
        # Create security event if suspicious
        if record.is_suspicious:
            logger.warning(f"Suspicious activity detected in record {db_record.id}: {record.threat_type}")
            IPDRService._create_security_event(db, db_record, dpi_data)
        
        return db_record

    @staticmethod
    def _create_security_event(db: Session, record: IPDRRecord, dpi_data: Optional[Dict] = None):
        """Create security event for suspicious record"""
        severity = "medium"
        if dpi_data and dpi_data.get("threat_indicators"):
            if len(dpi_data["threat_indicators"]) > 2:
                severity = "high"
            if "suspicious_content" in dpi_data["threat_indicators"]:
                severity = "critical"
        
        event = SecurityEvent(
            event_time=record.session_start_time,
            event_type=record.threat_type or "suspicious_activity",
            severity=severity,
            source_ip=record.source_ip,
            destination_ip=record.destination_ip,
            description=f"Suspicious activity detected: {record.threat_type}",
            ipdr_record_id=record.id
        )
        db.add(event)
        db.commit()
        logger.warning(f"Security event created: {event.event_type} (severity: {severity}) for record {record.id}")

    @staticmethod
    def get_records(db: Session, query: TrafficQuery) -> List[IPDRRecord]:
        """
        Get IPDR records based on filters
        
        Args:
            db: Database session
            query: Search parameters
            
        Returns:
            List of records
        """
        query_obj = IPDRService._apply_query_filters(db.query(IPDRRecord), query)
        return query_obj.order_by(IPDRRecord.session_start_time.desc())\
                       .offset(query.offset)\
                       .limit(query.limit)\
                       .all()

    @staticmethod
    def _apply_query_filters(query_obj, query: TrafficQuery):
        """Apply TrafficQuery filters to an IPDRRecord query"""
        filters = []
        if query.start_time:
            filters.append(IPDRRecord.session_start_time >= query.start_time)
        if query.end_time:
            filters.append(IPDRRecord.session_start_time <= query.end_time)
        if query.source_ip:
            filters.append(IPDRRecord.source_ip == query.source_ip)
        if query.destination_ip:
            filters.append(IPDRRecord.destination_ip == query.destination_ip)
        if query.protocol:
            filters.append(IPDRRecord.protocol == query.protocol)
        if query.protocol_number is not None:
            filters.append(IPDRRecord.protocol_number == query.protocol_number)
        if query.ip_version is not None:
            filters.append(IPDRRecord.ip_version == query.ip_version)
        if query.service_type:
            filters.append(IPDRRecord.service_type == query.service_type)
        if query.user_id:
            filters.append(IPDRRecord.user_id == query.user_id)
        if filters:
            return query_obj.filter(and_(*filters))
        return query_obj

    @staticmethod
    def get_statistics(db: Session, query: TrafficQuery) -> TrafficStatistics:
        """
        Calculate traffic statistics using SQL aggregates
        
        Args:
            db: Database session
            query: Search parameters
            
        Returns:
            Traffic statistics
        """
        base = IPDRService._apply_query_filters(db.query(IPDRRecord), query)

        totals = base.with_entities(
            func.coalesce(func.sum(IPDRRecord.total_bytes), 0),
            func.coalesce(func.sum(IPDRRecord.total_packets), 0),
            func.count(IPDRRecord.id),
            func.coalesce(func.sum(IPDRRecord.duration_seconds), 0),
        ).one()

        total_bytes = int(totals[0])
        total_packets = int(totals[1])
        total_sessions = int(totals[2])
        total_duration = int(totals[3])

        def top_by(column, exclude_null: bool = False) -> Dict[str, int]:
            q = IPDRService._apply_query_filters(
                db.query(column, func.sum(IPDRRecord.total_bytes).label("bytes")),
                query,
            )
            if exclude_null:
                q = q.filter(column.isnot(None))
            rows = (
                q.group_by(column)
                .order_by(func.sum(IPDRRecord.total_bytes).desc())
                .limit(10)
                .all()
            )
            return {str(key): int(bytes_val or 0) for key, bytes_val in rows if key is not None}

        return TrafficStatistics(
            total_bytes=total_bytes,
            total_packets=total_packets,
            total_sessions=total_sessions,
            total_duration=total_duration,
            avg_bytes_per_session=total_bytes / total_sessions if total_sessions > 0 else 0,
            avg_packets_per_session=total_packets / total_sessions if total_sessions > 0 else 0,
            top_protocols=top_by(IPDRRecord.protocol),
            top_services=top_by(IPDRRecord.service_type, exclude_null=True),
            top_source_ips=top_by(IPDRRecord.source_ip),
            top_destination_ips=top_by(IPDRRecord.destination_ip),
        )

    @staticmethod
    def create_summary(db: Session, date: datetime):
        """
        Create traffic summary for a day
        
        Args:
            db: Database session
            date: Target date
        """
        start_of_day = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = start_of_day + timedelta(days=1)
        
        # Delete previous summaries for this day
        db.query(TrafficSummary).filter(
            and_(
                TrafficSummary.date >= start_of_day,
                TrafficSummary.date < end_of_day
            )
        ).delete()
        
        # Get day records
        records = db.query(IPDRRecord).filter(
            and_(
                IPDRRecord.session_start_time >= start_of_day,
                IPDRRecord.session_start_time < end_of_day
            )
        ).all()
        
        # Group by hour, IP, protocol and service
        summaries = {}
        for record in records:
            hour = record.session_start_time.hour
            key = (
                hour,
                record.user_id or "unknown",
                record.source_ip,
                record.destination_ip,
                record.protocol,
                record.service_type or "unknown"
            )
            
            if key not in summaries:
                summaries[key] = {
                    "date": start_of_day,
                    "hour": hour,
                    "user_id": record.user_id,
                    "source_ip": record.source_ip,
                    "destination_ip": record.destination_ip,
                    "protocol": record.protocol,
                    "service_type": record.service_type,
                    "total_bytes": 0,
                    "total_packets": 0,
                    "total_sessions": 0,
                    "total_duration": 0
                }
            
            summaries[key]["total_bytes"] += record.total_bytes
            summaries[key]["total_packets"] += record.total_packets
            summaries[key]["total_sessions"] += 1
            summaries[key]["total_duration"] += record.duration_seconds
        
        # Save summaries
        for summary_data in summaries.values():
            summary = TrafficSummary(**summary_data)
            db.add(summary)
        
        db.commit()
