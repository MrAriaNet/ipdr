from sqlalchemy import Column, Integer, String, DateTime, BigInteger, Float, Boolean, ForeignKey, Text, Enum
from sqlalchemy.sql import func
from app.database import Base
import enum


class BillingModel(str, enum.Enum):
    """Billing models"""
    PREPAID = "prepaid"
    POSTPAID = "postpaid"
    HYBRID = "hybrid"


class IPDRRecord(Base):
    """Main table for storing IPDR records"""
    __tablename__ = "ipdr_records"

    id = Column(Integer, primary_key=True, index=True)
    # Source information (IPv4 or IPv6 textual form)
    source_ip = Column(String(64), nullable=False, index=True)
    source_port = Column(Integer, nullable=False)
    # Destination information
    destination_ip = Column(String(64), nullable=False, index=True)
    destination_port = Column(Integer, nullable=False)
    # Addressing / L4 protocol metadata
    ip_version = Column(Integer, default=4, index=True)  # 4 or 6
    protocol_number = Column(Integer, index=True)  # IANA IP protocol number 0-255
    # Timestamps
    session_start_time = Column(DateTime(timezone=True), nullable=False, index=True)
    session_end_time = Column(DateTime(timezone=True), nullable=True)
    duration_seconds = Column(Integer, default=0)
    # Data volume
    bytes_uploaded = Column(BigInteger, default=0)
    bytes_downloaded = Column(BigInteger, default=0)
    total_bytes = Column(BigInteger, default=0)
    packets_uploaded = Column(BigInteger, default=0)
    packets_downloaded = Column(BigInteger, default=0)
    total_packets = Column(BigInteger, default=0)
    # Protocol and service information
    protocol = Column(String(32), nullable=False, index=True)  # TCP, UDP, ICMPv6, GRE, ...
    service_type = Column(String(50), index=True)  # HTTP, HTTPS, FTP, VoIP, etc.
    application_name = Column(String(100))  # Identified application name
    # DPI information
    dpi_classification = Column(Text)  # JSON string for DPI information
    user_agent = Column(String(500))
    # Billing information
    user_id = Column(String(100), index=True)
    billing_model = Column(Enum(BillingModel), default=BillingModel.POSTPAID)
    cost = Column(Float, default=0.0)
    # Security
    is_suspicious = Column(Boolean, default=False, index=True)
    threat_type = Column(String(100))
    security_flags = Column(Text)  # JSON string for security flags
    # Metadata
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    # Additional information
    additional_info = Column(Text)  # JSON string for additional information


class TrafficSummary(Base):
    """Traffic summary table for quick reporting"""
    __tablename__ = "traffic_summaries"

    id = Column(Integer, primary_key=True, index=True)
    date = Column(DateTime(timezone=True), nullable=False, index=True)
    hour = Column(Integer, nullable=False, index=True)
    user_id = Column(String(100), index=True)
    source_ip = Column(String(64), index=True)
    destination_ip = Column(String(64), index=True)
    protocol = Column(String(32), index=True)
    ip_version = Column(Integer, index=True)
    service_type = Column(String(50), index=True)
    total_bytes = Column(BigInteger, default=0)
    total_packets = Column(BigInteger, default=0)
    total_sessions = Column(Integer, default=0)
    total_duration = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SecurityEvent(Base):
    """Security events table"""
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True)
    event_time = Column(DateTime(timezone=True), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)  # attack, suspicious_activity, etc.
    severity = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    source_ip = Column(String(64), index=True)
    destination_ip = Column(String(64), index=True)
    description = Column(Text)
    ipdr_record_id = Column(Integer, ForeignKey("ipdr_records.id"), nullable=True)
    is_resolved = Column(Boolean, default=False, index=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


