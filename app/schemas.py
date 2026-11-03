from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Optional, Dict, Any
from app.models import BillingModel


class IPDRRecordBase(BaseModel):
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    session_start_time: datetime
    session_end_time: Optional[datetime] = None
    duration_seconds: int = 0
    bytes_uploaded: int = 0
    bytes_downloaded: int = 0
    total_bytes: int = 0
    packets_uploaded: int = 0
    packets_downloaded: int = 0
    total_packets: int = 0
    protocol: str
    protocol_number: Optional[int] = None
    ip_version: Optional[int] = 4
    service_type: Optional[str] = None
    application_name: Optional[str] = None
    user_id: Optional[str] = None
    billing_model: Optional[BillingModel] = BillingModel.POSTPAID
    cost: float = 0.0
    is_suspicious: bool = False
    threat_type: Optional[str] = None


class IPDRRecordCreate(IPDRRecordBase):
    dpi_classification: Optional[Dict[str, Any]] = None
    user_agent: Optional[str] = None
    security_flags: Optional[Dict[str, Any]] = None
    additional_info: Optional[Dict[str, Any]] = None


class IPDRRecordResponse(IPDRRecordBase):
    model_config = ConfigDict(from_attributes=True)

    id: int
    created_at: datetime
    updated_at: Optional[datetime] = None


class TrafficQuery(BaseModel):
    """Traffic search parameters"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    protocol: Optional[str] = None
    protocol_number: Optional[int] = None
    ip_version: Optional[int] = None
    service_type: Optional[str] = None
    user_id: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)
    offset: int = Field(default=0, ge=0)


class TrafficStatistics(BaseModel):
    """Traffic statistics"""
    total_bytes: int
    total_packets: int
    total_sessions: int
    total_duration: int
    avg_bytes_per_session: float
    avg_packets_per_session: float
    top_protocols: Dict[str, int]
    top_services: Dict[str, int]
    top_source_ips: Dict[str, int]
    top_destination_ips: Dict[str, int]


class SecurityEventCreate(BaseModel):
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    description: str
    ipdr_record_id: Optional[int] = None


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_time: datetime
    event_type: str
    severity: str
    source_ip: Optional[str]
    destination_ip: Optional[str]
    description: str
    is_resolved: bool
    created_at: datetime
