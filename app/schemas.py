from pydantic import BaseModel, ConfigDict, Field
from datetime import datetime
from typing import Optional, Dict, Any, List
from app.models import BillingModel, CGNATEventType


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
    # Sampling (sFlow): total_bytes/packets are extrapolated when is_sampled and rate > 1
    is_sampled: bool = False
    sampling_rate: int = 1
    sampled_bytes: int = 0
    sampled_packets: int = 0
    sample_pool: Optional[int] = None
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
    content_hash: Optional[str] = None
    legal_hold: Optional[bool] = False
    hold_case_id: Optional[str] = None


class TrafficQuery(BaseModel):
    """Traffic search parameters"""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    protocol_number: Optional[int] = None
    ip_version: Optional[int] = None
    service_type: Optional[str] = None
    user_id: Optional[str] = None
    # When true: include sessions overlapping the window (not only started inside)
    session_overlap: bool = False
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


class CGNATPortBlockCreate(BaseModel):
    event_time: datetime
    event_type: CGNATEventType = CGNATEventType.ALLOCATE
    inside_ip: str
    outside_ip: str
    port_start: int = Field(..., ge=0, le=65535)
    port_end: int = Field(..., ge=0, le=65535)
    port_block_size: Optional[int] = None
    port_step: Optional[int] = Field(1, ge=1, le=65535)  # Cisco BPA scattered step (IE 363)
    protocol: Optional[str] = "ANY"
    protocol_number: Optional[int] = None
    ip_version: Optional[int] = 4
    vrf_id: Optional[int] = None
    nat_pool_name: Optional[str] = None
    subscriber_id: Optional[str] = None
    released_at: Optional[datetime] = None
    is_active: Optional[bool] = True
    router_ip: Optional[str] = None
    source: Optional[str] = "api"
    raw_nat_event: Optional[int] = None
    additional_info: Optional[Dict[str, Any]] = None
    mapping_mode: Optional[str] = "pba"  # pba | overload


class CGNATPortBlockResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_time: datetime
    event_type: CGNATEventType
    inside_ip: str
    outside_ip: str
    port_start: int
    port_end: int
    port_block_size: Optional[int]
    port_step: Optional[int] = 1
    protocol: Optional[str]
    protocol_number: Optional[int]
    ip_version: Optional[int]
    vrf_id: Optional[int]
    nat_pool_name: Optional[str]
    subscriber_id: Optional[str]
    released_at: Optional[datetime]
    is_active: bool
    router_ip: Optional[str]
    source: Optional[str]
    raw_nat_event: Optional[int]
    mapping_mode: Optional[str] = "pba"
    created_at: datetime


class CGNATMatchItem(BaseModel):
    inside_ip: str
    outside_ip: str
    port_start: int
    port_end: int
    port_block_size: Optional[int] = None
    port_step: Optional[int] = 1
    protocol: Optional[str] = None
    event_time: Optional[datetime] = None
    released_at: Optional[datetime] = None
    subscriber_id: Optional[str] = None
    block_id: Optional[int] = None
    mapping_mode: Optional[str] = "pba"


class CGNATLookupResponse(BaseModel):
    """
    Result of public_ip:port → subscriber mapping for security teams.

    PBA only — no NAT connection / XLATE / inside_port required.
    If multiple blocks overlap, ambiguous=True and matches lists all candidates.
    """
    found: bool
    public_ip: str
    public_port: int
    at_time: datetime
    inside_ip: Optional[str] = None
    outside_ip: Optional[str] = None
    port_start: Optional[int] = None
    port_end: Optional[int] = None
    port_block_size: Optional[int] = None
    port_step: Optional[int] = None
    protocol: Optional[str] = None
    event_time: Optional[datetime] = None
    released_at: Optional[datetime] = None
    subscriber_id: Optional[str] = None
    block_id: Optional[int] = None
    mapping_mode: Optional[str] = None
    match_count: int = 0
    ambiguous: bool = False
    matches: List[CGNATMatchItem] = []
    message: Optional[str] = None


class CGNATSubscriberBlockItem(BaseModel):
    block_id: int
    outside_ip: str
    port_start: int
    port_end: int
    port_block_size: Optional[int] = None
    port_step: Optional[int] = 1
    protocol: Optional[str] = None
    event_time: Optional[datetime] = None
    released_at: Optional[datetime] = None
    is_active: Optional[bool] = None
    subscriber_id: Optional[str] = None
    mapping_mode: Optional[str] = None


class CGNATSubscriberBlocksResponse(BaseModel):
    """Reverse PBA lookup: inside_ip → public port block(s) at a given time."""
    found: bool
    inside_ip: str
    at_time: datetime
    blocks: List[CGNATSubscriberBlockItem] = []
    message: Optional[str] = None


class CGNATBulkCreate(BaseModel):
    records: List[CGNATPortBlockCreate]


class SubscriberSessionCreate(BaseModel):
    framed_ip: str
    subscriber_id: str
    username: Optional[str] = None
    account_id: Optional[str] = None
    msisdn: Optional[str] = None
    imsi: Optional[str] = None
    mac: Optional[str] = None
    circuit_id: Optional[str] = None
    nas_ip: Optional[str] = None
    realm: Optional[str] = None
    session_id: Optional[str] = None
    valid_from: datetime
    valid_to: Optional[datetime] = None
    source: Optional[str] = "aaa"
    additional_info: Optional[Dict[str, Any]] = None


class SubscriberSessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    framed_ip: str
    subscriber_id: str
    username: Optional[str] = None
    account_id: Optional[str] = None
    msisdn: Optional[str] = None
    imsi: Optional[str] = None
    mac: Optional[str] = None
    circuit_id: Optional[str] = None
    nas_ip: Optional[str] = None
    realm: Optional[str] = None
    session_id: Optional[str] = None
    valid_from: datetime
    valid_to: Optional[datetime] = None
    source: Optional[str] = None
    created_at: datetime


class SubscriberResolveResponse(BaseModel):
    found: bool
    framed_ip: str
    at_time: datetime
    subscriber_id: Optional[str] = None
    username: Optional[str] = None
    account_id: Optional[str] = None
    msisdn: Optional[str] = None
    imsi: Optional[str] = None
    session_id: Optional[int] = None
    match_count: int = 0
    ambiguous: bool = False
    message: Optional[str] = None


class LEAInvestigateRequest(BaseModel):
    public_ip: str
    public_port: int = Field(..., ge=0, le=65535)
    at: datetime
    case_ref: Optional[str] = None
    window_seconds: int = Field(default=300, ge=0, le=86400)
    include_flows: bool = True
    resolve_subscriber: bool = True
    legal_hold: bool = False
    flow_limit: int = Field(default=500, ge=1, le=5000)


class LEAExportRequest(BaseModel):
    case_ref: str
    format: str = Field(default="json", pattern="^(json|csv|ndjson)$")
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    public_ip: Optional[str] = None
    public_port: Optional[int] = None
    at: Optional[datetime] = None
    legal_hold: bool = True
    limit: int = Field(default=10000, ge=1, le=100000)


class QueryAuditResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    event_time: datetime
    actor_id: str
    actor_role: Optional[str] = None
    action: str
    case_ref: Optional[str] = None
    client_ip: Optional[str] = None
    request_params: Optional[str] = None
    result_found: bool
    result_count: int
    result_summary: Optional[str] = None
    response_hash: Optional[str] = None
