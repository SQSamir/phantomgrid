from datetime import datetime
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
from ..enums import Protocol, Severity

class RawEvent(BaseModel):
    event_id: UUID = Field(default_factory=uuid4)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    tenant_id: UUID
    decoy_id: UUID | None = None
    session_id: UUID | None = None
    source_ip: str
    source_port: int | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: Protocol
    event_type: str
    severity: Severity = Severity.MEDIUM
    raw_data: dict[str, Any] = Field(default_factory=dict)
    tags: list[str] = Field(default_factory=list)

class GeoEnrichment(BaseModel):
    country: str | None = None
    country_code: str | None = None
    city: str | None = None
    lat: float | None = None
    lon: float | None = None
    asn: str | None = None
    isp: str | None = None
    is_tor: bool = False
    is_vpn: bool = False
    abuse_score: int | None = None

class EnrichedEvent(RawEvent):
    enrichment: GeoEnrichment = Field(default_factory=GeoEnrichment)
    mitre_technique_ids: list[str] = Field(default_factory=list)
