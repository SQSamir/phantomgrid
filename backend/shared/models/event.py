import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, func, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY, INET
from sqlalchemy.orm import Mapped, mapped_column
from ..db import Base

class Event(Base):
    __tablename__ = "events"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    decoy_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), index=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_ip: Mapped[str] = mapped_column(INET)
    source_port: Mapped[int | None] = mapped_column(Integer)
    destination_ip: Mapped[str | None] = mapped_column(INET)
    destination_port: Mapped[int | None] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(32))
    event_type: Mapped[str] = mapped_column(String(128))
    severity: Mapped[str] = mapped_column(String(16))
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    enrichment: Mapped[dict] = mapped_column(JSONB, default=dict)
    mitre_technique_ids: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
