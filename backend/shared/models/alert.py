import uuid
from sqlalchemy import String, DateTime, func, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import Mapped, mapped_column
from ..db import Base

class AlertRule(Base):
    __tablename__ = "alert_rules"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str | None] = mapped_column(String(255))
    type: Mapped[str] = mapped_column(String(32))
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped = mapped_column(DateTime(timezone=True), nullable=True)
    suppression_minutes: Mapped[int] = mapped_column(Integer, default=5)
    created_at: Mapped = mapped_column(DateTime(timezone=True), server_default=func.now())

class Alert(Base):
    __tablename__ = "alerts"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), index=True)
    rule_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="new")
    title: Mapped[str] = mapped_column(String(255))
    summary: Mapped[str] = mapped_column(String(1024))
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_country: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_asn: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_technique_ids: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=1)
    first_seen_at: Mapped = mapped_column(DateTime(timezone=True), server_default=func.now())
    last_seen_at: Mapped = mapped_column(DateTime(timezone=True), server_default=func.now())
