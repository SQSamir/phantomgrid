import uuid
from sqlalchemy import String, Integer, DateTime, func
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from ..db import Base

class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    plan: Mapped[str] = mapped_column(String(64), default="enterprise")
    max_decoys: Mapped[int] = mapped_column(Integer, default=1000)
    max_events_per_day: Mapped[int] = mapped_column(Integer, default=10_000_000)
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    created_at: Mapped = mapped_column(DateTime(timezone=True), server_default=func.now())
    suspended_at: Mapped = mapped_column(DateTime(timezone=True), nullable=True)
