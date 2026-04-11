import uuid
from sqlalchemy import String, DateTime, Boolean, func, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from ..db import Base


class Integration(Base):
    __tablename__ = "integrations"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    type: Mapped[str] = mapped_column(String(64), nullable=False)  # webhook | slack | pagerduty | email
    config: Mapped[dict] = mapped_column(JSONB, default=dict)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_triggered_at: Mapped = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped = mapped_column(DateTime(timezone=True), server_default=func.now())
