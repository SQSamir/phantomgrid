import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Text, Integer, func, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from ..db import Base


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    # lure | bait | breadcrumb | honeytoken
    type: Mapped[str] = mapped_column(String(32), nullable=False)
    # login_page | aws_key | api_token | ssh_key | jwt_token | db_credentials |
    # bash_history | env_file | config_file | url_token | dns_token
    subtype: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Type-specific generated content (credentials, file text, token URLs, etc.)
    content: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    status: Mapped[str] = mapped_column(String(32), default="active")
    trigger_count: Mapped[int] = mapped_column(Integer, default=0)
    last_triggered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
