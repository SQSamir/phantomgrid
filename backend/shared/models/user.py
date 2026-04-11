import uuid
from sqlalchemy import String, DateTime, Text, func, ForeignKey, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column
from ..db import Base

class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(32), default="tenant_admin")
    # mfa_secret stores a Fernet-encrypted TOTP base32 secret (not plaintext)
    mfa_secret: Mapped[str | None] = mapped_column(Text, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    # mfa_backup_codes: list of argon2-hashed single-use recovery codes
    mfa_backup_codes: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped = mapped_column(DateTime(timezone=True), server_default=func.now())
    deactivated_at: Mapped = mapped_column(DateTime(timezone=True), nullable=True)
