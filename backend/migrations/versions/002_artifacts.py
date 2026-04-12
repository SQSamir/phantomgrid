"""002_artifacts

Revision ID: 002_artifacts
Revises: 001_initial
Create Date: 2026-04-12
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID, JSONB

revision = "002_artifacts"
down_revision = "001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "artifacts",
        sa.Column("id", UUID(as_uuid=True), primary_key=True,
                  server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", UUID(as_uuid=True),
                  sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("subtype", sa.String(64), nullable=False),
        sa.Column("description", sa.Text, nullable=True),
        sa.Column("content", JSONB, nullable=False, server_default="'{}'"),
        sa.Column("status", sa.String(32), nullable=False, server_default="'active'"),
        sa.Column("trigger_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_artifacts_tenant_id", "artifacts", ["tenant_id"])
    op.create_index("ix_artifacts_type",      "artifacts", ["type"])
    # Index for fast honeytoken lookup by token_id stored in content JSONB
    op.execute(sa.text(
        "CREATE INDEX ix_artifacts_token_id ON artifacts ((content->>'token_id')) "
        "WHERE type = 'honeytoken'"
    ))


def downgrade() -> None:
    op.drop_table("artifacts")
