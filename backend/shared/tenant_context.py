"""
Tenant context dependency for FastAPI services sitting behind the API gateway.

The gateway validates the JWT and injects:
  X-Tenant-ID   — the tenant UUID from the token's ``tid`` claim
  X-User-ID     — the user UUID from the token's ``sub`` claim
  X-User-Role   — the role string from the token's ``role`` claim

Downstream services MUST NOT re-validate the JWT; they trust these headers.
Requests that arrive without X-Tenant-ID are rejected with 401, which protects
against direct access that bypasses the gateway.
"""
from __future__ import annotations

from dataclasses import dataclass

from fastapi import Header, HTTPException


@dataclass(frozen=True)
class TenantContext:
    tenant_id: str
    user_id: str
    role: str


async def require_tenant(
    x_tenant_id: str = Header(default=""),
    x_user_id: str = Header(default=""),
    x_user_role: str = Header(default=""),
) -> TenantContext:
    """FastAPI dependency — raises 401 if gateway headers are absent."""
    if not x_tenant_id or not x_user_id:
        raise HTTPException(
            status_code=401,
            detail="missing tenant context — request must pass through the gateway",
        )
    return TenantContext(
        tenant_id=x_tenant_id,
        user_id=x_user_id,
        role=x_user_role,
    )
