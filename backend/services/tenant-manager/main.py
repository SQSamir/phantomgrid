import asyncio
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import FastAPI, Depends, HTTPException, Query
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.db import get_db, tenant_db
from backend.shared.models.tenant import Tenant
from backend.shared.models.user import User
from backend.shared.tenant_context import TenantContext, require_tenant

app = FastAPI(title="tenant-manager")
pwd = CryptContext(schemes=["argon2"], deprecated="auto")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _require_super_admin(ctx: TenantContext) -> None:
    if ctx.role != "super_admin":
        raise HTTPException(403, "super_admin role required")


def _require_admin_or_super(ctx: TenantContext, tenant_id: str) -> None:
    """Allow super_admin anywhere; tenant_admin only within their own tenant."""
    if ctx.role == "super_admin":
        return
    if ctx.role == "tenant_admin" and ctx.tenant_id == tenant_id:
        return
    raise HTTPException(403, "insufficient permissions")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class TenantCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    plan: str = Field("enterprise", max_length=64)
    max_decoys: int = Field(1000, ge=1)
    max_events_per_day: int = Field(10_000_000, ge=1)
    mfa_required: bool = False


class TenantUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    plan: str | None = Field(None, max_length=64)
    max_decoys: int | None = Field(None, ge=1)
    max_events_per_day: int | None = Field(None, ge=1)
    mfa_required: bool | None = None


class TenantOut(BaseModel):
    id: str
    name: str
    plan: str
    max_decoys: int
    max_events_per_day: int
    mfa_required: bool
    created_at: str
    suspended_at: str | None


class UserCreate(BaseModel):
    email: EmailStr
    display_name: str | None = Field(None, max_length=255)
    role: str = Field("analyst", pattern="^(tenant_admin|analyst|readonly)$")


class UserUpdate(BaseModel):
    display_name: str | None = Field(None, max_length=255)
    role: str | None = Field(None, pattern="^(tenant_admin|analyst|readonly)$")


class UserOut(BaseModel):
    id: str
    email: str
    display_name: str | None
    role: str
    mfa_enabled: bool
    created_at: str
    deactivated_at: str | None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _tenant_out(t: Tenant) -> dict:
    return TenantOut(
        id=str(t.id),
        name=t.name,
        plan=t.plan,
        max_decoys=t.max_decoys,
        max_events_per_day=t.max_events_per_day,
        mfa_required=t.mfa_required,
        created_at=str(t.created_at),
        suspended_at=str(t.suspended_at) if t.suspended_at else None,
    ).model_dump()


def _user_out(u: User) -> dict:
    return UserOut(
        id=str(u.id),
        email=u.email,
        display_name=u.display_name,
        role=u.role,
        mfa_enabled=u.mfa_enabled,
        created_at=str(u.created_at),
        deactivated_at=str(u.deactivated_at) if u.deactivated_at else None,
    ).model_dump()


async def _hash_password(password: str) -> str:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, pwd.hash, password)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Tenant CRUD (super_admin only)
# ---------------------------------------------------------------------------

@app.get("/api/tenants")
async def list_tenants(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_super_admin(ctx)
    rows = await db.execute(
        select(Tenant).order_by(Tenant.created_at.desc()).offset(offset).limit(limit)
    )
    tenants = rows.scalars().all()
    total = await db.scalar(select(func.count(Tenant.id)))
    return {"total": total, "items": [_tenant_out(t) for t in tenants]}


@app.post("/api/tenants", status_code=201)
async def create_tenant(
    body: TenantCreate,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_super_admin(ctx)
    t = Tenant(
        name=body.name,
        plan=body.plan,
        max_decoys=body.max_decoys,
        max_events_per_day=body.max_events_per_day,
        mfa_required=body.mfa_required,
    )
    db.add(t)
    await db.commit()
    await db.refresh(t)
    return _tenant_out(t)


@app.get("/api/tenants/{tenant_id}")
async def get_tenant(
    tenant_id: str,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_admin_or_super(ctx, tenant_id)
    t = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not t:
        raise HTTPException(404, "tenant not found")
    return _tenant_out(t)


@app.patch("/api/tenants/{tenant_id}")
async def update_tenant(
    tenant_id: str,
    body: TenantUpdate,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_super_admin(ctx)
    t = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not t:
        raise HTTPException(404, "tenant not found")
    if body.name is not None:
        t.name = body.name
    if body.plan is not None:
        t.plan = body.plan
    if body.max_decoys is not None:
        t.max_decoys = body.max_decoys
    if body.max_events_per_day is not None:
        t.max_events_per_day = body.max_events_per_day
    if body.mfa_required is not None:
        t.mfa_required = body.mfa_required
    await db.commit()
    await db.refresh(t)
    return _tenant_out(t)


@app.post("/api/tenants/{tenant_id}/suspend")
async def suspend_tenant(
    tenant_id: str,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_super_admin(ctx)
    t = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not t:
        raise HTTPException(404, "tenant not found")
    if t.suspended_at:
        raise HTTPException(409, "tenant already suspended")
    t.suspended_at = _now()
    await db.commit()
    return {"suspended": True, "suspended_at": str(t.suspended_at)}


@app.post("/api/tenants/{tenant_id}/unsuspend")
async def unsuspend_tenant(
    tenant_id: str,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_super_admin(ctx)
    t = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not t:
        raise HTTPException(404, "tenant not found")
    if not t.suspended_at:
        raise HTTPException(409, "tenant is not suspended")
    t.suspended_at = None
    await db.commit()
    return {"suspended": False}


# ---------------------------------------------------------------------------
# User management (tenant_admin within own tenant; super_admin anywhere)
# ---------------------------------------------------------------------------

@app.get("/api/tenants/{tenant_id}/users")
async def list_users(
    tenant_id: str,
    include_deactivated: bool = Query(False),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_admin_or_super(ctx, tenant_id)
    q = select(User).where(User.tenant_id == tenant_id)
    if not include_deactivated:
        q = q.where(User.deactivated_at.is_(None))
    q = q.order_by(User.created_at.desc()).offset(offset).limit(limit)
    rows = await db.execute(q)
    users = rows.scalars().all()
    count_q = select(func.count(User.id)).where(User.tenant_id == tenant_id)
    if not include_deactivated:
        count_q = count_q.where(User.deactivated_at.is_(None))
    total = await db.scalar(count_q)
    return {"total": total, "items": [_user_out(u) for u in users]}


@app.post("/api/tenants/{tenant_id}/users", status_code=201)
async def create_user(
    tenant_id: str,
    body: UserCreate,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_admin_or_super(ctx, tenant_id)

    # Tenant must exist and not be suspended
    t = await db.scalar(select(Tenant).where(Tenant.id == tenant_id))
    if not t:
        raise HTTPException(404, "tenant not found")
    if t.suspended_at:
        raise HTTPException(403, "tenant is suspended")

    exists = await db.scalar(select(User).where(User.email == body.email))
    if exists:
        raise HTTPException(409, "email already in use")

    # Generate a random initial password — caller must deliver it out-of-band
    # (e.g. via the notifications service). Not returned after this response.
    temp_password = secrets.token_urlsafe(24)
    hashed = await _hash_password(temp_password)

    u = User(
        tenant_id=uuid.UUID(tenant_id),
        email=str(body.email),
        password_hash=hashed,
        role=body.role,
        display_name=body.display_name,
    )
    db.add(u)
    await db.commit()
    await db.refresh(u)
    return {**_user_out(u), "temp_password": temp_password}


@app.patch("/api/tenants/{tenant_id}/users/{user_id}")
async def update_user(
    tenant_id: str,
    user_id: str,
    body: UserUpdate,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_admin_or_super(ctx, tenant_id)
    u = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    if not u:
        raise HTTPException(404, "user not found")
    if u.deactivated_at:
        raise HTTPException(409, "user is deactivated")
    if body.display_name is not None:
        u.display_name = body.display_name
    if body.role is not None:
        # tenant_admin cannot escalate to super_admin
        if ctx.role != "super_admin" and body.role == "super_admin":
            raise HTTPException(403, "cannot assign super_admin role")
        u.role = body.role
    await db.commit()
    await db.refresh(u)
    return _user_out(u)


@app.delete("/api/tenants/{tenant_id}/users/{user_id}", status_code=200)
async def deactivate_user(
    tenant_id: str,
    user_id: str,
    ctx: TenantContext = Depends(require_tenant),
    db: AsyncSession = Depends(get_db),
):
    _require_admin_or_super(ctx, tenant_id)
    if ctx.user_id == user_id:
        raise HTTPException(400, "cannot deactivate your own account")
    u = await db.scalar(
        select(User).where(User.id == user_id, User.tenant_id == tenant_id)
    )
    if not u:
        raise HTTPException(404, "user not found")
    if u.deactivated_at:
        raise HTTPException(409, "user already deactivated")
    u.deactivated_at = _now()
    await db.commit()
    return {"deactivated": True, "user_id": user_id}


# ---------------------------------------------------------------------------
# Tenant stats (tenant_admin within own tenant; super_admin anywhere)
# ---------------------------------------------------------------------------

@app.get("/api/tenants/{tenant_id}/stats")
async def tenant_stats(
    tenant_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    _require_admin_or_super(ctx, tenant_id)
    from backend.shared.models.decoy import Decoy
    from backend.shared.models.event import Event
    from backend.shared.models.alert import Alert

    async with tenant_db(tenant_id) as db:
        user_count = await db.scalar(
            select(func.count(User.id)).where(
                User.tenant_id == tenant_id,
                User.deactivated_at.is_(None),
            )
        )
        active_decoys = await db.scalar(
            select(func.count(Decoy.id)).where(
                Decoy.tenant_id == tenant_id,
                Decoy.status == "active",
            )
        )
        total_events = await db.scalar(
            select(func.count(Event.id)).where(Event.tenant_id == tenant_id)
        )
        open_alerts = await db.scalar(
            select(func.count(Alert.id)).where(
                Alert.tenant_id == tenant_id,
                Alert.status == "new",
            )
        )
    return {
        "tenant_id": tenant_id,
        "active_users": user_count or 0,
        "active_decoys": active_decoys or 0,
        "total_events": total_events or 0,
        "open_alerts": open_alerts or 0,
    }
