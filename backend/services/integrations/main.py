"""
Integrations service — CRUD for tenant webhook/slack/email/pagerduty integrations,
plus a live connectivity test for each type.
"""
import json
import uuid
from typing import Any

import aiohttp
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field, HttpUrl
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.db import get_db, tenant_db
from backend.shared.models.integration import Integration
from backend.shared.tenant_context import TenantContext, require_tenant

app = FastAPI(title="integrations")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

VALID_TYPES = {"webhook", "slack", "email", "pagerduty"}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., pattern="^(webhook|slack|email|pagerduty)$")
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class IntegrationUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    config: dict[str, Any] | None = None
    enabled: bool | None = None


class IntegrationOut(BaseModel):
    id: str
    name: str
    type: str
    config: dict
    enabled: bool
    last_triggered_at: str | None
    created_at: str


# ---------------------------------------------------------------------------
# Serialiser
# ---------------------------------------------------------------------------

def _out(i: Integration) -> dict:
    return IntegrationOut(
        id=str(i.id),
        name=i.name,
        type=i.type,
        config=i.config or {},
        enabled=i.enabled,
        last_triggered_at=str(i.last_triggered_at) if i.last_triggered_at else None,
        created_at=str(i.created_at),
    ).model_dump()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

@app.get("/api/integrations")
async def list_integrations(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        rows = await db.execute(
            select(Integration)
            .where(Integration.tenant_id == ctx.tenant_id)
            .order_by(Integration.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        items = rows.scalars().all()
        total = await db.scalar(
            select(func.count(Integration.id)).where(Integration.tenant_id == ctx.tenant_id)
        )
    return {"total": total, "items": [_out(i) for i in items]}


@app.post("/api/integrations", status_code=201)
async def create_integration(
    body: IntegrationCreate,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        i = Integration(
            tenant_id=uuid.UUID(ctx.tenant_id),
            name=body.name,
            type=body.type,
            config=body.config,
            enabled=body.enabled,
        )
        db.add(i)
        await db.commit()
        await db.refresh(i)
    return _out(i)


@app.get("/api/integrations/{integration_id}")
async def get_integration(
    integration_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        i = await db.scalar(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.tenant_id == ctx.tenant_id,
            )
        )
    if not i:
        raise HTTPException(404, "integration not found")
    return _out(i)


@app.patch("/api/integrations/{integration_id}")
async def update_integration(
    integration_id: str,
    body: IntegrationUpdate,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        i = await db.scalar(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.tenant_id == ctx.tenant_id,
            )
        )
        if not i:
            raise HTTPException(404, "integration not found")
        if body.name is not None:
            i.name = body.name
        if body.config is not None:
            i.config = body.config
        if body.enabled is not None:
            i.enabled = body.enabled
        await db.commit()
        await db.refresh(i)
    return _out(i)


@app.delete("/api/integrations/{integration_id}", status_code=204)
async def delete_integration(
    integration_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        i = await db.scalar(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.tenant_id == ctx.tenant_id,
            )
        )
        if not i:
            raise HTTPException(404, "integration not found")
        await db.delete(i)
        await db.commit()


# ---------------------------------------------------------------------------
# Connectivity test
# ---------------------------------------------------------------------------

_TEST_PAYLOAD = {
    "event": "test",
    "title": "PhantomGrid connectivity test",
    "summary": "This is a test notification from PhantomGrid.",
    "severity": "info",
}


async def _test_webhook(cfg: dict) -> dict:
    url = cfg.get("url")
    if not url:
        return {"ok": False, "error": "url not configured"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                url,
                data=json.dumps(_TEST_PAYLOAD),
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"ok": resp.status < 400, "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _test_slack(cfg: dict) -> dict:
    webhook_url = cfg.get("webhook_url")
    if not webhook_url:
        return {"ok": False, "error": "webhook_url not configured"}
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                webhook_url,
                data=json.dumps({"text": ":white_check_mark: PhantomGrid connectivity test — OK"}),
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                return {"ok": resp.status < 400, "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _test_pagerduty(cfg: dict) -> dict:
    routing_key = cfg.get("routing_key")
    if not routing_key:
        return {"ok": False, "error": "routing_key not configured"}
    body = json.dumps({
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": "PhantomGrid connectivity test",
            "severity": "info",
            "source": "phantomgrid-integrations-test",
        },
    })
    try:
        async with aiohttp.ClientSession() as s:
            async with s.post(
                "https://events.pagerduty.com/v2/enqueue",
                data=body,
                headers={"Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=15),
            ) as resp:
                return {"ok": resp.status in (200, 202), "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _test_email(cfg: dict) -> dict:
    to_addrs = cfg.get("to") or []
    if not to_addrs:
        return {"ok": False, "error": "no 'to' addresses configured"}
    # Just validate config is present — actual send would require SMTP
    # which is already implemented in the notifications service.
    return {"ok": True, "note": "email config looks valid; actual delivery handled by notifications service"}


@app.post("/api/integrations/{integration_id}/test")
async def test_integration(
    integration_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        i = await db.scalar(
            select(Integration).where(
                Integration.id == integration_id,
                Integration.tenant_id == ctx.tenant_id,
            )
        )
    if not i:
        raise HTTPException(404, "integration not found")

    cfg = i.config or {}
    t = i.type
    if t == "webhook":
        result = await _test_webhook(cfg)
    elif t == "slack":
        result = await _test_slack(cfg)
    elif t == "pagerduty":
        result = await _test_pagerduty(cfg)
    elif t == "email":
        result = await _test_email(cfg)
    else:
        raise HTTPException(400, f"unknown integration type: {t}")

    return {"integration_id": integration_id, "type": t, **result}
