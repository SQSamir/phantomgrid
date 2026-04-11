from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Depends, Query
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.db import get_db, tenant_db
from backend.shared.models.alert import Alert
from backend.shared.models.decoy import Decoy
from backend.shared.models.event import Event
from backend.shared.tenant_context import TenantContext, require_tenant

app = FastAPI(title="analytics")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/api/analytics/overview")
async def overview(ctx: TenantContext = Depends(require_tenant)):
    async with tenant_db(ctx.tenant_id) as db:
        now = datetime.now(timezone.utc)
        day_ago = now - timedelta(days=1)

        active_decoys = await db.scalar(
            select(func.count(Decoy.id)).where(
                Decoy.tenant_id == ctx.tenant_id,
                Decoy.status == "active",
            )
        )
        events_today = await db.scalar(
            select(func.count(Event.id)).where(
                Event.tenant_id == ctx.tenant_id,
                Event.created_at >= day_ago,
            )
        )
        open_alerts = await db.scalar(
            select(func.count(Alert.id)).where(
                Alert.tenant_id == ctx.tenant_id,
                Alert.status == "new",
            )
        )
        # Distinct attacker IPs in last 24h
        attackers = await db.scalar(
            select(func.count(func.distinct(Event.source_ip))).where(
                Event.tenant_id == ctx.tenant_id,
                Event.created_at >= day_ago,
            )
        )
    return {
        "active_decoys": active_decoys or 0,
        "events_today": events_today or 0,
        "open_alerts": open_alerts or 0,
        "unique_attackers_24h": attackers or 0,
    }


@app.get("/api/analytics/events/timeline")
async def events_timeline(
    hours: int = Query(24, ge=1, le=168),
    ctx: TenantContext = Depends(require_tenant),
):
    """Return hourly event counts for the last N hours."""
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = await db.execute(
            text("""
                SELECT
                    date_trunc('hour', created_at) AS hour,
                    COUNT(*) AS count
                FROM events
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY 1
                ORDER BY 1
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        return [{"hour": str(r.hour), "count": r.count} for r in rows]


@app.get("/api/analytics/events/by-protocol")
async def events_by_protocol(
    hours: int = Query(24, ge=1, le=168),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = await db.execute(
            text("""
                SELECT protocol, COUNT(*) AS count
                FROM events
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY protocol
                ORDER BY count DESC
                LIMIT 20
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        return [{"protocol": r.protocol, "count": r.count} for r in rows]


@app.get("/api/analytics/events/by-severity")
async def events_by_severity(
    hours: int = Query(24, ge=1, le=168),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = await db.execute(
            text("""
                SELECT severity, COUNT(*) AS count
                FROM events
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY severity
                ORDER BY count DESC
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        return [{"severity": r.severity, "count": r.count} for r in rows]


@app.get("/api/analytics/top-attackers")
async def top_attackers(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(10, ge=1, le=50),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = await db.execute(
            text("""
                SELECT
                    source_ip,
                    COUNT(*) AS event_count,
                    COUNT(DISTINCT protocol) AS protocols_hit,
                    MAX(created_at) AS last_seen,
                    enrichment->>'country' AS country,
                    enrichment->>'asn' AS asn,
                    (enrichment->>'is_tor')::boolean AS is_tor
                FROM events
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY source_ip, enrichment->>'country', enrichment->>'asn', (enrichment->>'is_tor')::boolean
                ORDER BY event_count DESC
                LIMIT :limit
            """),
            {"tid": str(ctx.tenant_id), "since": since, "limit": limit},
        )
        return [
            {
                "source_ip": r.source_ip,
                "event_count": r.event_count,
                "protocols_hit": r.protocols_hit,
                "last_seen": str(r.last_seen),
                "country": r.country,
                "asn": r.asn,
                "is_tor": r.is_tor,
            }
            for r in rows
        ]


@app.get("/api/analytics/alerts/trend")
async def alerts_trend(
    days: int = Query(7, ge=1, le=30),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        rows = await db.execute(
            text("""
                SELECT
                    date_trunc('day', first_seen_at) AS day,
                    severity,
                    COUNT(*) AS count
                FROM alerts
                WHERE tenant_id = :tid AND first_seen_at >= :since
                GROUP BY 1, 2
                ORDER BY 1, 2
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        return [{"day": str(r.day), "severity": r.severity, "count": r.count} for r in rows]
