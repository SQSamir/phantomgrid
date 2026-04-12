"""
Analytics Service — aggregation queries for dashboard, reporting, and SOC workflows.

Endpoints:
  GET /api/analytics/overview              Dashboard summary with 24h vs prev-24h trends
  GET /api/analytics/events/timeline       Hourly event counts
  GET /api/analytics/events/by-protocol    Protocol breakdown
  GET /api/analytics/events/by-severity    Severity breakdown
  GET /api/analytics/top-attackers         Top source IPs with enrichment
  GET /api/analytics/alerts/trend          Daily alert counts by severity
  GET /api/analytics/sessions              List attacker sessions (SSH/Telnet)
  GET /api/analytics/sessions/{id}         Full session detail + command transcript
  GET /api/analytics/ioc-export            Download attacker IOCs as CSV
"""
import csv
import io
from datetime import datetime, timedelta, timezone

from fastapi import Depends, Query
from fastapi.responses import StreamingResponse
from fastapi import FastAPI
from sqlalchemy import select, func, text

from backend.shared.db import tenant_db
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


# ---------------------------------------------------------------------------
# Overview
# ---------------------------------------------------------------------------

@app.get("/api/analytics/overview")
async def overview(ctx: TenantContext = Depends(require_tenant)):
    async with tenant_db(ctx.tenant_id) as db:
        now      = datetime.now(timezone.utc)
        day_ago  = now - timedelta(days=1)
        two_days = now - timedelta(days=2)
        hour_ago = now - timedelta(hours=1)

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
        events_yesterday = await db.scalar(
            select(func.count(Event.id)).where(
                Event.tenant_id == ctx.tenant_id,
                Event.created_at >= two_days,
                Event.created_at < day_ago,
            )
        )
        open_alerts = await db.scalar(
            select(func.count(Alert.id)).where(
                Alert.tenant_id == ctx.tenant_id,
                Alert.status == "new",
            )
        )
        attackers_24h = await db.scalar(
            select(func.count(func.distinct(Event.source_ip))).where(
                Event.tenant_id == ctx.tenant_id,
                Event.created_at >= day_ago,
            )
        )
        attackers_prev = await db.scalar(
            select(func.count(func.distinct(Event.source_ip))).where(
                Event.tenant_id == ctx.tenant_id,
                Event.created_at >= two_days,
                Event.created_at < day_ago,
            )
        )
        critical_1h = await db.scalar(
            select(func.count(Event.id)).where(
                Event.tenant_id == ctx.tenant_id,
                Event.severity == "critical",
                Event.created_at >= hour_ago,
            )
        )

    def _trend(cur: int, prev: int) -> float | None:
        if prev == 0:
            return None
        return round((cur - prev) / prev * 100, 1)

    return {
        "active_decoys":          active_decoys or 0,
        "events_today":           events_today or 0,
        "events_yesterday":       events_yesterday or 0,
        "events_trend_pct":       _trend(events_today or 0, events_yesterday or 0),
        "open_alerts":            open_alerts or 0,
        "unique_attackers_24h":   attackers_24h or 0,
        "unique_attackers_prev":  attackers_prev or 0,
        "attackers_trend_pct":    _trend(attackers_24h or 0, attackers_prev or 0),
        "critical_events_1h":     critical_1h or 0,
    }


# ---------------------------------------------------------------------------
# Timeline
# ---------------------------------------------------------------------------

@app.get("/api/analytics/events/timeline")
async def events_timeline(
    hours: int = Query(24, ge=1, le=168),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = await db.execute(
            text("""
                SELECT date_trunc('hour', created_at) AS hour, COUNT(*) AS count
                FROM events
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY 1 ORDER BY 1
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        return [{"hour": str(r.hour), "count": r.count} for r in rows]


# ---------------------------------------------------------------------------
# Protocol / severity breakdown
# ---------------------------------------------------------------------------

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
                GROUP BY protocol ORDER BY count DESC LIMIT 20
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
                GROUP BY severity ORDER BY count DESC
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        return [{"severity": r.severity, "count": r.count} for r in rows]


# ---------------------------------------------------------------------------
# Top attackers
# ---------------------------------------------------------------------------

@app.get("/api/analytics/top-attackers")
async def top_attackers(
    hours: int = Query(24, ge=1, le=168),
    limit: int = Query(15, ge=1, le=100),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = await db.execute(
            text("""
                SELECT
                    source_ip::text                          AS source_ip,
                    COUNT(*)                                 AS event_count,
                    COUNT(DISTINCT protocol)                 AS protocols_hit,
                    array_agg(DISTINCT protocol)             AS protocols,
                    MAX(created_at)                          AS last_seen,
                    enrichment->>'country'                   AS country,
                    enrichment->>'country_code'              AS country_code,
                    enrichment->>'city'                      AS city,
                    enrichment->>'asn'                       AS asn,
                    enrichment->>'isp'                       AS isp,
                    (enrichment->>'lat')::float              AS lat,
                    (enrichment->>'lon')::float              AS lon,
                    bool_or((enrichment->>'is_tor')::boolean) AS is_tor
                FROM events
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY source_ip, enrichment->>'country', enrichment->>'country_code',
                         enrichment->>'city', enrichment->>'asn', enrichment->>'isp',
                         enrichment->>'lat', enrichment->>'lon'
                ORDER BY event_count DESC
                LIMIT :limit
            """),
            {"tid": str(ctx.tenant_id), "since": since, "limit": limit},
        )
        return [
            {
                "source_ip":     r.source_ip,
                "event_count":   r.event_count,
                "protocols_hit": r.protocols_hit,
                "protocols":     r.protocols or [],
                "last_seen":     str(r.last_seen),
                "country":       r.country,
                "country_code":  r.country_code,
                "city":          r.city,
                "asn":           r.asn,
                "isp":           r.isp,
                "lat":           r.lat,
                "lon":           r.lon,
                "is_tor":        bool(r.is_tor),
            }
            for r in rows
        ]


# ---------------------------------------------------------------------------
# Alerts trend
# ---------------------------------------------------------------------------

@app.get("/api/analytics/alerts/trend")
async def alerts_trend(
    days: int = Query(7, ge=1, le=30),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(days=days)
        rows = await db.execute(
            text("""
                SELECT date_trunc('day', first_seen_at) AS day,
                       severity, COUNT(*) AS count
                FROM alerts
                WHERE tenant_id = :tid AND first_seen_at >= :since
                GROUP BY 1, 2 ORDER BY 1, 2
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        return [{"day": str(r.day), "severity": r.severity, "count": r.count} for r in rows]


# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

@app.get("/api/analytics/sessions")
async def list_sessions(
    limit:    int = Query(50, ge=1, le=200),
    offset:   int = Query(0,  ge=0),
    protocol: str | None = Query(default=None),
    ctx: TenantContext = Depends(require_tenant),
):
    """
    List interactive sessions (SSH, Telnet) sorted by start time descending.
    Each row has: session_id, source_ip, protocol, started_at, ended_at, event_count.
    """
    async with tenant_db(ctx.tenant_id) as db:
        proto_filter = "AND protocol = :proto" if protocol else ""
        rows = await db.execute(
            text(f"""
                SELECT
                    session_id,
                    source_ip::text                   AS source_ip,
                    protocol,
                    MIN(created_at)                   AS started_at,
                    MAX(created_at)                   AS ended_at,
                    COUNT(*)                          AS event_count,
                    enrichment->>'country'            AS country,
                    enrichment->>'country_code'       AS country_code,
                    bool_or((enrichment->>'is_tor')::boolean) AS is_tor
                FROM events
                WHERE tenant_id = :tid
                  AND session_id IS NOT NULL
                  {proto_filter}
                GROUP BY session_id, source_ip, protocol,
                         enrichment->>'country', enrichment->>'country_code'
                ORDER BY started_at DESC
                OFFSET :offset LIMIT :limit
            """),
            {
                "tid": str(ctx.tenant_id),
                "offset": offset,
                "limit": limit,
                **( {"proto": protocol.upper()} if protocol else {} ),
            },
        )
        total_row = await db.scalar(
            text("""
                SELECT COUNT(DISTINCT session_id) FROM events
                WHERE tenant_id = :tid AND session_id IS NOT NULL
            """),
            {"tid": str(ctx.tenant_id)},
        )

    items = []
    for r in rows:
        started = r.started_at
        ended   = r.ended_at
        duration_s = int((ended - started).total_seconds()) if started and ended else 0
        items.append({
            "session_id":   str(r.session_id),
            "source_ip":    r.source_ip,
            "protocol":     r.protocol,
            "country":      r.country,
            "country_code": r.country_code,
            "is_tor":       bool(r.is_tor),
            "started_at":   started.isoformat() if started else None,
            "ended_at":     ended.isoformat() if ended else None,
            "duration_s":   duration_s,
            "event_count":  r.event_count,
        })
    return {"total": total_row or 0, "items": items}


@app.get("/api/analytics/sessions/{session_id}")
async def session_detail(
    session_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    """Return all events for a session plus the extracted command transcript."""
    async with tenant_db(ctx.tenant_id) as db:
        result = await db.execute(
            select(Event)
            .where(
                Event.tenant_id == ctx.tenant_id,
                Event.session_id == session_id,
            )
            .order_by(Event.created_at.asc())
        )
        events = result.scalars().all()

    if not events:
        from fastapi import HTTPException
        raise HTTPException(404, "session not found")

    # Extract transcript from session_closed event
    transcript: list = []
    credentials: dict = {}
    for ev in events:
        if ev.event_type == "session_closed" and ev.raw_data:
            transcript = ev.raw_data.get("transcript", [])
        if ev.event_type == "auth_attempt" and ev.raw_data and not credentials:
            credentials = {
                "username": ev.raw_data.get("username"),
                "password": ev.raw_data.get("password"),
            }

    first, last = events[0], events[-1]
    duration_s = int(
        (last.created_at - first.created_at).total_seconds()
    ) if first.created_at and last.created_at else 0

    return {
        "session_id":  session_id,
        "source_ip":   first.source_ip,
        "protocol":    first.protocol,
        "enrichment":  first.enrichment or {},
        "credentials": credentials,
        "started_at":  first.created_at.isoformat() if first.created_at else None,
        "ended_at":    last.created_at.isoformat() if last.created_at else None,
        "duration_s":  duration_s,
        "event_count": len(events),
        "transcript":  transcript,
        "events": [
            {
                "event_type": e.event_type,
                "severity":   e.severity,
                "raw_data":   e.raw_data,
                "created_at": e.created_at.isoformat() if e.created_at else None,
            }
            for e in events
        ],
    }


# ---------------------------------------------------------------------------
# IOC Export (CSV)
# ---------------------------------------------------------------------------

@app.get("/api/analytics/ioc-export")
async def ioc_export(
    hours: int = Query(168, ge=1, le=720),   # default 7 days
    ctx: TenantContext = Depends(require_tenant),
):
    """
    Stream a CSV of attacker IOCs: IP, country, ASN, protocols, event count,
    captured usernames, captured passwords, first/last seen.
    """
    async with tenant_db(ctx.tenant_id) as db:
        since = datetime.now(timezone.utc) - timedelta(hours=hours)
        rows = await db.execute(
            text("""
                SELECT
                    source_ip::text                                   AS ip,
                    enrichment->>'country'                            AS country,
                    enrichment->>'country_code'                       AS country_code,
                    enrichment->>'asn'                                AS asn,
                    enrichment->>'isp'                                AS isp,
                    bool_or((enrichment->>'is_tor')::boolean)         AS is_tor,
                    array_agg(DISTINCT protocol)                      AS protocols,
                    COUNT(*)                                          AS event_count,
                    MIN(created_at)                                   AS first_seen,
                    MAX(created_at)                                   AS last_seen,
                    array_agg(DISTINCT raw_data->>'username')
                        FILTER (WHERE raw_data->>'username' IS NOT NULL) AS usernames,
                    array_agg(DISTINCT raw_data->>'password')
                        FILTER (WHERE raw_data->>'password' IS NOT NULL) AS passwords
                FROM events
                WHERE tenant_id = :tid AND created_at >= :since
                GROUP BY source_ip, enrichment->>'country', enrichment->>'country_code',
                         enrichment->>'asn', enrichment->>'isp'
                ORDER BY event_count DESC
            """),
            {"tid": str(ctx.tenant_id), "since": since},
        )
        data = rows.mappings().all()

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "ip", "country", "country_code", "asn", "isp", "is_tor",
        "protocols", "event_count", "first_seen", "last_seen",
        "usernames", "passwords",
    ])
    for r in data:
        writer.writerow([
            r["ip"],
            r["country"] or "",
            r["country_code"] or "",
            r["asn"] or "",
            r["isp"] or "",
            "true" if r["is_tor"] else "false",
            "|".join(filter(None, r["protocols"] or [])),
            r["event_count"],
            str(r["first_seen"] or ""),
            str(r["last_seen"] or ""),
            "|".join(filter(None, r["usernames"] or [])),
            "|".join(filter(None, r["passwords"] or [])),
        ])
    buf.seek(0)

    filename = f"phantomgrid-ioc-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
