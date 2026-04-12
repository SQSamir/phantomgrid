"""
Event Processor — enriches raw honeypot events and persists them to the DB.

Kafka consumer:  events.raw  →  enrich  →  events.enriched  (+ DB insert)

HTTP API:
  GET  /api/events          paginated list, filterable by severity / protocol / source_ip
  GET  /api/events/{id}     single event detail
  GET  /health
  GET  /metrics             Prometheus
"""
import asyncio
import ipaddress
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

import httpx
import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from fastapi import Depends, FastAPI, HTTPException, Query
from sqlalchemy import func, select, cast, String

from backend.shared.db import tenant_db
from backend.shared.kafka import create_consumer, create_producer, send_json
from backend.shared.mitre_map import get_techniques
from backend.shared.models.event import Event
from backend.shared.redis_client import get_redis
from backend.shared.tenant_context import TenantContext, require_tenant

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Kafka background worker
# ---------------------------------------------------------------------------

_consumer: AIOKafkaConsumer | None = None
_producer: AIOKafkaProducer | None = None
_worker_task: asyncio.Task | None = None


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


async def _geoip(ip: str) -> dict:
    """Real GeoIP via ip-api.com with 24-hour Redis caching."""
    if _is_private(ip):
        return {}
    r = get_redis()
    cache_key = f"geoip:{ip}"
    cached = await r.get(cache_key)
    if cached:
        try:
            return json.loads(cached)
        except Exception:
            pass
    try:
        async with httpx.AsyncClient(timeout=3.0) as c:
            resp = await c.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": "status,country,countryCode,regionName,city,lat,lon,isp,org,as"
                },
            )
            if resp.status_code == 200:
                d = resp.json()
                if d.get("status") == "success":
                    geo = {
                        "country":      d.get("country"),
                        "country_code": d.get("countryCode"),
                        "city":         d.get("city"),
                        "region":       d.get("regionName"),
                        "lat":          d.get("lat"),
                        "lon":          d.get("lon"),
                        "isp":          d.get("isp"),
                        "asn":          d.get("as"),
                    }
                    await r.setex(cache_key, 86400, json.dumps(geo))
                    return geo
    except Exception as exc:
        log.warning("geoip_lookup_failed", ip=ip, error=str(exc))
    # Cache negative result for 1 hour to avoid hammering the free API
    await r.setex(cache_key, 3600, json.dumps({"country": "Unknown"}))
    return {"country": "Unknown"}


async def _abuse_score(ip: str) -> int:
    """AbuseIPDB stub — returns 0 until an API key is configured."""
    if _is_private(ip):
        return 0
    r = get_redis()
    k = f"abuse:{ip}"
    cached = await r.get(k)
    if cached is not None:
        return int(cached)
    score = 0
    # TODO: plug in real AbuseIPDB key via ABUSEIPDB_API_KEY env var
    await r.setex(k, 24 * 3600, str(score))
    return score


async def _is_tor_exit(ip: str) -> bool:
    if _is_private(ip):
        return False
    r = get_redis()
    return bool(await r.sismember("tor:exit_nodes", ip))


async def _enrich(event: dict) -> dict:
    ip = event.get("source_ip", "0.0.0.0")
    private = _is_private(ip)

    geo = {} if private else await _geoip(ip)

    event["enrichment"] = {
        **geo,
        "is_tor":       await _is_tor_exit(ip),
        "is_vpn":       False,
        "abuse_score":  await _abuse_score(ip),
        "enriched_at":  datetime.now(timezone.utc).isoformat(),
    }
    event["mitre_technique_ids"] = get_techniques(
        event.get("protocol", ""), event.get("event_type", "")
    )
    return event


async def _persist_event(event: dict) -> None:
    tenant_id = str(event.get("tenant_id", ""))
    if not tenant_id:
        return
    event_id = str(event.get("event_id") or uuid.uuid4())
    try:
        async with tenant_db(tenant_id) as session:
            row = Event(
                id=event_id,
                tenant_id=tenant_id,
                decoy_id=event.get("decoy_id"),
                session_id=event.get("session_id"),
                source_ip=event.get("source_ip", "0.0.0.0"),
                source_port=event.get("source_port"),
                destination_ip=event.get("destination_ip"),
                destination_port=event.get("destination_port"),
                protocol=event.get("protocol", ""),
                event_type=event.get("event_type", ""),
                severity=event.get("severity", "low"),
                raw_data=event.get("raw_data", {}),
                enrichment=event.get("enrichment", {}),
                mitre_technique_ids=event.get("mitre_technique_ids", []),
                tags=event.get("tags", []),
            )
            session.add(row)
            await session.commit()
    except Exception as exc:
        log.error("event_persist_failed", error=str(exc), event_id=event_id)


async def _consume_loop() -> None:
    assert _consumer is not None
    assert _producer is not None
    try:
        async for msg in _consumer:
            try:
                event = json.loads(msg.value)
                enriched = await _enrich(event)
                await _persist_event(enriched)
                await send_json(_producer, "events.enriched", enriched)
            except Exception as exc:
                log.error("event_processing_error", error=str(exc))
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        log.error("consumer_loop_crashed", error=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _consumer, _producer, _worker_task
    _consumer = await create_consumer("events.raw", "event-processor")
    _producer = await create_producer()
    _worker_task = asyncio.create_task(_consume_loop())
    yield
    _worker_task.cancel()
    try:
        await _worker_task
    except asyncio.CancelledError:
        pass
    await _consumer.stop()
    await _producer.stop()


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------

app = FastAPI(title="event-processor", lifespan=lifespan)

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Event query endpoints
# ---------------------------------------------------------------------------

def _event_to_dict(e: Event) -> dict[str, Any]:
    return {
        "id":                  str(e.id),
        "tenant_id":           str(e.tenant_id),
        "decoy_id":            str(e.decoy_id) if e.decoy_id else None,
        "session_id":          str(e.session_id) if e.session_id else None,
        "source_ip":           e.source_ip,
        "source_port":         e.source_port,
        "destination_ip":      e.destination_ip,
        "destination_port":    e.destination_port,
        "protocol":            e.protocol,
        "event_type":          e.event_type,
        "severity":            e.severity,
        "raw_data":            e.raw_data,
        "enrichment":          e.enrichment,
        "mitre_technique_ids": e.mitre_technique_ids,
        "tags":                e.tags,
        "created_at":          e.created_at.isoformat() if e.created_at else None,
    }


@app.get("/api/events")
async def list_events(
    ctx: TenantContext = Depends(require_tenant),
    severity:  str | None = Query(default=None),
    protocol:  str | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    # support both offset/limit (frontend) and page/page_size (legacy)
    offset:    int = Query(default=0,  ge=0),
    limit:     int = Query(default=50, ge=1, le=200),
    page:      int = Query(default=0,  ge=0),      # legacy — ignored if offset set
    page_size: int = Query(default=50, ge=1, le=200),
):
    # offset/limit takes precedence over page/page_size
    real_offset = offset if offset else page * page_size
    real_limit  = limit

    async with tenant_db(ctx.tenant_id) as session:
        base = select(Event).where(Event.tenant_id == ctx.tenant_id)
        if severity:
            base = base.where(Event.severity == severity)
        if protocol:
            base = base.where(Event.protocol == protocol.upper())
        if source_ip:
            base = base.where(cast(Event.source_ip, String) == source_ip)

        total = await session.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await session.execute(
            base.order_by(Event.created_at.desc())
                .offset(real_offset)
                .limit(real_limit)
        )
        events = result.scalars().all()

    return {
        "total": total or 0,
        "items": [_event_to_dict(e) for e in events],
    }


@app.get("/api/events/{event_id}")
async def get_event(
    event_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as session:
        result = await session.execute(
            select(Event).where(
                Event.id == event_id,
                Event.tenant_id == ctx.tenant_id,
            )
        )
        event = result.scalar_one_or_none()
    if not event:
        raise HTTPException(status_code=404, detail="event not found")
    return _event_to_dict(event)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
