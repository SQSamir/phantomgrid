"""
Alert Engine — evaluates enriched events against rules and fires alerts.

Kafka consumer:  events.enriched  →  rule evaluation  →  alerts.triggered
                                                       →  notifications.pending

HTTP API (served to the gateway):
  GET   /api/alerts        paginated list, filterable by status / severity
  PATCH /api/alerts/{id}   update status (investigating / resolved / suppressed)
  GET   /health
  GET   /metrics           Prometheus
"""
import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from typing import Any

import structlog
from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
from fastapi import Depends, FastAPI, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select

from backend.shared.db import tenant_db
from backend.shared.kafka import create_consumer, create_producer, send_json
from backend.shared.models.alert import Alert
from backend.shared.redis_client import get_redis
from backend.shared.tenant_context import TenantContext, require_tenant

log = structlog.get_logger()

VALID_STATUSES = {"new", "investigating", "resolved", "suppressed"}

# ---------------------------------------------------------------------------
# Suppression / rate-limiting helpers (unchanged from original)
# ---------------------------------------------------------------------------

async def _suppressed(tenant_id: str, rule_id: str, ip: str) -> bool:
    r = get_redis()
    return bool(await r.get(f"supp:{tenant_id}:{rule_id}:{ip}"))


async def _set_supp(tenant_id: str, rule_id: str, ip: str, minutes: int = 5):
    r = get_redis()
    await r.setex(f"supp:{tenant_id}:{rule_id}:{ip}", minutes * 60, "1")


async def _threshold_trigger(
    tenant_id: str, rule_id: str, ip: str, event_id: str,
    threshold: int = 5, window_sec: int = 300,
) -> bool:
    r = get_redis()
    now = int(time.time())
    k = f"rl:{tenant_id}:{rule_id}:{ip}"
    await r.zadd(k, {event_id: now})
    await r.zremrangebyscore(k, 0, now - window_sec)
    count = await r.zcard(k)
    await r.expire(k, window_sec)
    return count >= threshold


async def _correlation_trigger(
    tenant_id: str, ip: str, decoy_id: str,
    min_decoys: int = 3, window_sec: int = 300,
) -> bool:
    r = get_redis()
    k = f"decoys:{tenant_id}:{ip}"
    await r.sadd(k, decoy_id)
    await r.expire(k, window_sec)
    count = await r.scard(k)
    return count >= min_decoys


# ---------------------------------------------------------------------------
# Persistence + firing
# ---------------------------------------------------------------------------

async def _persist_alert(alert: dict) -> str:
    alert_id = str(uuid.uuid4())
    enrichment = alert.get("enrichment", {})
    try:
        async with tenant_db(alert["tenant_id"]) as session:
            row = Alert(
                id=alert_id,
                tenant_id=alert["tenant_id"],
                severity=alert.get("severity", "medium"),
                status="new",
                title=alert.get("title", ""),
                summary=alert.get("summary", ""),
                source_ip=alert.get("source_ip"),
                source_country=enrichment.get("country"),
                source_asn=enrichment.get("asn"),
                mitre_technique_ids=alert.get("mitre_technique_ids", []),
            )
            session.add(row)
            await session.commit()
    except Exception as exc:
        log.error("alert_persist_failed", error=str(exc), alert_title=alert.get("title"))
        raise
    return alert_id


async def _fire_alert(p: AIOKafkaProducer, alert: dict) -> None:
    try:
        alert_id = await _persist_alert(alert)
        alert["alert_id"] = alert_id
    except Exception:
        pass
    await send_json(p, "alerts.triggered", alert)
    await send_json(p, "notifications.pending", alert)


# ---------------------------------------------------------------------------
# Kafka consumer loop
# ---------------------------------------------------------------------------

_consumer: AIOKafkaConsumer | None = None
_producer: AIOKafkaProducer | None = None
_worker_task: asyncio.Task | None = None


async def _consume_loop() -> None:
    assert _consumer is not None
    assert _producer is not None
    try:
        async for msg in _consumer:
            try:
                e = json.loads(msg.value)
                tenant_id = str(e.get("tenant_id", ""))
                if not tenant_id:
                    continue

                ip = e.get("source_ip", "0.0.0.0")
                event_id = str(e.get("event_id", "evt"))
                decoy_id = str(e.get("decoy_id", "none"))
                proto = e.get("protocol", "")
                etype = e.get("event_type", "")

                # Simple match rule
                if etype in {"auth_attempt", "honeytoken_callback"}:
                    rule_id = f"simple:{proto}:{etype}"
                    if not await _suppressed(tenant_id, rule_id, ip):
                        alert = {
                            "tenant_id": tenant_id,
                            "severity": "critical" if etype == "honeytoken_callback" else "high",
                            "title": f"{proto} {etype}",
                            "summary": "Simple rule triggered",
                            "source_ip": ip,
                            "enrichment": e.get("enrichment", {}),
                            "mitre_technique_ids": e.get("mitre_technique_ids", []),
                        }
                        await _set_supp(tenant_id, rule_id, ip)
                        await _fire_alert(_producer, alert)

                # Threshold rule — brute-force-like patterns
                if etype == "auth_attempt":
                    rule_id = f"threshold:{proto}:auth_attempt"
                    trig = await _threshold_trigger(
                        tenant_id, rule_id, ip, event_id, threshold=5, window_sec=300
                    )
                    if trig and not await _suppressed(tenant_id, rule_id, ip):
                        alert = {
                            "tenant_id": tenant_id,
                            "severity": "high",
                            "title": f"{proto} brute force suspected",
                            "summary": "Threshold rule triggered (>=5 auth_attempt / 5m)",
                            "source_ip": ip,
                            "enrichment": e.get("enrichment", {}),
                            "mitre_technique_ids": e.get("mitre_technique_ids", []),
                        }
                        await _set_supp(tenant_id, rule_id, ip)
                        await _fire_alert(_producer, alert)

                # Correlation rule — same IP hits multiple decoys in short window
                rule_id = "correlation:multi-decoy"
                corr = await _correlation_trigger(
                    tenant_id, ip, decoy_id, min_decoys=3, window_sec=300
                )
                if corr and not await _suppressed(tenant_id, rule_id, ip):
                    alert = {
                        "tenant_id": tenant_id,
                        "severity": "critical",
                        "title": "Lateral movement pattern",
                        "summary": "Correlation rule triggered (>=3 decoys / 5m)",
                        "source_ip": ip,
                        "enrichment": e.get("enrichment", {}),
                        "mitre_technique_ids": e.get("mitre_technique_ids", []),
                    }
                    await _set_supp(tenant_id, rule_id, ip)
                    await _fire_alert(_producer, alert)

            except Exception as exc:
                log.error("alert_processing_error", error=str(exc))
    except asyncio.CancelledError:
        pass
    except Exception as exc:
        log.error("consumer_loop_crashed", error=str(exc))


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _consumer, _producer, _worker_task
    _consumer = await create_consumer("events.enriched", "alert-engine")
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

app = FastAPI(title="alert-engine", lifespan=lifespan)

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Alert query / mutation endpoints
# ---------------------------------------------------------------------------

def _alert_to_dict(a: Alert) -> dict[str, Any]:
    return {
        "id": str(a.id),
        "tenant_id": str(a.tenant_id),
        "rule_id": str(a.rule_id) if a.rule_id else None,
        "severity": a.severity,
        "status": a.status,
        "title": a.title,
        "summary": a.summary,
        "source_ip": a.source_ip,
        "source_country": a.source_country,
        "source_asn": a.source_asn,
        "mitre_technique_ids": a.mitre_technique_ids,
        "event_count": a.event_count,
        "first_seen_at": a.first_seen_at.isoformat() if a.first_seen_at else None,
        "last_seen_at": a.last_seen_at.isoformat() if a.last_seen_at else None,
    }


@app.get("/api/alerts")
async def list_alerts(
    ctx: TenantContext = Depends(require_tenant),
    status: str | None = Query(default=None),
    severity: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
):
    async with tenant_db(ctx.tenant_id) as session:
        q = select(Alert).order_by(Alert.last_seen_at.desc())
        if status:
            q = q.where(Alert.status == status)
        if severity:
            q = q.where(Alert.severity == severity)
        offset = (page - 1) * page_size
        q = q.offset(offset).limit(page_size)
        result = await session.execute(q)
        alerts = result.scalars().all()
    return {"items": [_alert_to_dict(a) for a in alerts], "page": page, "page_size": page_size}


@app.get("/api/alerts/{alert_id}")
async def get_alert(
    alert_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as session:
        result = await session.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="alert not found")
    return _alert_to_dict(alert)


class AlertStatusUpdate(BaseModel):
    status: str


@app.patch("/api/alerts/{alert_id}")
async def update_alert_status(
    alert_id: str,
    body: AlertStatusUpdate,
    ctx: TenantContext = Depends(require_tenant),
):
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of: {', '.join(sorted(VALID_STATUSES))}",
        )
    async with tenant_db(ctx.tenant_id) as session:
        result = await session.execute(
            select(Alert).where(Alert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        if not alert:
            raise HTTPException(status_code=404, detail="alert not found")
        alert.status = body.status
        await session.commit()
        await session.refresh(alert)
    return _alert_to_dict(alert)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8080, reload=False)
