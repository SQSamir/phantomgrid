"""
Alert Engine — evaluates enriched events against rules and fires alerts.

Kafka consumer:  events.enriched  →  rule evaluation  →  alerts.triggered
                                                       →  notifications.pending

Detection rules
---------------
1.  Simple match     — auth_attempt, honeytoken_triggered
2.  Brute-force      — ≥5 auth_attempts from same IP / 5 min
3.  Lateral movement — same IP hits ≥3 different decoys / 5 min
4.  Dangerous cmd    — wget/curl/python downloading from external host (critical)
5.  OT write/stop    — Modbus FC5/6/15/16, S7 PLC-stop, DNP3 WRITE (critical)
6.  Container escape — Docker/K8s API sensitive endpoint access (critical)
7.  Credential spray — same password tried against ≥3 different usernames / 10 min
8.  TOR origin       — any event from a known TOR exit node (high)
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
from sqlalchemy import func, select

from backend.shared.db import tenant_db
from backend.shared.kafka import create_consumer, create_producer, send_json
from backend.shared.models.alert import Alert
from backend.shared.redis_client import get_redis
from backend.shared.tenant_context import TenantContext, require_tenant

log = structlog.get_logger()

VALID_STATUSES = {"new", "investigating", "resolved", "suppressed"}

# ---------------------------------------------------------------------------
# Suppression helpers
# ---------------------------------------------------------------------------

async def _suppressed(tenant_id: str, rule_id: str, key: str) -> bool:
    r = get_redis()
    return bool(await r.get(f"supp:{tenant_id}:{rule_id}:{key}"))


async def _set_supp(tenant_id: str, rule_id: str, key: str, minutes: int = 5):
    r = get_redis()
    await r.setex(f"supp:{tenant_id}:{rule_id}:{key}", minutes * 60, "1")


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


async def _cred_spray_trigger(
    tenant_id: str, ip: str, password: str, username: str,
    threshold: int = 3, window_sec: int = 600,
) -> bool:
    """Track unique usernames tried with the same password per IP."""
    if not password:
        return False
    r = get_redis()
    # key per (tenant, ip, password_hash) → set of usernames
    pw_key = f"spray:{tenant_id}:{ip}:{hash(password) & 0xFFFFFFFF}"
    await r.sadd(pw_key, username or "?")
    await r.expire(pw_key, window_sec)
    return await r.scard(pw_key) >= threshold


# ---------------------------------------------------------------------------
# Dangerous command patterns
# ---------------------------------------------------------------------------

_DANGEROUS_PATTERNS = (
    "wget ", "curl ", "python -c", "python3 -c",
    "bash -i", "nc -e", "ncat -e", "/bin/sh -i",
    "chmod +x", "chmod 777",
    "> /dev/tcp/", "base64 -d",
    "rm -rf /", "dd if=",
)

def _is_dangerous_command(cmd: str) -> bool:
    low = cmd.lower()
    return any(p in low for p in _DANGEROUS_PATTERNS)


# ---------------------------------------------------------------------------
# OT/ICS write function codes
# ---------------------------------------------------------------------------

_OT_WRITE_FUNCTIONS = {
    # Modbus
    "WRITE_COIL", "WRITE_REGISTER", "WRITE_MULTIPLE_COILS",
    "WRITE_MULTIPLE_REGISTERS", "MASK_WRITE_REGISTER",
    # DNP3
    "WRITE", "DIRECT_OPERATE", "COLD_RESTART", "WARM_RESTART",
    # S7
    "PLC_STOP", "DOWNLOAD", "START_DOWNLOAD",
}

def _is_ot_write(event_type: str, raw_data: dict) -> bool:
    fn = (raw_data.get("function_name") or raw_data.get("function_code") or "").upper()
    return fn in _OT_WRITE_FUNCTIONS or event_type in {
        "ot_write_attempt", "plc_stop_attempt", "scada_write",
    }


# ---------------------------------------------------------------------------
# Container escape patterns
# ---------------------------------------------------------------------------

_CONTAINER_ESCAPE_PATHS = (
    "/containers/create", "/containers/run",
    "/exec/", "/images/create",
    "/api/v1/secrets", "/api/v1/pods",
    "/api/v1/exec", "/api/v1/namespaces/default/pods",
)

def _is_container_escape(event_type: str, raw_data: dict) -> bool:
    if event_type == "container_escape_attempt":
        return True
    path = (raw_data.get("path") or raw_data.get("url") or "").lower()
    return any(p in path for p in _CONTAINER_ESCAPE_PATHS)


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
        log.error("alert_persist_failed", error=str(exc), title=alert.get("title"))
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


def _base_alert(e: dict, severity: str, title: str, summary: str) -> dict:
    return {
        "tenant_id":           str(e.get("tenant_id", "")),
        "severity":            severity,
        "title":               title,
        "summary":             summary,
        "source_ip":           e.get("source_ip", "0.0.0.0"),
        "enrichment":          e.get("enrichment", {}),
        "mitre_technique_ids": e.get("mitre_technique_ids", []),
    }


# ---------------------------------------------------------------------------
# Main consume loop
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

                ip        = e.get("source_ip", "0.0.0.0")
                event_id  = str(e.get("event_id", uuid.uuid4()))
                decoy_id  = str(e.get("decoy_id", "none"))
                proto     = e.get("protocol", "")
                etype     = e.get("event_type", "")
                raw       = e.get("raw_data", {})
                enrichment = e.get("enrichment", {})

                # ── Rule 1: Honeytoken triggered ─────────────────────────────
                if etype == "honeytoken_triggered":
                    rule_id = "honeytoken:triggered"
                    if not await _suppressed(tenant_id, rule_id, ip):
                        await _set_supp(tenant_id, rule_id, ip, minutes=60)
                        await _fire_alert(_producer, _base_alert(
                            e, "critical",
                            "Honeytoken Accessed",
                            f"Planted token accessed from {ip} — attacker confirmed",
                        ))

                # ── Rule 2: Auth attempt simple match ────────────────────────
                if etype == "auth_attempt":
                    rule_id = f"auth:{proto}:{ip}"
                    if not await _suppressed(tenant_id, rule_id, ip):
                        await _set_supp(tenant_id, rule_id, ip, minutes=5)
                        await _fire_alert(_producer, _base_alert(
                            e, "high",
                            f"{proto} Credential Capture",
                            f"Credentials captured on {proto} honeypot from {ip}",
                        ))

                # ── Rule 3: Brute-force threshold ────────────────────────────
                if etype == "auth_attempt":
                    rule_id = f"bruteforce:{proto}"
                    trig = await _threshold_trigger(
                        tenant_id, rule_id, ip, event_id,
                        threshold=5, window_sec=300,
                    )
                    if trig and not await _suppressed(tenant_id, rule_id, ip):
                        await _set_supp(tenant_id, rule_id, ip, minutes=10)
                        await _fire_alert(_producer, _base_alert(
                            e, "high",
                            f"{proto} Brute Force — {ip}",
                            "≥5 authentication attempts in 5 minutes",
                        ))

                # ── Rule 4: Lateral movement / multi-decoy sweep ─────────────
                rule_id = "lateral:multi-decoy"
                if await _correlation_trigger(tenant_id, ip, decoy_id, min_decoys=3):
                    if not await _suppressed(tenant_id, rule_id, ip):
                        await _set_supp(tenant_id, rule_id, ip, minutes=15)
                        await _fire_alert(_producer, _base_alert(
                            e, "critical",
                            f"Lateral Movement Detected — {ip}",
                            "Same attacker touched ≥3 honeypots within 5 minutes",
                        ))

                # ── Rule 5: Dangerous command execution ──────────────────────
                if etype == "command_executed":
                    cmd = raw.get("command", "")
                    if _is_dangerous_command(cmd):
                        rule_id = f"dangerous_cmd:{ip}"
                        if not await _suppressed(tenant_id, rule_id, ip):
                            await _set_supp(tenant_id, rule_id, ip, minutes=10)
                            await _fire_alert(_producer, _base_alert(
                                e, "critical",
                                f"Malicious Command Executed — {proto}",
                                f"Dangerous payload command detected: {cmd[:120]}",
                            ))

                # ── Rule 6: OT/ICS write or stop command ──────────────────────
                if proto in {"MODBUS", "DNP3", "S7COMM"} and _is_ot_write(etype, raw):
                    rule_id = f"ot_write:{decoy_id}"
                    if not await _suppressed(tenant_id, rule_id, ip):
                        await _set_supp(tenant_id, rule_id, ip, minutes=30)
                        fn = raw.get("function_name", etype)
                        await _fire_alert(_producer, _base_alert(
                            e, "critical",
                            f"OT/ICS Write Command — {proto}",
                            f"Unauthorized {fn} command on industrial control system from {ip}",
                        ))

                # ── Rule 7: Container/cloud escape attempt ────────────────────
                if proto in {"DOCKER_API", "K8S_API"} and _is_container_escape(etype, raw):
                    rule_id = f"container_escape:{ip}"
                    if not await _suppressed(tenant_id, rule_id, ip):
                        await _set_supp(tenant_id, rule_id, ip, minutes=30)
                        await _fire_alert(_producer, _base_alert(
                            e, "critical",
                            f"Container Escape Attempt — {proto}",
                            f"Attacker accessed privileged {proto} endpoint from {ip}",
                        ))

                # ── Rule 8: Credential spray detection ───────────────────────
                if etype == "auth_attempt":
                    username = raw.get("username", "")
                    password = raw.get("password", "")
                    if await _cred_spray_trigger(tenant_id, ip, password, username):
                        rule_id = f"cred_spray:{ip}"
                        if not await _suppressed(tenant_id, rule_id, ip):
                            await _set_supp(tenant_id, rule_id, ip, minutes=15)
                            await _fire_alert(_producer, _base_alert(
                                e, "high",
                                f"Credential Spray — {ip}",
                                "Same password tried against ≥3 usernames in 10 minutes",
                            ))

                # ── Rule 9: TOR exit node origin ──────────────────────────────
                if enrichment.get("is_tor"):
                    rule_id = f"tor:{ip}"
                    if not await _suppressed(tenant_id, rule_id, ip):
                        await _set_supp(tenant_id, rule_id, ip, minutes=60)
                        await _fire_alert(_producer, _base_alert(
                            e, "high",
                            f"TOR Exit Node Activity — {ip}",
                            f"Attacker using TOR anonymization network ({proto} {etype})",
                        ))

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


def _alert_to_dict(a: Alert) -> dict[str, Any]:
    return {
        "id":                  str(a.id),
        "tenant_id":           str(a.tenant_id),
        "rule_id":             str(a.rule_id) if a.rule_id else None,
        "severity":            a.severity,
        "status":              a.status,
        "title":               a.title,
        "summary":             a.summary,
        "source_ip":           a.source_ip,
        "source_country":      a.source_country,
        "source_asn":          a.source_asn,
        "mitre_technique_ids": a.mitre_technique_ids,
        "event_count":         a.event_count,
        "first_seen_at":       a.first_seen_at.isoformat() if a.first_seen_at else None,
        "last_seen_at":        a.last_seen_at.isoformat() if a.last_seen_at else None,
    }


@app.get("/api/alerts")
async def list_alerts(
    ctx:       TenantContext = Depends(require_tenant),
    status:    str | None = Query(default=None),
    severity:  str | None = Query(default=None),
    offset:    int = Query(default=0,  ge=0),
    limit:     int = Query(default=50, ge=1, le=200),
):
    async with tenant_db(ctx.tenant_id) as session:
        base = select(Alert).where(Alert.tenant_id == ctx.tenant_id)
        if status:
            base = base.where(Alert.status == status)
        if severity:
            base = base.where(Alert.severity == severity)
        total = await session.scalar(
            select(func.count()).select_from(base.subquery())
        )
        result = await session.execute(
            base.order_by(Alert.last_seen_at.desc()).offset(offset).limit(limit)
        )
        alerts = result.scalars().all()
    return {"total": total or 0, "items": [_alert_to_dict(a) for a in alerts]}


@app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: str, ctx: TenantContext = Depends(require_tenant)):
    async with tenant_db(ctx.tenant_id) as session:
        result = await session.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == ctx.tenant_id)
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
    body:     AlertStatusUpdate,
    ctx:      TenantContext = Depends(require_tenant),
):
    if body.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail=f"status must be one of: {', '.join(sorted(VALID_STATUSES))}",
        )
    async with tenant_db(ctx.tenant_id) as session:
        result = await session.execute(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == ctx.tenant_id)
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
