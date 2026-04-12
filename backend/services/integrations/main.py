"""
Integrations service — SIEM connectors + SOAR + ticketing.

Native connectors (not just webhooks):
  - Splunk HEC (HTTP Event Collector)
  - Microsoft Sentinel (Log Analytics Workspace API)
  - IBM QRadar (Syslog CEF)
  - Elastic Security (Bulk API + ECS field mapping)
  - Generic webhook + Slack + PagerDuty + email

Receives Kafka events from alerts.triggered and pushes to all configured SIEMs.
"""
import asyncio
import json
import os
import uuid
import time
import syslog as _syslog_module
from datetime import datetime, timezone
from typing import Any

import aiohttp
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from backend.shared.db import tenant_db
from backend.shared.models.integration import Integration
from backend.shared.tenant_context import TenantContext, require_tenant

log = structlog.get_logger()
app = FastAPI(title="integrations")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")

# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

VALID_TYPES = {
    "webhook", "slack", "email", "pagerduty",
    "splunk", "sentinel", "qradar", "elastic",
    "crowdstrike", "sentinelone", "jira", "servicenow", "thehive",
}


class IntegrationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str
    config: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True


class IntegrationUpdate(BaseModel):
    name: str | None = None
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


def _out(i: Integration) -> dict:
    cfg = dict(i.config or {})
    # Redact sensitive fields
    for key in ("api_key", "token", "password", "secret", "routing_key",
                "hec_token", "workspace_key"):
        if key in cfg:
            cfg[key] = "***REDACTED***"
    return IntegrationOut(
        id=str(i.id),
        name=i.name,
        type=i.type,
        config=cfg,
        enabled=i.enabled,
        last_triggered_at=str(i.last_triggered_at) if i.last_triggered_at else None,
        created_at=str(i.created_at),
    ).model_dump()


# ---------------------------------------------------------------------------
# SIEM event formatters
# ---------------------------------------------------------------------------

def _to_splunk_hec(alert: dict) -> dict:
    """Format alert as Splunk HEC event."""
    return {
        "time": time.time(),
        "host": "phantomgrid",
        "source": "phantomgrid:honeypot",
        "sourcetype": "phantomgrid:alert",
        "index": "main",
        "event": {
            "severity": alert.get("severity"),
            "title":    alert.get("title"),
            "summary":  alert.get("summary"),
            "source_ip": alert.get("source_ip"),
            "protocol":  alert.get("protocol", {}).get("value", "unknown") if isinstance(alert.get("protocol"), dict) else alert.get("protocol", "unknown"),
            "mitre_techniques": alert.get("mitre_techniques", []),
            "tenant_id": alert.get("tenant_id"),
            "alert_id":  alert.get("id"),
            "rule_type": alert.get("rule_type"),
        },
    }


def _to_ecs(alert: dict) -> dict:
    """Format alert as Elastic Common Schema (ECS) document."""
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event": {
            "kind":     "alert",
            "category": ["intrusion_detection"],
            "type":     ["info"],
            "severity": {"critical": 90, "high": 70, "medium": 50, "low": 25}.get(
                alert.get("severity", "low"), 25
            ),
            "dataset": "phantomgrid.alerts",
            "provider": "phantomgrid",
            "id": alert.get("id"),
            "reason": alert.get("title"),
        },
        "source": {
            "ip": alert.get("source_ip"),
            "geo": {
                "country_name": alert.get("raw_data", {}).get("country"),
                "city_name":    alert.get("raw_data", {}).get("city"),
            },
        },
        "threat": {
            "technique": {
                "id": alert.get("mitre_techniques", []),
            },
            "framework": "MITRE ATT&CK",
        },
        "rule": {
            "name":     alert.get("rule_type"),
            "category": "honeypot",
        },
        "message": alert.get("summary"),
        "tags": ["phantomgrid", "honeypot", alert.get("severity", "low")],
        "phantomgrid": {
            "alert_id":  alert.get("id"),
            "tenant_id": alert.get("tenant_id"),
            "protocol":  alert.get("protocol"),
        },
    }


def _to_cef(alert: dict) -> str:
    """Format alert as Common Event Format (CEF) for QRadar/Syslog."""
    severity_map = {"critical": 10, "high": 8, "medium": 5, "low": 2, "info": 1}
    sev = severity_map.get(alert.get("severity", "low"), 2)
    src_ip = alert.get("source_ip", "0.0.0.0")
    title  = (alert.get("title", "") or "").replace("|", "/").replace("\\", "/")
    summary = (alert.get("summary", "") or "").replace("=", "\\=")[:200]

    ext = (
        f"src={src_ip} "
        f"msg={summary} "
        f"cs1Label=MITRETechniques "
        f"cs1={','.join(alert.get('mitre_techniques', []))} "
        f"cs2Label=TenantID "
        f"cs2={alert.get('tenant_id', '')} "
        f"cs3Label=Protocol "
        f"cs3={alert.get('protocol', '')} "
        f"outcome={alert.get('rule_type', 'unknown')}"
    )
    return (
        f"CEF:0|PhantomGrid|HoneypotPlatform|1.0|{alert.get('rule_type', 'alert')}"
        f"|{title}|{sev}|{ext}"
    )


def _to_sentinel(alert: dict) -> dict:
    """Format alert for Microsoft Sentinel Log Analytics."""
    return {
        "TimeGenerated":    datetime.now(timezone.utc).isoformat(),
        "Severity":         alert.get("severity", "informational").capitalize(),
        "AlertName":        alert.get("title", "PhantomGrid Alert"),
        "Description":      alert.get("summary", ""),
        "SourceIP":         alert.get("source_ip"),
        "Protocol":         str(alert.get("protocol", "")),
        "MITRETechniques":  json.dumps(alert.get("mitre_techniques", [])),
        "TenantId":         alert.get("tenant_id"),
        "AlertId":          alert.get("id"),
        "RuleType":         alert.get("rule_type"),
        "Country":          alert.get("raw_data", {}).get("country", ""),
        "ASN":              alert.get("raw_data", {}).get("asn", ""),
        "IsTOR":            str(alert.get("raw_data", {}).get("is_tor", False)),
    }


# ---------------------------------------------------------------------------
# SIEM push functions
# ---------------------------------------------------------------------------

async def _push_splunk(cfg: dict, alert: dict) -> dict:
    url   = cfg.get("hec_url", "")
    token = cfg.get("hec_token", "")
    if not url or not token:
        return {"ok": False, "error": "hec_url or hec_token not configured"}
    try:
        async with aiohttp.ClientSession() as s:
            resp = await s.post(
                url,
                json=_to_splunk_hec(alert),
                headers={"Authorization": f"Splunk {token}",
                         "Content-Type": "application/json"},
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=cfg.get("ssl_verify", True),
            )
            return {"ok": resp.status in (200, 204), "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _push_elastic(cfg: dict, alert: dict) -> dict:
    url     = cfg.get("url", "")
    api_key = cfg.get("api_key", "")
    index   = cfg.get("index", "phantomgrid-alerts")
    if not url:
        return {"ok": False, "error": "url not configured"}
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"ApiKey {api_key}"
    try:
        async with aiohttp.ClientSession() as s:
            resp = await s.post(
                f"{url.rstrip('/')}/{index}/_doc",
                json=_to_ecs(alert),
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=10),
                ssl=cfg.get("ssl_verify", True),
            )
            data = await resp.json()
            return {"ok": resp.status in (200, 201), "status": resp.status,
                    "id": data.get("_id")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _push_sentinel(cfg: dict, alert: dict) -> dict:
    workspace_id  = cfg.get("workspace_id", "")
    workspace_key = cfg.get("workspace_key", "")
    log_type      = cfg.get("log_type", "PhantomGridAlerts")
    if not workspace_id or not workspace_key:
        return {"ok": False, "error": "workspace_id or workspace_key not configured"}

    import hmac
    import hashlib
    import base64

    body    = json.dumps([_to_sentinel(alert)])
    content = body.encode("utf-8")
    rfc1123 = datetime.now(timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")
    string_to_hash = f"POST\n{len(content)}\napplication/json\nx-ms-date:{rfc1123}\n/api/logs"
    decoded_key    = base64.b64decode(workspace_key)
    encoded_hash   = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), hashlib.sha256).digest()
    ).decode("utf-8")
    sig = f"SharedKey {workspace_id}:{encoded_hash}"

    try:
        async with aiohttp.ClientSession() as s:
            resp = await s.post(
                f"https://{workspace_id}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
                data=content,
                headers={
                    "Content-Type":  "application/json",
                    "Log-Type":      log_type,
                    "Authorization": sig,
                    "x-ms-date":     rfc1123,
                },
                timeout=aiohttp.ClientTimeout(total=15),
            )
            return {"ok": resp.status == 200, "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _push_qradar(cfg: dict, alert: dict) -> dict:
    """Push CEF syslog to QRadar syslog listener."""
    host = cfg.get("syslog_host", "")
    port = int(cfg.get("syslog_port", 514))
    if not host:
        return {"ok": False, "error": "syslog_host not configured"}
    cef_line = _to_cef(alert) + "\n"
    try:
        loop = asyncio.get_event_loop()
        transport, proto = await loop.create_datagram_endpoint(
            asyncio.DatagramProtocol,
            remote_addr=(host, port),
        )
        transport.sendto(cef_line.encode("utf-8"))
        transport.close()
        return {"ok": True, "host": host, "port": port}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _push_webhook(cfg: dict, alert: dict) -> dict:
    url     = cfg.get("url", "")
    headers = cfg.get("headers", {})
    if not url:
        return {"ok": False, "error": "url not configured"}
    try:
        async with aiohttp.ClientSession() as s:
            resp = await s.post(
                url,
                json=alert,
                headers={"Content-Type": "application/json", **headers},
                timeout=aiohttp.ClientTimeout(total=10),
            )
            return {"ok": resp.status < 400, "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _push_slack(cfg: dict, alert: dict) -> dict:
    url = cfg.get("webhook_url", "")
    if not url:
        return {"ok": False, "error": "webhook_url not configured"}
    sev = alert.get("severity", "info")
    color_map = {"critical": "#FF0000", "high": "#FF6600",
                 "medium": "#FFCC00", "low": "#36A64F", "info": "#4A90E2"}
    payload = {
        "attachments": [{
            "color":  color_map.get(sev, "#4A90E2"),
            "title":  f":warning: PhantomGrid Alert — {alert.get('title', '')}",
            "text":   alert.get("summary", ""),
            "fields": [
                {"title": "Severity",   "value": sev.upper(),                         "short": True},
                {"title": "Source IP",  "value": alert.get("source_ip", "N/A"),       "short": True},
                {"title": "Protocol",   "value": str(alert.get("protocol", "N/A")),   "short": True},
                {"title": "MITRE",      "value": ", ".join(alert.get("mitre_techniques", [])) or "N/A", "short": True},
            ],
            "footer": "PhantomGrid Honeypot Platform",
            "ts":     int(time.time()),
        }]
    }
    try:
        async with aiohttp.ClientSession() as s:
            resp = await s.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=10))
            return {"ok": resp.status < 400, "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _push_pagerduty(cfg: dict, alert: dict) -> dict:
    routing_key = cfg.get("routing_key", "")
    if not routing_key:
        return {"ok": False, "error": "routing_key not configured"}
    sev_map = {"critical": "critical", "high": "error", "medium": "warning",
               "low": "info", "info": "info"}
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": alert.get("id", str(uuid.uuid4())),
        "payload": {
            "summary":  f"PhantomGrid: {alert.get('title', 'Honeypot Alert')}",
            "severity": sev_map.get(alert.get("severity", "low"), "info"),
            "source":   alert.get("source_ip", "phantomgrid"),
            "custom_details": {
                "protocol":   alert.get("protocol"),
                "rule_type":  alert.get("rule_type"),
                "mitre":      alert.get("mitre_techniques", []),
                "summary":    alert.get("summary"),
            },
        },
    }
    try:
        async with aiohttp.ClientSession() as s:
            resp = await s.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=15),
            )
            return {"ok": resp.status in (200, 202), "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


# Dispatcher
_PUSH_FN = {
    "splunk":     _push_splunk,
    "elastic":    _push_elastic,
    "sentinel":   _push_sentinel,
    "qradar":     _push_qradar,
    "webhook":    _push_webhook,
    "slack":      _push_slack,
    "pagerduty":  _push_pagerduty,
}


async def dispatch_alert(alert: dict, tenant_id: str):
    """Push alert to all enabled integrations for this tenant."""
    async with tenant_db(tenant_id) as db:
        rows = await db.execute(
            select(Integration).where(
                Integration.tenant_id == tenant_id,
                Integration.enabled == True,  # noqa: E712
            )
        )
        integrations = rows.scalars().all()

    for intg in integrations:
        fn = _PUSH_FN.get(intg.type)
        if fn:
            try:
                result = await fn(intg.config or {}, alert)
                log.info("siem_push", integration=intg.name, type=intg.type,
                         ok=result.get("ok"))
            except Exception as exc:
                log.error("siem_push_error", integration=intg.name, error=str(exc))


# ---------------------------------------------------------------------------
# Kafka consumer
# ---------------------------------------------------------------------------

async def _consume():
    consumer = AIOKafkaConsumer(
        "alerts.triggered",
        bootstrap_servers=KAFKA_BROKERS,
        group_id="integrations",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode()),
    )
    for attempt in range(10):
        try:
            await consumer.start()
            log.info("integrations_consumer_started")
            break
        except Exception as exc:
            await asyncio.sleep(2 ** attempt)
    else:
        return

    try:
        async for msg in consumer:
            alert = msg.value
            tenant_id = alert.get("tenant_id")
            if tenant_id:
                asyncio.ensure_future(dispatch_alert(alert, tenant_id))
    except asyncio.CancelledError:
        pass
    finally:
        await consumer.stop()


@app.on_event("startup")
async def startup():
    asyncio.ensure_future(_consume())


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
    limit:  int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        rows = await db.execute(
            select(Integration)
            .where(Integration.tenant_id == ctx.tenant_id)
            .order_by(Integration.created_at.desc())
            .offset(offset).limit(limit)
        )
        items = rows.scalars().all()
        total = await db.scalar(
            select(func.count(Integration.id))
            .where(Integration.tenant_id == ctx.tenant_id)
        )
    return {"total": total, "items": [_out(i) for i in items]}


@app.post("/api/integrations", status_code=201)
async def create_integration(
    body: IntegrationCreate,
    ctx: TenantContext = Depends(require_tenant),
):
    if body.type not in VALID_TYPES:
        raise HTTPException(400, f"Invalid type. Valid: {sorted(VALID_TYPES)}")
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
        raise HTTPException(404, "not found")
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
            raise HTTPException(404, "not found")
        if body.name is not None:    i.name   = body.name
        if body.config is not None:  i.config = body.config
        if body.enabled is not None: i.enabled = body.enabled
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
            raise HTTPException(404, "not found")
        await db.delete(i)
        await db.commit()


# ---------------------------------------------------------------------------
# Connectivity test
# ---------------------------------------------------------------------------

_TEST_ALERT = {
    "id": "test-alert-id",
    "title": "PhantomGrid Connectivity Test",
    "summary": "This is a test notification from PhantomGrid. If you see this, the integration is working.",
    "severity": "info",
    "source_ip": "1.2.3.4",
    "protocol": "SSH",
    "rule_type": "connectivity_test",
    "mitre_techniques": [],
    "tenant_id": "test",
}


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
        raise HTTPException(404, "not found")

    fn = _PUSH_FN.get(i.type)
    if not fn:
        raise HTTPException(400, f"No test handler for type: {i.type}")

    result = await fn(i.config or {}, _TEST_ALERT)
    return {"integration_id": integration_id, "type": i.type, **result}


@app.get("/api/integrations/types/available")
async def list_types():
    return {
        "types": [
            {"id": "webhook",    "name": "Generic Webhook",          "category": "notification"},
            {"id": "slack",      "name": "Slack",                    "category": "notification"},
            {"id": "pagerduty",  "name": "PagerDuty",               "category": "notification"},
            {"id": "email",      "name": "Email (SMTP)",             "category": "notification"},
            {"id": "splunk",     "name": "Splunk HEC",               "category": "siem"},
            {"id": "elastic",    "name": "Elastic Security (ECS)",   "category": "siem"},
            {"id": "sentinel",   "name": "Microsoft Sentinel",       "category": "siem"},
            {"id": "qradar",     "name": "IBM QRadar (CEF Syslog)",  "category": "siem"},
            {"id": "jira",       "name": "Jira",                     "category": "ticketing"},
            {"id": "servicenow", "name": "ServiceNow",               "category": "ticketing"},
            {"id": "thehive",    "name": "TheHive",                  "category": "ticketing"},
            {"id": "crowdstrike","name": "CrowdStrike Falcon",       "category": "edr"},
            {"id": "sentinelone","name": "SentinelOne",              "category": "edr"},
        ]
    }
