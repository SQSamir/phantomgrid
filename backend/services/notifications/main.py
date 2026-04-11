"""
Notifications service — consumes ``notifications.pending`` from Kafka and
dispatches to each tenant's enabled integrations.

Supported integration types:
  webhook    — HTTP POST with optional HMAC-SHA256 X-PhantomGrid-Signature
  slack      — Slack Incoming Webhook
  email      — SMTP (settings come from env)
  pagerduty  — PagerDuty Events API v2
"""
import asyncio
import hashlib
import hmac
import json
import logging
import os
import smtplib
import ssl
from contextlib import asynccontextmanager
from email.message import EmailMessage

import aiohttp
from fastapi import FastAPI
from sqlalchemy import select

from backend.shared.db import SessionLocal
from backend.shared.kafka import create_consumer, send_json, create_producer
from backend.shared.models.integration import Integration

log = logging.getLogger("notifications")
logging.basicConfig(level=logging.INFO)

# ---------------------------------------------------------------------------
# SMTP env
# ---------------------------------------------------------------------------
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM = os.getenv("SMTP_FROM", "alerts@phantomgrid.local")

TOPIC_IN = "notifications.pending"
CONSUMER_GROUP = "notifications-svc"


# ---------------------------------------------------------------------------
# Dispatch helpers
# ---------------------------------------------------------------------------

async def _dispatch_webhook(cfg: dict, payload: dict, session: aiohttp.ClientSession) -> None:
    url = cfg.get("url")
    if not url:
        return
    body = json.dumps(payload, default=str)
    headers = {"Content-Type": "application/json"}
    secret = cfg.get("secret")
    if secret:
        sig = hmac.new(secret.encode(), body.encode(), hashlib.sha256).hexdigest()
        headers["X-PhantomGrid-Signature"] = f"sha256={sig}"
    headers.update(cfg.get("headers") or {})
    try:
        async with session.post(url, data=body, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            if resp.status >= 400:
                log.warning("webhook_failed url=%s status=%d", url, resp.status)
    except Exception as exc:
        log.error("webhook_error url=%s error=%s", url, exc)


async def _dispatch_slack(cfg: dict, payload: dict, session: aiohttp.ClientSession) -> None:
    webhook_url = cfg.get("webhook_url")
    if not webhook_url:
        return
    alert = payload
    text = (
        f":rotating_light: *{alert.get('severity', 'unknown').upper()} Alert*\n"
        f"*{alert.get('title', 'Alert triggered')}*\n"
        f"{alert.get('summary', '')}\n"
        f"Source IP: `{alert.get('source_ip', 'N/A')}`  |  "
        f"Tenant: `{alert.get('tenant_id', 'N/A')}`"
    )
    body = json.dumps({"text": text})
    try:
        async with session.post(
            webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=10),
        ) as resp:
            if resp.status >= 400:
                log.warning("slack_failed status=%d", resp.status)
    except Exception as exc:
        log.error("slack_error error=%s", exc)


def _send_email_sync(to_addrs: list[str], subject: str, body: str) -> None:
    if not SMTP_HOST:
        log.warning("SMTP_HOST not configured — skipping email")
        return
    msg = EmailMessage()
    msg["From"] = SMTP_FROM
    msg["To"] = ", ".join(to_addrs)
    msg["Subject"] = subject
    msg.set_content(body)
    ctx = ssl.create_default_context()
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
            s.starttls(context=ctx)
            if SMTP_USERNAME:
                s.login(SMTP_USERNAME, SMTP_PASSWORD)
            s.send_message(msg)
    except Exception as exc:
        log.error("email_error error=%s", exc)


async def _dispatch_email(cfg: dict, payload: dict) -> None:
    to_addrs = cfg.get("to") or []
    if not to_addrs:
        return
    alert = payload
    subject = f"[PhantomGrid] {alert.get('severity', '').upper()} Alert: {alert.get('title', 'Alert triggered')}"
    body = (
        f"Severity: {alert.get('severity', 'N/A')}\n"
        f"Title:    {alert.get('title', 'N/A')}\n"
        f"Summary:  {alert.get('summary', 'N/A')}\n"
        f"Source IP: {alert.get('source_ip', 'N/A')}\n"
        f"Tenant:   {alert.get('tenant_id', 'N/A')}\n"
        f"Alert ID: {alert.get('alert_id', 'N/A')}\n"
    )
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, _send_email_sync, to_addrs, subject, body)


async def _dispatch_pagerduty(cfg: dict, payload: dict, session: aiohttp.ClientSession) -> None:
    routing_key = cfg.get("routing_key")
    if not routing_key:
        return
    alert = payload
    severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}
    pd_severity = severity_map.get(alert.get("severity", "medium"), "warning")
    body = json.dumps({
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": alert.get("title", "PhantomGrid alert"),
            "severity": pd_severity,
            "source": alert.get("source_ip", "unknown"),
            "custom_details": {
                "summary": alert.get("summary"),
                "tenant_id": alert.get("tenant_id"),
                "alert_id": alert.get("alert_id"),
            },
        },
    })
    try:
        async with session.post(
            "https://events.pagerduty.com/v2/enqueue",
            data=body,
            headers={"Content-Type": "application/json"},
            timeout=aiohttp.ClientTimeout(total=15),
        ) as resp:
            if resp.status not in (200, 202):
                log.warning("pagerduty_failed status=%d", resp.status)
    except Exception as exc:
        log.error("pagerduty_error error=%s", exc)


# ---------------------------------------------------------------------------
# Integration lookup and fan-out
# ---------------------------------------------------------------------------

async def _load_integrations(tenant_id: str) -> list[Integration]:
    async with SessionLocal() as db:
        rows = await db.execute(
            select(Integration).where(
                Integration.tenant_id == tenant_id,
                Integration.enabled == True,  # noqa: E712
            )
        )
        return list(rows.scalars().all())


async def _fanout(alert: dict) -> None:
    tenant_id = alert.get("tenant_id")
    if not tenant_id:
        return
    integrations = await _load_integrations(tenant_id)
    if not integrations:
        return

    async with aiohttp.ClientSession() as http:
        tasks = []
        for integ in integrations:
            cfg = integ.config or {}
            t = integ.type
            if t == "webhook":
                tasks.append(_dispatch_webhook(cfg, alert, http))
            elif t == "slack":
                tasks.append(_dispatch_slack(cfg, alert, http))
            elif t == "email":
                tasks.append(_dispatch_email(cfg, alert))
            elif t == "pagerduty":
                tasks.append(_dispatch_pagerduty(cfg, alert, http))
            else:
                log.warning("unknown_integration_type type=%s", t)
        await asyncio.gather(*tasks, return_exceptions=True)

    # Update last_triggered_at for all fired integrations
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    async with SessionLocal() as db:
        for integ in integrations:
            row = await db.get(Integration, integ.id)
            if row:
                row.last_triggered_at = now
        await db.commit()


# ---------------------------------------------------------------------------
# Kafka consumer loop
# ---------------------------------------------------------------------------

async def _consume_loop() -> None:
    consumer = await create_consumer(TOPIC_IN, CONSUMER_GROUP)
    log.info("notifications consumer started topic=%s group=%s", TOPIC_IN, CONSUMER_GROUP)
    try:
        async for msg in consumer:
            try:
                alert = json.loads(msg.value.decode())
                await _fanout(alert)
            except Exception as exc:
                log.error("fanout_error error=%s", exc)
    finally:
        await consumer.stop()


# ---------------------------------------------------------------------------
# App lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(_consume_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(title="notifications", lifespan=lifespan)

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.post("/api/notifications/test")
async def test_notification(payload: dict):
    """Manually trigger a fan-out for testing. Requires internal access only."""
    await _fanout(payload)
    return {"dispatched": True}
