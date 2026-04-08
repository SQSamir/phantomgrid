import asyncio
import json
import os
import smtplib
import ssl
from contextlib import suppress
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlparse

import httpx
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(title="phantomgrid-notifications")

KAFKA_BROKERS = os.getenv("KAFKA_BROKERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("NOTIFICATIONS_TOPIC", "notifications.pending")
GROUP_ID = os.getenv("KAFKA_GROUP_ID", "notifications-service")
WEBHOOK_ALLOWLIST = [h.strip().lower() for h in os.getenv("WEBHOOK_ALLOWLIST", "").split(",") if h.strip()]


class AlertPayload(BaseModel):
    tenant_id: str
    severity: str
    summary: str
    source_ip: str | None = None
    source_country: str | None = None
    decoy_name: str | None = None
    mitre_technique: str | None = None
    alert_title: str | None = None
    event_count: int | None = None


def _is_blocked_host(host: str) -> bool:
    h = host.lower()
    if h in {"localhost", "127.0.0.1"}:
        return True
    try:
        ip = ip_address(h)
        if ip.is_loopback or ip.is_link_local or ip.is_private:
            return True
        if h.startswith("169.254."):
            return True
    except ValueError:
        pass
    return False


def validate_webhook_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        raise HTTPException(status_code=400, detail="Invalid webhook scheme")
    if not parsed.hostname:
        raise HTTPException(status_code=400, detail="Invalid webhook host")
    if _is_blocked_host(parsed.hostname):
        raise HTTPException(status_code=400, detail="Blocked internal webhook host")
    if WEBHOOK_ALLOWLIST and parsed.hostname.lower() not in WEBHOOK_ALLOWLIST:
        raise HTTPException(status_code=400, detail="Webhook host not in allowlist")


async def send_webhook(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    validate_webhook_url(url)
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        r = await client.post(url, json=payload)
    return {"ok": r.is_success, "status": r.status_code, "channel": "webhook"}


async def send_slack_webhook(url: str, payload: dict[str, Any]) -> dict[str, Any]:
    validate_webhook_url(url)
    text = (
        f"*[{payload.get('severity', 'INFO').upper()}] {payload.get('alert_title', payload.get('summary', 'Alert'))}*\n"
        f"Source: {payload.get('source_ip', '-')} ({payload.get('source_country', 'N/A')})\n"
        f"Decoy: {payload.get('decoy_name', 'N/A')}\n"
        f"MITRE: {payload.get('mitre_technique', 'N/A')}\n"
        f"Events: {payload.get('event_count', 1)}"
    )
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        r = await client.post(url, json={"text": text})
    return {"ok": r.is_success, "status": r.status_code, "channel": "slack"}


async def send_pagerduty(routing_key: str, payload: dict[str, Any]) -> dict[str, Any]:
    severity_map = {"critical": "critical", "high": "error", "medium": "warning", "low": "info", "info": "info"}
    body = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "payload": {
            "summary": payload.get("summary", "PhantomGrid alert"),
            "source": payload.get("source_ip", "phantomgrid"),
            "severity": severity_map.get(str(payload.get("severity", "info")).lower(), "info"),
            "custom_details": payload,
        },
    }
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        r = await client.post("https://events.pagerduty.com/v2/enqueue", json=body)
    return {"ok": r.is_success, "status": r.status_code, "channel": "pagerduty"}


def _smtp_send(host: str, port: int, username: str, password: str, sender: str, recipient: str, msg: MIMEMultipart, use_tls: bool) -> None:
    if use_tls:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(host, port, timeout=10) as s:
            s.starttls(context=ctx)
            if username:
                s.login(username, password)
            s.sendmail(sender, [recipient], msg.as_string())
    else:
        with smtplib.SMTP_SSL(host, port, timeout=10) as s:
            if username:
                s.login(username, password)
            s.sendmail(sender, [recipient], msg.as_string())


async def send_email(payload: dict[str, Any], cfg: dict[str, Any]) -> dict[str, Any]:
    host = cfg.get("host") or os.getenv("SMTP_HOST", "")
    port = int(cfg.get("port") or os.getenv("SMTP_PORT", "587"))
    username = cfg.get("username") or os.getenv("SMTP_USER", "")
    password = cfg.get("password") or os.getenv("SMTP_PASS", "")
    sender = cfg.get("from") or os.getenv("SMTP_FROM", "phantomgrid@localhost")
    recipient = cfg.get("to") or os.getenv("SMTP_TO", "")
    use_tls = str(cfg.get("starttls", os.getenv("SMTP_STARTTLS", "true"))).lower() == "true"

    if not host or not recipient:
        return {"ok": False, "channel": "email", "error": "smtp host/to missing"}

    subject = f"[PHANTOMGRID] {str(payload.get('severity', 'info')).upper()}: {payload.get('alert_title', payload.get('summary', 'Alert'))}"
    html = f"""
    <html><body>
      <h2>{payload.get('alert_title', payload.get('summary', 'Alert'))}</h2>
      <p><b>Severity:</b> {payload.get('severity', 'info')}</p>
      <p><b>Source:</b> {payload.get('source_ip', '-')} ({payload.get('source_country', 'N/A')})</p>
      <p><b>Decoy:</b> {payload.get('decoy_name', 'N/A')}</p>
      <p><b>MITRE:</b> {payload.get('mitre_technique', 'N/A')}</p>
      <p><b>Events:</b> {payload.get('event_count', 1)}</p>
      <pre>{json.dumps(payload, indent=2)}</pre>
    </body></html>
    """

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = recipient
    msg.attach(MIMEText(html, "html"))

    await asyncio.to_thread(_smtp_send, host, port, username, password, sender, recipient, msg, use_tls)
    return {"ok": True, "status": 202, "channel": "email"}


async def send_telegram(bot_token: str, chat_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    text = (
        f"[{payload.get('severity', 'info')}] {payload.get('summary', 'Notification')}\n"
        f"IP: {payload.get('source_ip', '-')}\n"
        f"MITRE: {payload.get('mitre_technique', '-')}"
    )
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await client.post(url, json={"chat_id": chat_id, "text": text})
    return {"ok": r.is_success, "status": r.status_code, "channel": "telegram"}


async def dispatch_notification(message: dict[str, Any]) -> list[dict[str, Any]]:
    payload = message.get("payload", message)
    channels = message.get("channels", [])
    results: list[dict[str, Any]] = []

    for ch in channels:
        kind = str(ch.get("type", "")).lower()
        try:
            if kind == "telegram":
                bot = ch.get("bot_token") or os.getenv("TELEGRAM_BOT_TOKEN", "")
                chat = ch.get("chat_id") or os.getenv("TELEGRAM_CHAT_ID", "")
                if bot and chat:
                    results.append(await send_telegram(bot, chat, payload))
            elif kind == "webhook":
                url = ch.get("url")
                if url:
                    results.append(await send_webhook(url, payload))
            elif kind == "slack":
                url = ch.get("webhook_url") or ch.get("url")
                if url:
                    results.append(await send_slack_webhook(url, payload))
            elif kind == "email":
                results.append(await send_email(payload, ch))
            elif kind == "pagerduty":
                rk = ch.get("routing_key") or os.getenv("PAGERDUTY_ROUTING_KEY", "")
                if rk:
                    results.append(await send_pagerduty(rk, payload))
        except Exception as exc:  # noqa: BLE001
            results.append({"ok": False, "channel": kind, "error": str(exc)})
    return results


consumer_task: asyncio.Task | None = None
consumer: AIOKafkaConsumer | None = None


async def consume_loop() -> None:
    global consumer
    consumer = AIOKafkaConsumer(
        KAFKA_TOPIC,
        bootstrap_servers=KAFKA_BROKERS,
        group_id=GROUP_ID,
        auto_offset_reset="latest",
        enable_auto_commit=True,
        value_deserializer=lambda v: json.loads(v.decode("utf-8")),
    )
    await consumer.start()
    try:
        async for msg in consumer:
            await dispatch_notification(msg.value)
    finally:
        await consumer.stop()


@app.on_event("startup")
async def startup_event() -> None:
    global consumer_task
    consumer_task = asyncio.create_task(consume_loop())


@app.on_event("shutdown")
async def shutdown_event() -> None:
    global consumer_task
    if consumer_task:
        consumer_task.cancel()
        with suppress(asyncio.CancelledError):
            await consumer_task


@app.get('/health')
def health():
    return {"status": "ok", "service": "notifications", "topic": KAFKA_TOPIC}


@app.post('/notify/webhook')
async def notify_webhook(url: str, payload: AlertPayload):
    return await send_webhook(url, payload.model_dump())


@app.post('/notify/telegram')
async def notify_telegram(bot_token: str, chat_id: str, payload: AlertPayload):
    return await send_telegram(bot_token, chat_id, payload.model_dump())
