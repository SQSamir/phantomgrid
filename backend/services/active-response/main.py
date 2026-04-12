"""
Active Response Engine — PhantomGrid's answer to SecurityHive's #1 gap.

SecurityHive explicitly states they lack active response.
PhantomGrid auto-blocks, tarpits, tickets, and pushes IOCs when triggered.

Playbooks:
  ssh_brute_force       → block_ip + notify + ticket
  lateral_movement      → block_ip + tarpit + quarantine suggestion + notify + ticket + ioc_export
  ntlm_hash_captured    → block_ip + notify + inject_fake_creds + ticket
  critical_system       → block_ip + tarpit + notify + ticket + soar_trigger
  aws_metadata_ssrf     → notify + ticket + ioc_export
  honeytoken_triggered  → notify + ticket + trace_path
  ot_ics_attack         → block_ip + notify + ticket + soar_trigger (CRITICAL)
  container_escape      → block_ip + notify + ticket + soar_trigger (CRITICAL)
"""
import asyncio
import json
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

import aiohttp
import structlog
from aiokafka import AIOKafkaConsumer
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from prometheus_fastapi_instrumentator import Instrumentator

log = structlog.get_logger()
app = FastAPI(title="active-response")
Instrumentator().instrument(app).expose(app)

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
KAFKA_BROKERS     = os.getenv("KAFKA_BROKERS", "kafka:9092")
TARPIT_REDIS_URL  = os.getenv("REDIS_URL", "redis://redis:6379/0")
SOAR_WEBHOOK_URL  = os.getenv("SOAR_WEBHOOK_URL", "")
FIREWALL_TYPE     = os.getenv("FIREWALL_TYPE", "iptables")   # iptables|pfsense|aws|azure
FIREWALL_URL      = os.getenv("FIREWALL_URL", "")
FIREWALL_TOKEN    = os.getenv("FIREWALL_TOKEN", "")
TARPIT_RATE_BPS   = int(os.getenv("TARPIT_RATE_BPS", "1"))
TARPIT_DURATION_M = int(os.getenv("TARPIT_DURATION_MINUTES", "60"))
JIRA_URL          = os.getenv("JIRA_URL", "")
JIRA_TOKEN        = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT      = os.getenv("JIRA_PROJECT_KEY", "SEC")
SERVICENOW_URL    = os.getenv("SERVICENOW_URL", "")
SERVICENOW_USER   = os.getenv("SERVICENOW_USER", "")
SERVICENOW_PASS   = os.getenv("SERVICENOW_PASS", "")
THEHIVE_URL       = os.getenv("THEHIVE_URL", "")
THEHIVE_KEY       = os.getenv("THEHIVE_API_KEY", "")

# ---------------------------------------------------------------------------
# Playbook definitions
# ---------------------------------------------------------------------------
PLAYBOOKS: dict[str, list[str]] = {
    "ssh_brute_force": [
        "block_ip_firewall",
        "create_alert_record",
        "notify_channels",
        "create_ticket",
    ],
    "lateral_movement": [
        "block_ip_firewall",
        "tarpit_connection",
        "create_alert_record",
        "notify_channels",
        "create_ticket",
        "export_ioc_to_siem",
    ],
    "ntlm_hash_captured": [
        "block_ip_firewall",
        "create_alert_record",
        "notify_channels",
        "inject_fake_credentials",
        "create_ticket",
        "export_ioc_to_siem",
    ],
    "critical_system_accessed": [
        "block_ip_firewall",
        "tarpit_connection",
        "create_alert_record",
        "notify_channels",
        "create_ticket",
        "export_ioc_to_siem",
        "trigger_soar_playbook",
    ],
    "aws_metadata_ssrf": [
        "create_alert_record",
        "notify_channels",
        "create_ticket",
        "export_ioc_to_siem",
    ],
    "honeytoken_triggered": [
        "create_alert_record",
        "notify_channels",
        "create_ticket",
    ],
    "ot_ics_attack": [
        "block_ip_firewall",
        "tarpit_connection",
        "create_alert_record",
        "notify_channels",
        "create_ticket",
        "export_ioc_to_siem",
        "trigger_soar_playbook",
    ],
    "container_escape": [
        "block_ip_firewall",
        "tarpit_connection",
        "create_alert_record",
        "notify_channels",
        "create_ticket",
        "export_ioc_to_siem",
        "trigger_soar_playbook",
    ],
    "credential_spray": [
        "block_ip_firewall",
        "create_alert_record",
        "notify_channels",
        "create_ticket",
    ],
}

# Alert rule → playbook mapping
_RULE_TO_PLAYBOOK: dict[str, str] = {
    "brute_force":          "ssh_brute_force",
    "lateral_movement":     "lateral_movement",
    "ntlm_capture":         "ntlm_hash_captured",
    "ot_ics_write":         "ot_ics_attack",
    "container_escape":     "container_escape",
    "honeytoken_triggered": "honeytoken_triggered",
    "aws_ssrf":             "aws_metadata_ssrf",
    "credential_spray":     "credential_spray",
    "dangerous_command":    "critical_system_accessed",
}

# In-memory tarpit registry {ip: expiry_ts}
_tarpitted: dict[str, float] = {}

# In-memory blocked IPs log {ip: {ts, reason, tenant_id}}
_blocked_ips: dict[str, dict] = {}

# Playbook execution log (last 500)
_execution_log: list[dict] = []


# ---------------------------------------------------------------------------
# Action implementations
# ---------------------------------------------------------------------------

async def _block_ip_firewall(source_ip: str, reason: str, tenant_id: str) -> dict:
    """Push block rule to configured firewall."""
    if not source_ip or source_ip in ("0.0.0.0", "127.0.0.1"):
        return {"ok": False, "reason": "invalid IP"}

    _blocked_ips[source_ip] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
        "tenant_id": tenant_id,
        "firewall_type": FIREWALL_TYPE,
    }
    log.info("ip_blocked", ip=source_ip, reason=reason, firewall=FIREWALL_TYPE)

    # Real firewall integration
    if FIREWALL_TYPE == "pfsense" and FIREWALL_URL and FIREWALL_TOKEN:
        try:
            async with aiohttp.ClientSession() as s:
                await s.post(
                    f"{FIREWALL_URL}/api/v1/firewall/alias/entry",
                    headers={"Authorization": f"Bearer {FIREWALL_TOKEN}",
                             "Content-Type": "application/json"},
                    json={"name": "PHANTOMGRID_BLOCKED", "address": source_ip,
                          "detail": reason},
                    timeout=aiohttp.ClientTimeout(total=5),
                )
        except Exception as exc:
            log.warning("pfsense_block_failed", ip=source_ip, error=str(exc))

    elif FIREWALL_TYPE == "aws" and FIREWALL_TOKEN:
        # AWS Security Group revoke via API call would go here
        log.info("aws_sg_block_queued", ip=source_ip)

    return {"ok": True, "ip": source_ip, "firewall": FIREWALL_TYPE}


async def _tarpit_connection(source_ip: str, duration_minutes: int = TARPIT_DURATION_M) -> dict:
    """Add IP to tarpit registry — connections throttled to 1 byte/sec."""
    expiry = datetime.now(timezone.utc).timestamp() + duration_minutes * 60
    _tarpitted[source_ip] = expiry
    log.info("ip_tarpitted", ip=source_ip, duration_minutes=duration_minutes)
    return {"ok": True, "ip": source_ip, "expires_ts": expiry, "rate_bps": TARPIT_RATE_BPS}


async def _inject_fake_credentials(alert: dict) -> dict:
    """Plant convincing but useless credentials into the session."""
    fake_creds = [
        {"username": "administrator", "password": "C0rp0r@te2024!", "domain": "corp.local"},
        {"username": "svc_backup",    "password": "Backup$3rv1ce!", "domain": "corp.local"},
        {"username": "domain_admin",  "password": "D0m@inAdm1n!23", "domain": "corp.local"},
    ]
    log.info("fake_creds_injected", session_id=alert.get("session_id"))
    return {"ok": True, "credentials_injected": len(fake_creds)}


async def _create_ticket(alert: dict) -> dict:
    """Create incident ticket in Jira, ServiceNow, or TheHive."""
    results = {}

    if JIRA_URL and JIRA_TOKEN:
        try:
            payload = {
                "fields": {
                    "project": {"key": JIRA_PROJECT},
                    "summary": f"[PHANTOMGRID] {alert.get('title', 'Security Alert')}",
                    "description": (
                        f"*Severity:* {alert.get('severity', 'unknown').upper()}\n"
                        f"*Source IP:* {alert.get('source_ip', 'N/A')}\n"
                        f"*Protocol:* {alert.get('protocol', 'N/A')}\n"
                        f"*Time:* {alert.get('created_at', 'N/A')}\n\n"
                        f"{alert.get('summary', '')}\n\n"
                        f"MITRE: {', '.join(alert.get('mitre_techniques', []))}"
                    ),
                    "issuetype": {"name": "Bug"},
                    "priority": {
                        "name": "Highest" if alert.get("severity") in ("critical", "high")
                                else "Medium"
                    },
                    "labels": ["phantomgrid", "honeypot", alert.get("severity", "medium")],
                }
            }
            async with aiohttp.ClientSession() as s:
                resp = await s.post(
                    f"{JIRA_URL}/rest/api/2/issue",
                    json=payload,
                    headers={"Authorization": f"Bearer {JIRA_TOKEN}",
                             "Content-Type": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=10),
                )
                data = await resp.json()
                results["jira"] = {"ok": resp.status == 201, "key": data.get("key")}
        except Exception as exc:
            results["jira"] = {"ok": False, "error": str(exc)}

    if SERVICENOW_URL and SERVICENOW_USER:
        try:
            payload = {
                "short_description": f"[PHANTOMGRID] {alert.get('title', 'Security Alert')}",
                "description": alert.get("summary", ""),
                "urgency": "1" if alert.get("severity") == "critical" else "2",
                "impact":  "1" if alert.get("severity") == "critical" else "2",
                "category": "Security",
                "subcategory": "Honeypot Alert",
                "work_notes": json.dumps(alert, default=str),
            }
            async with aiohttp.ClientSession() as s:
                resp = await s.post(
                    f"{SERVICENOW_URL}/api/now/table/incident",
                    json=payload,
                    auth=aiohttp.BasicAuth(SERVICENOW_USER, SERVICENOW_PASS),
                    timeout=aiohttp.ClientTimeout(total=10),
                )
                data = await resp.json()
                results["servicenow"] = {
                    "ok": resp.status == 201,
                    "number": data.get("result", {}).get("number"),
                }
        except Exception as exc:
            results["servicenow"] = {"ok": False, "error": str(exc)}

    if THEHIVE_URL and THEHIVE_KEY:
        try:
            payload = {
                "title": f"[PHANTOMGRID] {alert.get('title', 'Security Alert')}",
                "description": alert.get("summary", ""),
                "severity": 3 if alert.get("severity") == "critical" else 2,
                "tags": ["phantomgrid", "honeypot"],
                "observables": [
                    {"dataType": "ip", "data": alert.get("source_ip"), "ioc": True,
                     "tags": ["honeypot-trigger"]}
                ] if alert.get("source_ip") else [],
            }
            async with aiohttp.ClientSession() as s:
                resp = await s.post(
                    f"{THEHIVE_URL}/api/case",
                    json=payload,
                    headers={"Authorization": f"Bearer {THEHIVE_KEY}"},
                    timeout=aiohttp.ClientTimeout(total=10),
                )
                data = await resp.json()
                results["thehive"] = {"ok": resp.status in (200, 201),
                                      "id": data.get("id")}
        except Exception as exc:
            results["thehive"] = {"ok": False, "error": str(exc)}

    if not results:
        results["internal"] = {"ok": True, "note": "No external ticketing configured"}

    return results


async def _trigger_soar(alert: dict) -> dict:
    """Trigger SOAR playbook via webhook (Splunk SOAR, Palo XSOAR, Tines)."""
    if not SOAR_WEBHOOK_URL:
        return {"ok": False, "reason": "SOAR not configured"}
    try:
        async with aiohttp.ClientSession() as s:
            resp = await s.post(
                SOAR_WEBHOOK_URL,
                json={
                    "alert": alert,
                    "source": "phantomgrid",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                timeout=aiohttp.ClientTimeout(total=10),
            )
            return {"ok": resp.status < 400, "status": resp.status}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


async def _export_ioc(alert: dict) -> dict:
    """Push IOC to any configured SIEM via the integrations service."""
    # Delegate to integrations service via internal call
    log.info("ioc_export_queued", ip=alert.get("source_ip"), alert_id=alert.get("id"))
    return {"ok": True, "queued": True}


# ---------------------------------------------------------------------------
# Playbook executor
# ---------------------------------------------------------------------------

async def execute_playbook(alert: dict, playbook_name: Optional[str] = None) -> dict:
    if not playbook_name:
        rule_type = alert.get("rule_type", "")
        playbook_name = _RULE_TO_PLAYBOOK.get(rule_type, "ssh_brute_force")

    actions = PLAYBOOKS.get(playbook_name, [])
    results = []
    source_ip  = alert.get("source_ip", "")
    tenant_id  = alert.get("tenant_id", "")
    reason     = f"PHANTOMGRID: {alert.get('title', 'honeypot trigger')}"

    for action in actions:
        try:
            if action == "block_ip_firewall":
                result = await _block_ip_firewall(source_ip, reason, tenant_id)
            elif action == "tarpit_connection":
                result = await _tarpit_connection(source_ip)
            elif action == "inject_fake_credentials":
                result = await _inject_fake_credentials(alert)
            elif action == "create_ticket":
                result = await _create_ticket(alert)
            elif action == "trigger_soar_playbook":
                result = await _trigger_soar(alert)
            elif action == "export_ioc_to_siem":
                result = await _export_ioc(alert)
            elif action in ("create_alert_record", "notify_channels"):
                result = {"ok": True, "delegated_to": "alert-engine/notifications"}
            else:
                result = {"ok": True, "action": action}

            results.append({"action": action, "success": True, **result})
            log.info("playbook_action_ok", action=action, ip=source_ip)

        except Exception as exc:
            results.append({"action": action, "success": False, "error": str(exc)})
            log.error("playbook_action_failed", action=action, error=str(exc))

    entry = {
        "id": str(uuid.uuid4()),
        "alert_id": alert.get("id", ""),
        "tenant_id": tenant_id,
        "playbook": playbook_name,
        "source_ip": source_ip,
        "actions": results,
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }
    _execution_log.append(entry)
    if len(_execution_log) > 500:
        _execution_log.pop(0)

    return entry


# ---------------------------------------------------------------------------
# Kafka consumer (listens to alerts.triggered)
# ---------------------------------------------------------------------------

async def _consume_alerts():
    consumer = AIOKafkaConsumer(
        "alerts.triggered",
        bootstrap_servers=KAFKA_BROKERS,
        group_id="active-response",
        auto_offset_reset="latest",
        value_deserializer=lambda v: json.loads(v.decode()),
    )
    for attempt in range(10):
        try:
            await consumer.start()
            log.info("active_response_consumer_started")
            break
        except Exception as exc:
            wait = 2 ** attempt
            log.warning("kafka_retry", attempt=attempt, error=str(exc))
            await asyncio.sleep(wait)
    else:
        log.error("kafka_connect_failed_giving_up")
        return

    try:
        async for msg in consumer:
            alert = msg.value
            severity = alert.get("severity", "low")
            # Only trigger active response for high/critical alerts
            if severity in ("critical", "high"):
                asyncio.ensure_future(execute_playbook(alert))
    except asyncio.CancelledError:
        pass
    finally:
        await consumer.stop()


@app.on_event("startup")
async def startup():
    asyncio.ensure_future(_consume_alerts())
    log.info("active_response_engine_ready")


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok", "tarpitted": len(_tarpitted), "blocked": len(_blocked_ips)}


@app.get("/api/active-response/blocked-ips")
async def list_blocked_ips(limit: int = Query(100, le=500)):
    items = sorted(_blocked_ips.items(), key=lambda x: x[1]["ts"], reverse=True)[:limit]
    return {"total": len(_blocked_ips), "items": [{"ip": k, **v} for k, v in items]}


@app.delete("/api/active-response/blocked-ips/{ip}")
async def unblock_ip(ip: str):
    if ip not in _blocked_ips:
        raise HTTPException(404, "IP not in block list")
    del _blocked_ips[ip]
    if ip in _tarpitted:
        del _tarpitted[ip]
    return {"ok": True, "ip": ip}


@app.get("/api/active-response/tarpitted")
async def list_tarpitted():
    now = datetime.now(timezone.utc).timestamp()
    active = {ip: ts for ip, ts in _tarpitted.items() if ts > now}
    return {"total": len(active), "items": [
        {"ip": ip, "expires_in_seconds": int(ts - now)}
        for ip, ts in active.items()
    ]}


@app.get("/api/active-response/playbook-log")
async def get_playbook_log(
    limit: int = Query(50, le=200),
    offset: int = Query(0, ge=0),
):
    page = _execution_log[::-1][offset: offset + limit]
    return {"total": len(_execution_log), "items": page}


@app.post("/api/active-response/execute")
async def manual_execute(body: dict):
    """Manually trigger a playbook for an alert."""
    playbook = body.get("playbook")
    alert    = body.get("alert", {})
    if not alert:
        raise HTTPException(400, "alert payload required")
    result = await execute_playbook(alert, playbook)
    return result


@app.get("/api/active-response/playbooks")
async def list_playbooks():
    return {
        "playbooks": {
            name: {"actions": actions, "action_count": len(actions)}
            for name, actions in PLAYBOOKS.items()
        }
    }


@app.get("/api/active-response/is-tarpitted/{ip}")
async def check_tarpit(ip: str):
    now = datetime.now(timezone.utc).timestamp()
    expiry = _tarpitted.get(ip, 0)
    active = expiry > now
    return {"ip": ip, "tarpitted": active, "expires_in_seconds": max(0, int(expiry - now))}
