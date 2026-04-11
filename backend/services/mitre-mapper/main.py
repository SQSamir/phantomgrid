"""
MITRE ATT&CK Mapper service.

Endpoints
---------
GET  /api/mitre/techniques              — list all techniques referenced in mappings
GET  /api/mitre/techniques/{id}         — detail for a single technique ID
POST /api/mitre/map                     — map (protocol, event_type) → technique IDs
GET  /api/mitre/coverage                — coverage matrix: protocol × event_type → techniques
GET  /api/mitre/events/{event_id}       — show MITRE techniques attached to a stored event
GET  /api/mitre/alerts/{alert_id}       — show MITRE techniques attached to a stored alert
GET  /api/mitre/stats                   — technique frequency across tenant events

The technique metadata (name, tactic, url) is stored inline — we do not call the
live MITRE STIX API so the service works fully air-gapped.
"""
from fastapi import FastAPI, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select, func, text
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.db import get_db, tenant_db
from backend.shared.mitre_map import MITRE_MAPPING, get_techniques, get_all_technique_ids
from backend.shared.models.alert import Alert
from backend.shared.models.event import Event
from backend.shared.tenant_context import TenantContext, require_tenant

app = FastAPI(title="mitre-mapper")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

# ---------------------------------------------------------------------------
# Static technique catalogue (subset covering all IDs used in mitre_map.py)
# ---------------------------------------------------------------------------

_TECHNIQUES: dict[str, dict] = {
    "T1005":    {"name": "Data from Local System",               "tactic": "collection"},
    "T1021":    {"name": "Remote Services",                      "tactic": "lateral-movement"},
    "T1021.001":{"name": "Remote Desktop Protocol",              "tactic": "lateral-movement"},
    "T1021.002":{"name": "SMB/Windows Admin Shares",             "tactic": "lateral-movement"},
    "T1021.005":{"name": "VNC",                                  "tactic": "lateral-movement"},
    "T1039":    {"name": "Data from Network Shared Drive",       "tactic": "collection"},
    "T1040":    {"name": "Network Sniffing",                     "tactic": "credential-access"},
    "T1041":    {"name": "Exfiltration Over C2 Channel",         "tactic": "exfiltration"},
    "T1046":    {"name": "Network Service Discovery",            "tactic": "discovery"},
    "T1048":    {"name": "Exfiltration Over Alternative Protocol","tactic": "exfiltration"},
    "T1056.003":{"name": "Web Portal Capture",                   "tactic": "collection"},
    "T1059":    {"name": "Command and Scripting Interpreter",    "tactic": "execution"},
    "T1059.003":{"name": "Windows Command Shell",                "tactic": "execution"},
    "T1059.004":{"name": "Unix Shell",                           "tactic": "execution"},
    "T1071.004":{"name": "DNS",                                  "tactic": "command-and-control"},
    "T1074":    {"name": "Data Staged",                          "tactic": "collection"},
    "T1078":    {"name": "Valid Accounts",                       "tactic": "defense-evasion"},
    "T1078.001":{"name": "Default Accounts",                     "tactic": "defense-evasion"},
    "T1083":    {"name": "File and Directory Discovery",         "tactic": "discovery"},
    "T1087.002":{"name": "Domain Account",                       "tactic": "discovery"},
    "T1090":    {"name": "Proxy",                                "tactic": "command-and-control"},
    "T1098.004":{"name": "SSH Authorized Keys",                  "tactic": "persistence"},
    "T1105":    {"name": "Ingress Tool Transfer",                "tactic": "command-and-control"},
    "T1110":    {"name": "Brute Force",                          "tactic": "credential-access"},
    "T1110.001":{"name": "Password Guessing",                    "tactic": "credential-access"},
    "T1110.003":{"name": "Password Spraying",                    "tactic": "credential-access"},
    "T1110.004":{"name": "Credential Stuffing",                  "tactic": "credential-access"},
    "T1113":    {"name": "Screen Capture",                       "tactic": "collection"},
    "T1115":    {"name": "Clipboard Data",                       "tactic": "collection"},
    "T1135":    {"name": "Network Share Discovery",              "tactic": "discovery"},
    "T1187":    {"name": "Forced Authentication",                "tactic": "credential-access"},
    "T1189":    {"name": "Drive-by Compromise",                  "tactic": "initial-access"},
    "T1190":    {"name": "Exploit Public-Facing Application",    "tactic": "initial-access"},
    "T1496":    {"name": "Resource Hijacking",                   "tactic": "impact"},
    "T1498.002":{"name": "Reflection Amplification",             "tactic": "impact"},
    "T1505":    {"name": "Server Software Component",            "tactic": "persistence"},
    "T1505.003":{"name": "Web Shell",                            "tactic": "persistence"},
    "T1528":    {"name": "Steal Application Access Token",       "tactic": "credential-access"},
    "T1530":    {"name": "Data from Cloud Storage",              "tactic": "collection"},
    "T1534":    {"name": "Internal Spearphishing",               "tactic": "lateral-movement"},
    "T1550.002":{"name": "Pass the Hash",                        "tactic": "defense-evasion"},
    "T1552.005":{"name": "Cloud Instance Metadata API",          "tactic": "credential-access"},
    "T1552.007":{"name": "Container API",                        "tactic": "credential-access"},
    "T1557.001":{"name": "LLMNR/NBT-NS Poisoning and SMB Relay", "tactic": "credential-access"},
    "T1558.003":{"name": "Kerberoasting",                        "tactic": "credential-access"},
    "T1562.001":{"name": "Disable or Modify Tools",              "tactic": "defense-evasion"},
    "T1565.002":{"name": "Transmitted Data Manipulation",        "tactic": "impact"},
    "T1568.002":{"name": "Domain Generation Algorithms",         "tactic": "command-and-control"},
    "T1570":    {"name": "Lateral Tool Transfer",                "tactic": "lateral-movement"},
    "T1572":    {"name": "Protocol Tunneling",                   "tactic": "command-and-control"},
    "T1590":    {"name": "Gather Victim Network Information",    "tactic": "reconnaissance"},
    "T1590.002":{"name": "DNS",                                  "tactic": "reconnaissance"},
    "T1595.001":{"name": "Scanning IP Blocks",                   "tactic": "reconnaissance"},
    "T1595.002":{"name": "Vulnerability Scanning",               "tactic": "reconnaissance"},
    "T1609":    {"name": "Container Administration Command",     "tactic": "execution"},
    "T1610":    {"name": "Deploy Container",                     "tactic": "defense-evasion"},
    "T1611":    {"name": "Escape to Host",                       "tactic": "privilege-escalation"},
    "T1485":    {"name": "Data Destruction",                     "tactic": "impact"},
    "T1486":    {"name": "Data Encrypted for Impact",            "tactic": "impact"},
}

_MITRE_BASE_URL = "https://attack.mitre.org/techniques/"


def _enrich(tid: str) -> dict:
    meta = _TECHNIQUES.get(tid, {})
    base = tid.split(".")[0]
    return {
        "id": tid,
        "name": meta.get("name", "Unknown"),
        "tactic": meta.get("tactic", "unknown"),
        "url": f"{_MITRE_BASE_URL}{base}/{tid.replace('.', '/')}" if "." in tid else f"{_MITRE_BASE_URL}{tid}/",
    }


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Technique catalogue
# ---------------------------------------------------------------------------

@app.get("/api/mitre/techniques")
async def list_techniques(
    tactic: str | None = Query(None),
    ctx: TenantContext = Depends(require_tenant),
):
    """List all technique IDs and metadata referenced in the mapping table."""
    ids = get_all_technique_ids()
    result = [_enrich(tid) for tid in ids]
    if tactic:
        result = [t for t in result if t["tactic"] == tactic]
    return {"total": len(result), "items": result}


@app.get("/api/mitre/techniques/{technique_id}")
async def get_technique(
    technique_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    tid = technique_id.upper()
    if tid not in _TECHNIQUES:
        raise HTTPException(404, "technique not found")
    # Find all (protocol, event_type) pairs that map to this technique
    triggers = [
        {"protocol": k[0], "event_type": k[1]}
        for k, ids in MITRE_MAPPING.items()
        if tid in ids
    ]
    return {**_enrich(tid), "triggered_by": triggers}


# ---------------------------------------------------------------------------
# Mapping lookup
# ---------------------------------------------------------------------------

class MapRequest(BaseModel):
    protocol: str
    event_type: str


@app.post("/api/mitre/map")
async def map_event(
    body: MapRequest,
    ctx: TenantContext = Depends(require_tenant),
):
    ids = get_techniques(body.protocol, body.event_type)
    return {
        "protocol": body.protocol.upper(),
        "event_type": body.event_type,
        "techniques": [_enrich(tid) for tid in ids],
    }


# ---------------------------------------------------------------------------
# Coverage matrix
# ---------------------------------------------------------------------------

@app.get("/api/mitre/coverage")
async def coverage(ctx: TenantContext = Depends(require_tenant)):
    """Full protocol × event_type → technique mapping."""
    rows = []
    for (protocol, event_type), ids in sorted(MITRE_MAPPING.items()):
        rows.append({
            "protocol": protocol,
            "event_type": event_type,
            "techniques": [_enrich(tid) for tid in ids],
        })
    return {"total": len(rows), "mappings": rows}


# ---------------------------------------------------------------------------
# Per-event and per-alert MITRE enrichment
# ---------------------------------------------------------------------------

@app.get("/api/mitre/events/{event_id}")
async def event_techniques(
    event_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        ev = await db.scalar(
            select(Event).where(Event.id == event_id, Event.tenant_id == ctx.tenant_id)
        )
    if not ev:
        raise HTTPException(404, "event not found")
    stored = ev.mitre_technique_ids or []
    # Also compute live from protocol + event_type for completeness
    live = get_techniques(ev.protocol, ev.event_type)
    all_ids = list(dict.fromkeys(stored + live))  # deduplicate, preserve order
    return {
        "event_id": event_id,
        "protocol": ev.protocol,
        "event_type": ev.event_type,
        "techniques": [_enrich(tid) for tid in all_ids],
    }


@app.get("/api/mitre/alerts/{alert_id}")
async def alert_techniques(
    alert_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        al = await db.scalar(
            select(Alert).where(Alert.id == alert_id, Alert.tenant_id == ctx.tenant_id)
        )
    if not al:
        raise HTTPException(404, "alert not found")
    ids = al.mitre_technique_ids or []
    return {
        "alert_id": alert_id,
        "techniques": [_enrich(tid) for tid in ids],
    }


# ---------------------------------------------------------------------------
# Tenant technique frequency stats
# ---------------------------------------------------------------------------

@app.get("/api/mitre/stats")
async def technique_stats(
    hours: int = Query(168, ge=1, le=720),
    ctx: TenantContext = Depends(require_tenant),
):
    """Return technique ID frequency across events for this tenant."""
    async with tenant_db(ctx.tenant_id) as db:
        rows = await db.execute(
            text("""
                SELECT unnest(mitre_technique_ids) AS technique_id, COUNT(*) AS count
                FROM events
                WHERE tenant_id = :tid
                  AND created_at >= NOW() - (:hours * INTERVAL '1 hour')
                GROUP BY 1
                ORDER BY count DESC
                LIMIT 50
            """),
            {"tid": str(ctx.tenant_id), "hours": hours},
        )
        results = rows.fetchall()
    return {
        "hours": hours,
        "stats": [
            {**_enrich(r.technique_id), "count": r.count}
            for r in results
        ],
    }
