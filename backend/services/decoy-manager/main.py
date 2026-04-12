"""
Decoy Manager — CRUD for decoy networks, decoys, and decoy templates.

Lifecycle transitions:
  draft → deploying  (POST /deploy)
  deploying → active (internal; honeypot-engine signals back via Kafka or
                       a future PATCH — for now we accept a direct PATCH)
  active → paused    (POST /pause)
  paused → active    (POST /resume)
  any → destroyed    (DELETE)

Kafka topic ``decoy.lifecycle`` is published for every status change so the
honeypot-engine can start/stop listeners accordingly.
"""
import json
import random
import secrets
import string
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any

from aiokafka import AIOKafkaProducer
from fastapi import FastAPI, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func, cast
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.asyncio import AsyncSession

from backend.shared.db import get_db, tenant_db
from backend.shared.enums import DecoyStatus
from backend.shared.kafka import create_producer, send_json
from backend.shared.models.artifact import Artifact
from backend.shared.models.decoy import Decoy, DecoyNetwork, DecoyTemplate
from backend.shared.tenant_context import TenantContext, require_tenant

_producer: AIOKafkaProducer | None = None

TOPIC_DECOY_LIFECYCLE = "decoy.lifecycle"


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _producer
    _producer = await create_producer()
    yield
    await _producer.stop()


app = FastAPI(title="decoy-manager", lifespan=lifespan)

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)


def _now() -> datetime:
    return datetime.now(timezone.utc)


async def _publish_lifecycle(decoy: Decoy, event: str) -> None:
    if _producer is None:
        return
    await send_json(_producer, TOPIC_DECOY_LIFECYCLE, {
        "event": event,
        "decoy_id": str(decoy.id),
        "tenant_id": str(decoy.tenant_id),
        "type": decoy.type,
        "config": decoy.config,
        "ip_address": decoy.ip_address,
        "port": decoy.port,
        "status": decoy.status,
        "timestamp": str(_now()),
    })


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class NetworkCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    cidr: str = Field(..., max_length=64)
    vlan_id: int | None = None
    environment_type: str = Field("corporate", max_length=64)
    description: str | None = Field(None, max_length=255)


class NetworkUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    cidr: str | None = Field(None, max_length=64)
    vlan_id: int | None = None
    environment_type: str | None = Field(None, max_length=64)
    description: str | None = Field(None, max_length=255)


class NetworkOut(BaseModel):
    id: str
    name: str
    cidr: str
    vlan_id: int | None
    environment_type: str
    description: str | None
    created_at: str


class DecoyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., max_length=64)
    config: dict[str, Any] = Field(default_factory=dict)
    network_id: str | None = None
    ip_address: str | None = Field(None, max_length=64)
    port: int | None = Field(None, ge=1, le=65535)
    tags: list[str] = Field(default_factory=list)


class DecoyUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    config: dict[str, Any] | None = None
    ip_address: str | None = Field(None, max_length=64)
    port: int | None = Field(None, ge=1, le=65535)
    tags: list[str] | None = None


class DecoyOut(BaseModel):
    id: str
    name: str
    type: str
    config: dict
    status: str
    network_id: str | None
    ip_address: str | None
    port: int | None
    tags: list[str]
    interaction_count: int
    last_interaction_at: str | None
    deployed_at: str | None
    created_at: str
    updated_at: str


class TemplateOut(BaseModel):
    id: str
    name: str
    type: str
    description: str | None
    default_config: dict
    tags: list[str]


# ---------------------------------------------------------------------------
# Serialisers
# ---------------------------------------------------------------------------

def _net_out(n: DecoyNetwork) -> dict:
    return NetworkOut(
        id=str(n.id),
        name=n.name,
        cidr=n.cidr,
        vlan_id=n.vlan_id,
        environment_type=n.environment_type,
        description=n.description,
        created_at=str(n.created_at),
    ).model_dump()


def _decoy_out(d: Decoy) -> dict:
    return DecoyOut(
        id=str(d.id),
        name=d.name,
        type=d.type,
        config=d.config or {},
        status=d.status,
        network_id=str(d.network_id) if d.network_id else None,
        ip_address=d.ip_address,
        port=d.port,
        tags=d.tags or [],
        interaction_count=d.interaction_count or 0,
        last_interaction_at=str(d.last_interaction_at) if d.last_interaction_at else None,
        deployed_at=str(d.deployed_at) if d.deployed_at else None,
        created_at=str(d.created_at),
        updated_at=str(d.updated_at),
    ).model_dump()


def _tmpl_out(t: DecoyTemplate) -> dict:
    return TemplateOut(
        id=str(t.id),
        name=t.name,
        type=t.type,
        description=t.description,
        default_config=t.default_config or {},
        tags=t.tags or [],
    ).model_dump()


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Decoy Networks
# ---------------------------------------------------------------------------

@app.get("/api/decoy-networks")
async def list_networks(
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        rows = await db.execute(
            select(DecoyNetwork)
            .where(DecoyNetwork.tenant_id == ctx.tenant_id)
            .order_by(DecoyNetwork.created_at.desc())
            .offset(offset)
            .limit(limit)
        )
        networks = rows.scalars().all()
        total = await db.scalar(
            select(func.count(DecoyNetwork.id)).where(DecoyNetwork.tenant_id == ctx.tenant_id)
        )
    return {"total": total, "items": [_net_out(n) for n in networks]}


@app.post("/api/decoy-networks", status_code=201)
async def create_network(
    body: NetworkCreate,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        n = DecoyNetwork(
            tenant_id=uuid.UUID(ctx.tenant_id),
            name=body.name,
            cidr=body.cidr,
            vlan_id=body.vlan_id,
            environment_type=body.environment_type,
            description=body.description,
        )
        db.add(n)
        await db.commit()
        await db.refresh(n)
    return _net_out(n)


@app.get("/api/decoy-networks/{network_id}")
async def get_network(
    network_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        n = await db.scalar(
            select(DecoyNetwork).where(
                DecoyNetwork.id == network_id,
                DecoyNetwork.tenant_id == ctx.tenant_id,
            )
        )
    if not n:
        raise HTTPException(404, "network not found")
    return _net_out(n)


@app.patch("/api/decoy-networks/{network_id}")
async def update_network(
    network_id: str,
    body: NetworkUpdate,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        n = await db.scalar(
            select(DecoyNetwork).where(
                DecoyNetwork.id == network_id,
                DecoyNetwork.tenant_id == ctx.tenant_id,
            )
        )
        if not n:
            raise HTTPException(404, "network not found")
        if body.name is not None:
            n.name = body.name
        if body.cidr is not None:
            n.cidr = body.cidr
        if body.vlan_id is not None:
            n.vlan_id = body.vlan_id
        if body.environment_type is not None:
            n.environment_type = body.environment_type
        if body.description is not None:
            n.description = body.description
        await db.commit()
        await db.refresh(n)
    return _net_out(n)


@app.delete("/api/decoy-networks/{network_id}", status_code=204)
async def delete_network(
    network_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        n = await db.scalar(
            select(DecoyNetwork).where(
                DecoyNetwork.id == network_id,
                DecoyNetwork.tenant_id == ctx.tenant_id,
            )
        )
        if not n:
            raise HTTPException(404, "network not found")
        # Block deletion if any active decoys are on this network
        active = await db.scalar(
            select(func.count(Decoy.id)).where(
                Decoy.network_id == network_id,
                Decoy.status.in_([DecoyStatus.ACTIVE, DecoyStatus.DEPLOYING]),
            )
        )
        if active:
            raise HTTPException(409, "cannot delete network with active decoys")
        await db.delete(n)
        await db.commit()


# ---------------------------------------------------------------------------
# Decoys
# ---------------------------------------------------------------------------

@app.get("/api/decoys")
async def list_decoys(
    status: str | None = Query(None),
    network_id: str | None = Query(None),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        q = select(Decoy).where(Decoy.tenant_id == ctx.tenant_id)
        if status:
            q = q.where(Decoy.status == status)
        if network_id:
            q = q.where(Decoy.network_id == network_id)
        q = q.order_by(Decoy.created_at.desc()).offset(offset).limit(limit)
        rows = await db.execute(q)
        decoys = rows.scalars().all()
        count_q = select(func.count(Decoy.id)).where(Decoy.tenant_id == ctx.tenant_id)
        if status:
            count_q = count_q.where(Decoy.status == status)
        total = await db.scalar(count_q)
    return {"total": total, "items": [_decoy_out(d) for d in decoys]}


@app.post("/api/decoys", status_code=201)
async def create_decoy(
    body: DecoyCreate,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        if body.network_id:
            net = await db.scalar(
                select(DecoyNetwork).where(
                    DecoyNetwork.id == body.network_id,
                    DecoyNetwork.tenant_id == ctx.tenant_id,
                )
            )
            if not net:
                raise HTTPException(404, "network not found")
        d = Decoy(
            tenant_id=uuid.UUID(ctx.tenant_id),
            network_id=uuid.UUID(body.network_id) if body.network_id else None,
            name=body.name,
            type=body.type,
            config=body.config,
            status=DecoyStatus.DRAFT,
            ip_address=body.ip_address,
            port=body.port,
            tags=body.tags,
        )
        db.add(d)
        await db.commit()
        await db.refresh(d)
    return _decoy_out(d)


@app.get("/api/decoys/{decoy_id}")
async def get_decoy(
    decoy_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        d = await db.scalar(
            select(Decoy).where(Decoy.id == decoy_id, Decoy.tenant_id == ctx.tenant_id)
        )
    if not d:
        raise HTTPException(404, "decoy not found")
    return _decoy_out(d)


@app.patch("/api/decoys/{decoy_id}")
async def update_decoy(
    decoy_id: str,
    body: DecoyUpdate,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        d = await db.scalar(
            select(Decoy).where(Decoy.id == decoy_id, Decoy.tenant_id == ctx.tenant_id)
        )
        if not d:
            raise HTTPException(404, "decoy not found")
        if d.status not in (DecoyStatus.DRAFT, DecoyStatus.PAUSED):
            raise HTTPException(409, "only draft or paused decoys can be edited")
        if body.name is not None:
            d.name = body.name
        if body.config is not None:
            d.config = body.config
        if body.ip_address is not None:
            d.ip_address = body.ip_address
        if body.port is not None:
            d.port = body.port
        if body.tags is not None:
            d.tags = body.tags
        d.updated_at = _now()
        await db.commit()
        await db.refresh(d)
    return _decoy_out(d)


# Lifecycle transitions

@app.post("/api/decoys/{decoy_id}/deploy")
async def deploy_decoy(
    decoy_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        d = await db.scalar(
            select(Decoy).where(Decoy.id == decoy_id, Decoy.tenant_id == ctx.tenant_id)
        )
        if not d:
            raise HTTPException(404, "decoy not found")
        if d.status != DecoyStatus.DRAFT:
            raise HTTPException(409, f"cannot deploy decoy in status '{d.status}'")
        d.status = DecoyStatus.DEPLOYING
        d.updated_at = _now()
        await db.commit()
        await db.refresh(d)
    await _publish_lifecycle(d, "deploy")
    return _decoy_out(d)


@app.post("/api/decoys/{decoy_id}/activate")
async def activate_decoy(
    decoy_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    """Marks a deploying decoy as active (called by honeypot-engine or operator)."""
    async with tenant_db(ctx.tenant_id) as db:
        d = await db.scalar(
            select(Decoy).where(Decoy.id == decoy_id, Decoy.tenant_id == ctx.tenant_id)
        )
        if not d:
            raise HTTPException(404, "decoy not found")
        if d.status != DecoyStatus.DEPLOYING:
            raise HTTPException(409, f"cannot activate decoy in status '{d.status}'")
        d.status = DecoyStatus.ACTIVE
        d.deployed_at = _now()
        d.updated_at = _now()
        await db.commit()
        await db.refresh(d)
    await _publish_lifecycle(d, "activate")
    return _decoy_out(d)


@app.post("/api/decoys/{decoy_id}/pause")
async def pause_decoy(
    decoy_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        d = await db.scalar(
            select(Decoy).where(Decoy.id == decoy_id, Decoy.tenant_id == ctx.tenant_id)
        )
        if not d:
            raise HTTPException(404, "decoy not found")
        if d.status != DecoyStatus.ACTIVE:
            raise HTTPException(409, f"cannot pause decoy in status '{d.status}'")
        d.status = DecoyStatus.PAUSED
        d.updated_at = _now()
        await db.commit()
        await db.refresh(d)
    await _publish_lifecycle(d, "pause")
    return _decoy_out(d)


@app.post("/api/decoys/{decoy_id}/resume")
async def resume_decoy(
    decoy_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        d = await db.scalar(
            select(Decoy).where(Decoy.id == decoy_id, Decoy.tenant_id == ctx.tenant_id)
        )
        if not d:
            raise HTTPException(404, "decoy not found")
        if d.status != DecoyStatus.PAUSED:
            raise HTTPException(409, f"cannot resume decoy in status '{d.status}'")
        d.status = DecoyStatus.ACTIVE
        d.updated_at = _now()
        await db.commit()
        await db.refresh(d)
    await _publish_lifecycle(d, "resume")
    return _decoy_out(d)


@app.delete("/api/decoys/{decoy_id}", status_code=200)
async def destroy_decoy(
    decoy_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        d = await db.scalar(
            select(Decoy).where(Decoy.id == decoy_id, Decoy.tenant_id == ctx.tenant_id)
        )
        if not d:
            raise HTTPException(404, "decoy not found")
        if d.status == DecoyStatus.DESTROYED:
            raise HTTPException(409, "decoy already destroyed")
        prev_status = d.status
        d.status = DecoyStatus.DESTROYED
        d.updated_at = _now()
        await db.commit()
        await db.refresh(d)
    # Notify honeypot-engine only if it was running
    if prev_status in (DecoyStatus.ACTIVE, DecoyStatus.DEPLOYING, DecoyStatus.PAUSED):
        await _publish_lifecycle(d, "destroy")
    return {"destroyed": True, "decoy_id": decoy_id}


# ---------------------------------------------------------------------------
# Decoy Templates (read-only; seeded by migrations)
# ---------------------------------------------------------------------------

@app.get("/api/decoy-templates")
async def list_templates(
    type_filter: str | None = Query(None, alias="type"),
    db: AsyncSession = Depends(get_db),
    ctx: TenantContext = Depends(require_tenant),
):
    q = select(DecoyTemplate)
    if type_filter:
        q = q.where(DecoyTemplate.type == type_filter)
    q = q.order_by(DecoyTemplate.name)
    rows = await db.execute(q)
    return [_tmpl_out(t) for t in rows.scalars().all()]


@app.get("/api/decoy-templates/{template_id}")
async def get_template(
    template_id: str,
    db: AsyncSession = Depends(get_db),
    ctx: TenantContext = Depends(require_tenant),
):
    t = await db.scalar(select(DecoyTemplate).where(DecoyTemplate.id == template_id))
    if not t:
        raise HTTPException(404, "template not found")
    return _tmpl_out(t)


# ---------------------------------------------------------------------------
# Deception Artifacts  (Lure / Bait / Breadcrumb / Honeytoken)
# ---------------------------------------------------------------------------

ARTIFACT_SUBTYPES = {
    "lure":        ["login_page", "exposed_api"],
    "bait":        ["aws_key", "api_token", "jwt_token", "ssh_key", "db_credentials"],
    "breadcrumb":  ["bash_history", "env_file", "config_file", "network_map"],
    "honeytoken":  ["url_token", "dns_token"],
}


def _rand(chars: str, n: int) -> str:
    return "".join(random.choices(chars, k=n))


def _generate_content(artifact_type: str, subtype: str, base_url: str = "http://localhost:8080") -> dict:
    alpha  = string.ascii_letters + string.digits
    hex_   = string.hexdigits.lower()

    if subtype == "aws_key":
        return {
            "access_key_id":     "AKIA" + _rand(string.ascii_uppercase + string.digits, 16),
            "secret_access_key": secrets.token_urlsafe(30),
            "region":            "us-east-1",
            "profile":           "default",
            "note":              "Plant in ~/.aws/credentials or hardcode in source code",
        }
    if subtype == "api_token":
        return {
            "token":   "ghp_" + secrets.token_hex(18),
            "service": "GitHub",
            "scopes":  ["repo", "admin:org", "read:user"],
            "note":    "Plant in .env files, config files, or CI/CD pipelines",
        }
    if subtype == "jwt_token":
        import base64
        header  = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(
            json.dumps({"sub": "svc-account", "role": "admin", "iat": 1700000000}).encode()
        ).rstrip(b"=").decode()
        sig     = secrets.token_hex(16)
        return {
            "token": f"{header}.{payload}.{sig}",
            "service": "Internal API",
            "note": "Plant in source code comments, config files, or Slack exports",
        }
    if subtype == "ssh_key":
        fake_body = "\n".join(
            _rand(alpha + "+/", 64) for _ in range(25)
        )
        return {
            "private_key": (
                "-----BEGIN RSA PRIVATE KEY-----\n"
                + fake_body + "\n"
                "-----END RSA PRIVATE KEY-----"
            ),
            "key_comment": "deploy@prod-bastion",
            "note": "Plant as ~/.ssh/id_rsa or in a Git repo",
        }
    if subtype == "db_credentials":
        pwd = secrets.token_urlsafe(16)
        return {
            "host":     "prod-db-01.internal",
            "port":     5432,
            "database": "customers_prod",
            "username": "app_readonly",
            "password": pwd,
            "dsn":      f"postgresql://app_readonly:{pwd}@prod-db-01.internal:5432/customers_prod",
            "note":     "Plant in application config, README, or wiki pages",
        }
    if subtype == "bash_history":
        return {
            "filename": ".bash_history",
            "content": (
                "ssh admin@10.10.0.50\n"
                "mysql -h prod-db-01.internal -u root -pS3cr3tP@ss\n"
                "curl -H 'Authorization: Bearer ghp_" + secrets.token_hex(18) + "' https://api.internal/v1/users\n"
                "scp deploy@bastion:/home/deploy/.ssh/id_rsa .\n"
                "kubectl --kubeconfig=./admin.conf get secrets -A\n"
                "aws s3 cp s3://company-backups/db_dump.sql.gz .\n"
            ),
            "note": "Plant as /home/<user>/.bash_history on a decoy workstation",
        }
    if subtype == "env_file":
        return {
            "filename": ".env",
            "content": (
                f"DATABASE_URL=postgresql://app:{secrets.token_urlsafe(12)}@prod-db-01.internal:5432/app_prod\n"
                f"REDIS_URL=redis://:{secrets.token_urlsafe(12)}@cache-01.internal:6379\n"
                f"AWS_ACCESS_KEY_ID=AKIA{_rand(string.ascii_uppercase + string.digits, 16)}\n"
                f"AWS_SECRET_ACCESS_KEY={secrets.token_urlsafe(30)}\n"
                f"JWT_SECRET={secrets.token_hex(32)}\n"
                f"STRIPE_SECRET_KEY=sk_live_{secrets.token_hex(24)}\n"
            ),
            "note": "Plant in application root directory or Git history",
        }
    if subtype == "config_file":
        return {
            "filename": "database.yml",
            "content": (
                "production:\n"
                "  adapter: postgresql\n"
                "  host: prod-db-01.internal\n"
                "  database: app_production\n"
                "  username: app_user\n"
                f"  password: {secrets.token_urlsafe(14)}\n"
                "  pool: 5\n"
            ),
            "note": "Plant in config/ directory of a decoy application server",
        }
    if subtype == "network_map":
        return {
            "filename": "network_topology.txt",
            "content": (
                "=== INTERNAL NETWORK MAP ===\n"
                "Domain Controller:  10.10.0.10  (dc01.corp.internal)\n"
                "Backup DC:          10.10.0.11  (dc02.corp.internal)\n"
                "File Server:        10.10.1.20  (fs01.corp.internal)\n"
                "Finance DB:         10.10.2.50  (fin-db.corp.internal)\n"
                "HR System:          10.10.2.51  (hr-db.corp.internal)\n"
                "Bastion Host:       10.10.0.5   (bastion.corp.internal)\n"
                "VPN Gateway:        203.0.113.1\n"
            ),
            "note": "Plant as a file on a decoy workstation or shared drive",
        }
    if subtype == "login_page":
        token_id = str(uuid.uuid4())
        return {
            "template":      "cisco_vpn",
            "fake_domain":   "vpn.corp-internal.net",
            "capture_url":   f"{base_url}/api/artifacts/t/{token_id}",
            "token_id":      token_id,
            "note":          "Configure in HTTP honeypot or serve via nginx",
        }
    if subtype == "url_token":
        token_id = secrets.token_hex(16)
        return {
            "token_id":    token_id,
            "trigger_url": f"{base_url}/api/artifacts/t/{token_id}",
            "note":        "Embed in documents, emails, HTML files, or config",
        }
    if subtype == "dns_token":
        label = secrets.token_hex(8)
        return {
            "hostname":   f"{label}.canary.yourdomain.com",
            "token_id":   label,
            "note":       "Plant in /etc/hosts or DNS configs; trigger fires on DNS lookup",
        }
    if subtype == "exposed_api":
        token_id = secrets.token_hex(16)
        return {
            "token_id":    token_id,
            "trigger_url": f"{base_url}/api/artifacts/t/{token_id}",
            "fake_path":   "/api/v1/internal/admin",
            "note":        "Register as a fake endpoint in your API docs or Swagger",
        }
    return {}


class ArtifactCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    type: str = Field(..., pattern="^(lure|bait|breadcrumb|honeytoken)$")
    subtype: str = Field(..., max_length=64)
    description: str | None = Field(None, max_length=512)


class ArtifactOut(BaseModel):
    id: str
    name: str
    type: str
    subtype: str
    description: str | None
    content: dict
    status: str
    trigger_count: int
    last_triggered_at: str | None
    created_at: str


def _artifact_out(a: Artifact) -> dict:
    return ArtifactOut(
        id=str(a.id),
        name=a.name,
        type=a.type,
        subtype=a.subtype,
        description=a.description,
        content=a.content or {},
        status=a.status,
        trigger_count=a.trigger_count or 0,
        last_triggered_at=str(a.last_triggered_at) if a.last_triggered_at else None,
        created_at=str(a.created_at),
    ).model_dump()


@app.get("/api/artifacts")
async def list_artifacts(
    type_filter: str | None = Query(None, alias="type"),
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        q = select(Artifact).where(Artifact.tenant_id == ctx.tenant_id)
        if type_filter:
            q = q.where(Artifact.type == type_filter)
        q = q.order_by(Artifact.created_at.desc()).offset(offset).limit(limit)
        rows = await db.execute(q)
        artifacts = rows.scalars().all()
        total = await db.scalar(
            select(func.count(Artifact.id)).where(Artifact.tenant_id == ctx.tenant_id)
        )
    return {"total": total, "items": [_artifact_out(a) for a in artifacts]}


@app.post("/api/artifacts", status_code=201)
async def create_artifact(
    body: ArtifactCreate,
    request: Request,
    ctx: TenantContext = Depends(require_tenant),
):
    valid_subtypes = ARTIFACT_SUBTYPES.get(body.type, [])
    if body.subtype not in valid_subtypes:
        raise HTTPException(400, f"invalid subtype '{body.subtype}' for type '{body.type}'. valid: {valid_subtypes}")

    base_url = str(request.base_url).rstrip("/")
    content = _generate_content(body.type, body.subtype, base_url)

    async with tenant_db(ctx.tenant_id) as db:
        a = Artifact(
            tenant_id=uuid.UUID(ctx.tenant_id),
            name=body.name,
            type=body.type,
            subtype=body.subtype,
            description=body.description,
            content=content,
            status="active",
        )
        db.add(a)
        await db.commit()
        await db.refresh(a)
    return _artifact_out(a)


@app.delete("/api/artifacts/{artifact_id}", status_code=204)
async def delete_artifact(
    artifact_id: str,
    ctx: TenantContext = Depends(require_tenant),
):
    async with tenant_db(ctx.tenant_id) as db:
        a = await db.scalar(
            select(Artifact).where(Artifact.id == artifact_id, Artifact.tenant_id == ctx.tenant_id)
        )
        if not a:
            raise HTTPException(404, "artifact not found")
        await db.delete(a)
        await db.commit()


# ---------------------------------------------------------------------------
# Honeytoken trigger — PUBLIC endpoint (no JWT required)
# Accessed by attacker when they use a planted token/URL
# ---------------------------------------------------------------------------

@app.get("/api/artifacts/t/{token_id}")
async def trigger_honeytoken(token_id: str, request: Request):
    """Called when an attacker uses a planted honeytoken URL.
    No authentication required — the token IS the authentication.
    """
    from sqlalchemy import text as sa_text
    from backend.shared.db import get_db as _get_db

    attacker_ip = request.headers.get("X-Forwarded-For", request.client.host if request.client else "unknown")

    # Look up artifact by token_id in JSONB content
    async for db in _get_db():
        row = await db.execute(
            sa_text(
                "SELECT id, tenant_id, name, subtype, trigger_count "
                "FROM artifacts "
                "WHERE content->>'token_id' = :token_id AND status = 'active' "
                "LIMIT 1"
            ),
            {"token_id": token_id},
        )
        artifact = row.mappings().first()

        if artifact:
            # Increment trigger count
            await db.execute(
                sa_text(
                    "UPDATE artifacts SET trigger_count = trigger_count + 1, "
                    "last_triggered_at = now() "
                    "WHERE id = :id"
                ),
                {"id": str(artifact["id"])},
            )
            await db.commit()

            # Emit event to Kafka → event-processor will save it
            if _producer:
                import json as _json
                from datetime import datetime as _dt
                await _producer.send_and_wait(
                    "events.raw",
                    _json.dumps({
                        "event_id":   str(uuid.uuid4()),
                        "timestamp":  _dt.utcnow().isoformat(),
                        "tenant_id":  str(artifact["tenant_id"]),
                        "source_ip":  attacker_ip,
                        "protocol":   "HONEYTOKEN",
                        "event_type": "honeytoken_triggered",
                        "severity":   "critical",
                        "raw_data": {
                            "token_id":      token_id,
                            "artifact_name": artifact["name"],
                            "subtype":       artifact["subtype"],
                            "trigger_count": artifact["trigger_count"] + 1,
                            "user_agent":    request.headers.get("User-Agent", ""),
                            "referer":       request.headers.get("Referer", ""),
                        },
                        "tags": ["honeytoken_triggered", "deception_artifact"],
                    }).encode(),
                )

    # Return a convincing but benign response regardless of match
    return {"status": "ok"}
