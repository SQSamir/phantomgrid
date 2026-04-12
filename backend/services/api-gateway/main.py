import os
import time
import uuid
from functools import lru_cache

import httpx
import structlog
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from jose import jwt, JWTError
from slowapi import Limiter
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# JWT material (mirrors auth-service config)
# ---------------------------------------------------------------------------
PRIVATE_KEY_PATH = os.getenv("JWT_PRIVATE_KEY_PATH", "/run/secrets/jwt_private.pem")
PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", "/run/secrets/jwt_public.pem")
_JWT_SECRET_ENV = os.getenv("JWT_SECRET", "")

_has_rs256_keys = os.path.exists(PUBLIC_KEY_PATH)
if not _has_rs256_keys and not _JWT_SECRET_ENV:
    raise RuntimeError(
        "No JWT verification material found. "
        "Mount the RS256 public key or set JWT_SECRET."
    )

@lru_cache(maxsize=1)
def _jwt_verify_material():
    """Load JWT verify key once and cache — file I/O should not happen per-request."""
    if os.path.exists(PUBLIC_KEY_PATH):
        with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            pub = f.read()
        return "RS256", pub
    return "HS256", _JWT_SECRET_ENV

def _decode_token(token: str) -> dict:
    algo, key = _jwt_verify_material()
    try:
        return jwt.decode(token, key, algorithms=[algo])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="invalid or expired token") from exc

# ---------------------------------------------------------------------------
# Upstream routing table
# ---------------------------------------------------------------------------
_UPSTREAM = {
    "/auth":           os.getenv("UPSTREAM_AUTH",           "http://auth-service:8080"),
    "/api/events":     os.getenv("UPSTREAM_EVENTS",         "http://event-processor:8080"),
    "/api/alerts":     os.getenv("UPSTREAM_ALERTS",         "http://alert-engine:8080"),
    "/api/analytics":  os.getenv("UPSTREAM_ANALYTICS",      "http://analytics:8080"),
    "/api/decoys":     os.getenv("UPSTREAM_DECOYS",         "http://decoy-manager:8080"),
    "/api/decoy-networks": os.getenv("UPSTREAM_DECOYS",     "http://decoy-manager:8080"),
    "/api/decoy-templates": os.getenv("UPSTREAM_DECOYS",    "http://decoy-manager:8080"),
    "/api/artifacts":  os.getenv("UPSTREAM_DECOYS",         "http://decoy-manager:8080"),
    "/api/tenants":    os.getenv("UPSTREAM_TENANTS",        "http://tenant-manager:8080"),
    "/api/mitre":      os.getenv("UPSTREAM_MITRE",          "http://mitre-mapper:8080"),
    "/api/notifications": os.getenv("UPSTREAM_NOTIFICATIONS", "http://notifications:8080"),
    "/api/integrations":     os.getenv("UPSTREAM_INTEGRATIONS",      "http://integrations:8080"),
    "/auth/admin":           os.getenv("UPSTREAM_AUTH",               "http://auth-service:8080"),
    "/api/active-response":  os.getenv("UPSTREAM_ACTIVE_RESPONSE",   "http://active-response:8080"),
    "/ws":                   os.getenv("UPSTREAM_REALTIME",           "http://realtime:8080"),
}

# Paths that do not require a valid JWT (matched by prefix)
_PUBLIC_PREFIXES = {
    "/health",
    "/auth/register",
    "/auth/login",
    "/auth/refresh",
    "/api/artifacts/t",   # honeytoken trigger — no JWT, token_id is the auth
}

def _resolve_upstream(path: str) -> str | None:
    for prefix, upstream in _UPSTREAM.items():
        if path == prefix or path.startswith(prefix + "/"):
            return upstream
    return None

def _is_public(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in _PUBLIC_PREFIXES)

# ---------------------------------------------------------------------------
# Rate limiter  (100 requests / minute per IP by default)
# ---------------------------------------------------------------------------
_RATE_LIMIT = os.getenv("RATE_LIMIT", "100/minute")
limiter = Limiter(key_func=get_remote_address, default_limits=[_RATE_LIMIT])

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
app = FastAPI(title="api-gateway")
app.state.limiter = limiter

_CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

@app.exception_handler(RateLimitExceeded)
async def _rate_limit_handler(request: Request, exc: RateLimitExceeded):
    ip = get_remote_address(request)
    log.warning("rate_limit_exceeded", ip=ip, path=request.url.path)
    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})

# Shared httpx client (connection-pooled)
_http_client: httpx.AsyncClient | None = None

@app.on_event("startup")
async def _startup():
    global _http_client
    _http_client = httpx.AsyncClient(timeout=30.0)

@app.on_event("shutdown")
async def _shutdown():
    if _http_client:
        await _http_client.aclose()

# ---------------------------------------------------------------------------
# Health check (no auth, no proxying)
# ---------------------------------------------------------------------------
@app.get("/health")
async def health():
    return {"status": "ok"}

# ---------------------------------------------------------------------------
# Catch-all proxy handler
# ---------------------------------------------------------------------------
@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"],
)
@limiter.limit(_RATE_LIMIT)
async def proxy(request: Request, path: str):
    full_path = "/" + path
    upstream = _resolve_upstream(full_path)
    if upstream is None:
        raise HTTPException(status_code=404, detail="no route for this path")

    # ------------------------------------------------------------------
    # Authentication gate
    # ------------------------------------------------------------------
    tenant_id: str | None = None
    user_id: str | None = None
    role: str | None = None

    if not _is_public(full_path):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="missing bearer token")
        token = auth_header[len("Bearer "):]
        claims = _decode_token(token)
        tenant_id = claims.get("tid")
        user_id = claims.get("sub")
        role = claims.get("role")
        if not tenant_id or not user_id:
            raise HTTPException(status_code=401, detail="token missing required claims")

    # ------------------------------------------------------------------
    # Forward request to upstream
    # ------------------------------------------------------------------
    request_id = str(uuid.uuid4())
    target_url = upstream + full_path
    if request.url.query:
        target_url += "?" + request.url.query

    # Strip hop-by-hop headers; inject context headers
    forward_headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in {
            "host", "transfer-encoding", "connection",
            "keep-alive", "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "upgrade",
        }
    }
    forward_headers["X-Request-ID"] = request_id
    if tenant_id:
        forward_headers["X-Tenant-ID"] = tenant_id
    if user_id:
        forward_headers["X-User-ID"] = user_id
    if role:
        forward_headers["X-User-Role"] = role

    body = await request.body()

    t0 = time.monotonic()
    try:
        upstream_resp = await _http_client.request(
            method=request.method,
            url=target_url,
            headers=forward_headers,
            content=body,
        )
    except httpx.ConnectError:
        log.error("upstream_unavailable", upstream=upstream, path=full_path, request_id=request_id)
        raise HTTPException(status_code=502, detail="upstream service unavailable")
    except httpx.TimeoutException:
        log.error("upstream_timeout", upstream=upstream, path=full_path, request_id=request_id)
        raise HTTPException(status_code=504, detail="upstream service timed out")

    elapsed_ms = round((time.monotonic() - t0) * 1000)
    log.info(
        "proxied",
        method=request.method,
        path=full_path,
        upstream=upstream,
        status=upstream_resp.status_code,
        ms=elapsed_ms,
        request_id=request_id,
        tenant_id=tenant_id,
    )

    # Strip hop-by-hop headers from upstream response
    response_headers = {
        k: v for k, v in upstream_resp.headers.items()
        if k.lower() not in {
            "transfer-encoding", "connection", "keep-alive",
            "proxy-authenticate", "proxy-authorization",
            "te", "trailers", "upgrade",
        }
    }
    response_headers["X-Request-ID"] = request_id

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        headers=response_headers,
        media_type=upstream_resp.headers.get("content-type"),
    )
