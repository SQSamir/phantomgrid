import asyncio
import json
import os
from collections import defaultdict, deque

from jose import jwt, JWTError
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from backend.shared.kafka import create_consumer

app = FastAPI(title="realtime")

from prometheus_fastapi_instrumentator import Instrumentator
Instrumentator().instrument(app).expose(app)

# ---------------------------------------------------------------------------
# JWT material (mirrors auth-service / api-gateway config)
# ---------------------------------------------------------------------------
PUBLIC_KEY_PATH = os.getenv("JWT_PUBLIC_KEY_PATH", "/run/secrets/jwt_public.pem")
_JWT_SECRET_ENV = os.getenv("JWT_SECRET", "")

_has_rs256_key = os.path.exists(PUBLIC_KEY_PATH)
if not _has_rs256_key and not _JWT_SECRET_ENV:
    raise RuntimeError(
        "No JWT verification material found. "
        "Mount the RS256 public key or set JWT_SECRET."
    )

def _jwt_verify_material():
    if os.path.exists(PUBLIC_KEY_PATH):
        with open(PUBLIC_KEY_PATH, "r", encoding="utf-8") as f:
            pub = f.read()
        return "RS256", pub
    return "HS256", _JWT_SECRET_ENV

def _decode_ws_token(token: str) -> dict | None:
    algo, key = _jwt_verify_material()
    try:
        return jwt.decode(token, key, algorithms=[algo])
    except JWTError:
        return None

# ---------------------------------------------------------------------------
# Per-tenant state
# tenant_id -> [ws]  /  tenant_id -> bounded event queue (drop oldest)
# ---------------------------------------------------------------------------
clients: dict[str, list] = defaultdict(list)
queues: dict[str, deque] = defaultdict(lambda: deque(maxlen=500))


@app.get("/health")
async def health():
    return {"status": "ok"}


async def _consumer(topic: str):
    c = await create_consumer(topic, "realtime")
    try:
        async for msg in c:
            d = json.loads(msg.value)
            tid = str(d.get("tenant_id", ""))
            if not tid:
                continue
            queues[tid].append({"topic": topic, "payload": d})
    finally:
        await c.stop()


@app.on_event("startup")
async def startup_event():
    app.state.t1 = asyncio.create_task(_consumer("events.enriched"))
    app.state.t2 = asyncio.create_task(_consumer("alerts.triggered"))


@app.on_event("shutdown")
async def shutdown_event():
    for t in [getattr(app.state, "t1", None), getattr(app.state, "t2", None)]:
        if t:
            t.cancel()


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket):
    token = ws.query_params.get("token")
    if not token:
        await ws.close(code=4401)
        return

    claims = _decode_ws_token(token)
    if claims is None:
        await ws.close(code=4401)
        return

    tid = str(claims.get("tid", ""))
    if not tid:
        await ws.close(code=4401)
        return

    await ws.accept()
    clients[tid].append(ws)

    try:
        while True:
            await ws.send_json({"type": "ping"})

            # Flush queued events for this tenant (max 100 per tick)
            sent = 0
            while queues[tid] and sent < 100:
                item = queues[tid].popleft()
                await ws.send_json(item)
                sent += 1

            await asyncio.sleep(1)
    except WebSocketDisconnect:
        pass
    finally:
        clients[tid] = [c for c in clients[tid] if c != ws]
