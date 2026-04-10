import asyncio
import json
import os
from collections import defaultdict, deque

from jose import jwt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect

from backend.shared.kafka import create_consumer

app = FastAPI(title="realtime")
SECRET = os.getenv("JWT_SECRET", "dev-secret")

# tenant_id -> [ws]
clients = defaultdict(list)
# tenant_id -> bounded event queue (drop oldest on pressure)
queues = defaultdict(lambda: deque(maxlen=500))


@app.get("/health")
async def health():
    return {"status": "ok"}


async def _consumer(topic: str):
    c = await create_consumer(topic, "realtime")
    try:
        async for msg in c:
            d = json.loads(msg.value)
            tid = str(d.get("tenant_id"))
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
        await ws.close()
        return

    try:
        claims = jwt.decode(token, SECRET, algorithms=["HS256", "RS256"])
    except Exception:
        await ws.close(code=4401)
        return

    tid = str(claims.get("tid"))
    if not tid:
        await ws.close(code=4401)
        return

    await ws.accept()
    clients[tid].append(ws)

    try:
        while True:
            # heartbeat
            await ws.send_json({"type": "ping"})

            # flush queued events for tenant (max 100 per tick)
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
