import asyncio, json, os
from collections import defaultdict, deque
from jose import jwt
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from backend.shared.kafka import create_consumer

app = FastAPI(title='realtime')
SECRET = os.getenv('JWT_SECRET', 'dev-secret')
clients = defaultdict(list)
queues = defaultdict(lambda: deque(maxlen=500))

@app.get('/health')
async def health(): return {'status':'ok'}

@app.websocket('/ws')
async def ws_endpoint(ws: WebSocket):
    token = ws.query_params.get('token')
    if not token:
        await ws.close(); return
    claims = jwt.decode(token, SECRET, algorithms=['HS256'])
    tid = claims.get('tid')
    await ws.accept()
    clients[tid].append(ws)
    try:
        while True:
            await ws.send_json({'type':'ping'})
            await asyncio.sleep(30)
    except WebSocketDisconnect:
        clients[tid] = [c for c in clients[tid] if c != ws]

async def kafka_loop(topic):
    c = await create_consumer(topic, 'realtime')
    async for msg in c:
        d = json.loads(msg.value)
        tid = d.get('tenant_id')
        for ws in list(clients.get(tid, [])):
            try: await ws.send_json({'topic':topic, 'payload':d})
            except Exception: pass
