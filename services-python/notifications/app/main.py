from fastapi import FastAPI
from pydantic import BaseModel
import httpx

app = FastAPI(title="phantomgrid-notifications")

class AlertPayload(BaseModel):
    tenant_id: str
    severity: str
    summary: str
    source_ip: str | None = None
    mitre_technique: str | None = None

@app.get('/health')
def health():
    return {"status": "ok", "service": "notifications"}

@app.post('/notify/webhook')
async def notify_webhook(url: str, payload: AlertPayload):
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(url, json=payload.model_dump())
    return {"ok": r.is_success, "status": r.status_code}

@app.post('/notify/telegram')
async def notify_telegram(bot_token: str, chat_id: str, payload: AlertPayload):
    text = f"[{payload.severity}] {payload.summary}\nIP: {payload.source_ip}\nMITRE: {payload.mitre_technique}"
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    async with httpx.AsyncClient(timeout=5.0) as client:
        r = await client.post(url, json={"chat_id": chat_id, "text": text})
    return {"ok": r.is_success, "status": r.status_code}
