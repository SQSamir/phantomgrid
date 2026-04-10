import json
import time
from backend.shared.kafka import create_consumer, create_producer, send_json
from backend.shared.redis_client import get_redis


async def _suppressed(rule_id: str, ip: str) -> bool:
    r = get_redis()
    return bool(await r.get(f"supp:{rule_id}:{ip}"))


async def _set_supp(rule_id: str, ip: str, minutes: int = 5):
    r = get_redis()
    await r.setex(f"supp:{rule_id}:{ip}", minutes * 60, "1")


async def _threshold_trigger(rule_id: str, ip: str, event_id: str, threshold: int = 5, window_sec: int = 300) -> bool:
    r = get_redis()
    now = int(time.time())
    k = f"rl:{rule_id}:{ip}"
    await r.zadd(k, {event_id: now})
    await r.zremrangebyscore(k, 0, now - window_sec)
    c = await r.zcard(k)
    await r.expire(k, window_sec)
    return c >= threshold


async def _correlation_trigger(ip: str, decoy_id: str, min_decoys: int = 3, window_sec: int = 300) -> bool:
    r = get_redis()
    k = f"decoys:{ip}"
    await r.sadd(k, decoy_id)
    await r.expire(k, window_sec)
    c = await r.scard(k)
    return c >= min_decoys


async def run():
    c = await create_consumer("events.enriched", "alert-engine")
    p = await create_producer()
    try:
        async for msg in c:
            e = json.loads(msg.value)
            ip = e.get("source_ip", "0.0.0.0")
            event_id = str(e.get("event_id", "evt"))
            decoy_id = str(e.get("decoy_id", "none"))
            proto = e.get("protocol", "")
            etype = e.get("event_type", "")

            # Simple match
            if etype in {"auth_attempt", "honeytoken_callback"}:
                rule_id = f"simple:{proto}:{etype}"
                if not await _suppressed(rule_id, ip):
                    alert = {
                        "tenant_id": e.get("tenant_id"),
                        "severity": "critical" if etype == "honeytoken_callback" else "high",
                        "title": f"{proto} {etype}",
                        "summary": "Simple rule triggered",
                        "source_ip": ip,
                        "mitre_technique_ids": e.get("mitre_technique_ids", []),
                    }
                    await _set_supp(rule_id, ip)
                    await send_json(p, "alerts.triggered", alert)
                    await send_json(p, "notifications.pending", alert)

            # Threshold rule for brute-force-like patterns
            if etype == "auth_attempt":
                rule_id = f"threshold:{proto}:auth_attempt"
                trig = await _threshold_trigger(rule_id, ip, event_id, threshold=5, window_sec=300)
                if trig and not await _suppressed(rule_id, ip):
                    alert = {
                        "tenant_id": e.get("tenant_id"),
                        "severity": "high",
                        "title": f"{proto} brute force suspected",
                        "summary": "Threshold rule triggered (>=5 auth_attempt / 5m)",
                        "source_ip": ip,
                        "mitre_technique_ids": e.get("mitre_technique_ids", []),
                    }
                    await _set_supp(rule_id, ip)
                    await send_json(p, "alerts.triggered", alert)
                    await send_json(p, "notifications.pending", alert)

            # Correlation rule: same IP hits multiple decoys in short window
            rule_id = "correlation:multi-decoy"
            corr = await _correlation_trigger(ip, decoy_id, min_decoys=3, window_sec=300)
            if corr and not await _suppressed(rule_id, ip):
                alert = {
                    "tenant_id": e.get("tenant_id"),
                    "severity": "critical",
                    "title": "Lateral movement pattern",
                    "summary": "Correlation rule triggered (>=3 decoys / 5m)",
                    "source_ip": ip,
                    "mitre_technique_ids": e.get("mitre_technique_ids", []),
                }
                await _set_supp(rule_id, ip)
                await send_json(p, "alerts.triggered", alert)
                await send_json(p, "notifications.pending", alert)
    finally:
        await c.stop()
        await p.stop()


if __name__ == "__main__":
    import asyncio
    asyncio.run(run())
