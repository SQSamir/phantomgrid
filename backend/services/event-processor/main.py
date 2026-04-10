import json
import ipaddress
from datetime import datetime, timezone

import httpx

from backend.shared.kafka import create_consumer, create_producer, send_json
from backend.shared.mitre_map import get_techniques
from backend.shared.redis_client import get_redis


def _is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return True


async def _abuse_score(ip: str) -> int | None:
    r = get_redis()
    k = f"abuse:{ip}"
    cached = await r.get(k)
    if cached is not None:
        return int(cached)

    score = 0
    if not _is_private(ip):
        # Placeholder external call; safe fail to 0
        try:
            async with httpx.AsyncClient(timeout=2.0) as c:
                _ = c  # reserved for AbuseIPDB integration
                score = 0
        except Exception:
            score = 0
    await r.setex(k, 24 * 3600, str(score))
    return score


async def _is_tor_exit(ip: str) -> bool:
    if _is_private(ip):
        return False
    r = get_redis()
    # background refresh can update this key every 6h
    return bool(await r.sismember("tor:exit_nodes", ip))


async def enrich(event: dict):
    ip = event.get("source_ip", "0.0.0.0")
    private = _is_private(ip)

    event["enrichment"] = {
        "country": None if private else "Unknown",
        "country_code": None,
        "city": None,
        "lat": None,
        "lon": None,
        "asn": None,
        "isp": None,
        "is_tor": await _is_tor_exit(ip),
        "is_vpn": False,
        "abuse_score": await _abuse_score(ip),
        "enriched_at": datetime.now(timezone.utc).isoformat(),
    }
    event["mitre_technique_ids"] = get_techniques(event.get("protocol", ""), event.get("event_type", ""))
    return event


async def run():
    c = await create_consumer("events.raw", "event-processor")
    p = await create_producer()
    try:
        async for msg in c:
            event = json.loads(msg.value)
            enriched = await enrich(event)
            await send_json(p, "events.enriched", enriched)
    finally:
        await c.stop()
        await p.stop()


if __name__ == "__main__":
    import asyncio
    asyncio.run(run())
