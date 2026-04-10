import json, ipaddress
from backend.shared.kafka import create_consumer, create_producer, send_json
from backend.shared.mitre_map import get_techniques

async def enrich(event: dict):
    ip = event.get('source_ip', '0.0.0.0')
    private = ipaddress.ip_address(ip).is_private
    event['enrichment'] = {'country': None if private else 'Unknown', 'is_tor': False, 'abuse_score': None}
    event['mitre_technique_ids'] = get_techniques(event.get('protocol',''), event.get('event_type',''))
    return event

async def run():
    c = await create_consumer('events.raw', 'event-processor')
    p = await create_producer()
    try:
        async for msg in c:
            event = json.loads(msg.value)
            enriched = await enrich(event)
            await send_json(p, 'events.enriched', enriched)
    finally:
        await c.stop(); await p.stop()
