import json
from backend.shared.kafka import create_consumer, create_producer, send_json

async def run():
    c = await create_consumer('events.enriched', 'alert-engine')
    p = await create_producer()
    try:
        async for msg in c:
            e = json.loads(msg.value)
            if e.get('event_type') in {'auth_attempt','honeytoken_callback'}:
                alert = {
                    'tenant_id': e.get('tenant_id'), 'severity': 'critical' if e.get('event_type')=='honeytoken_callback' else 'high',
                    'title': f"{e.get('protocol')} {e.get('event_type')}", 'summary': 'Auto-triggered', 'source_ip': e.get('source_ip'),
                    'mitre_technique_ids': e.get('mitre_technique_ids', [])
                }
                await send_json(p, 'alerts.triggered', alert)
                await send_json(p, 'notifications.pending', alert)
    finally:
        await c.stop(); await p.stop()
