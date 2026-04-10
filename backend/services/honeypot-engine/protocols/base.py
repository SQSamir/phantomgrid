import structlog
from backend.shared.schemas.event import RawEvent
from backend.shared.enums import Protocol, Severity
from backend.shared.mitre_map import get_techniques

class BaseHoneypotHandler:
    PROTOCOL = 'HTTP'
    def __init__(self, decoy_id, tenant_id, config, emitter, tracker):
        self.decoy_id = decoy_id; self.tenant_id = tenant_id; self.config = config
        self.emitter = emitter; self.tracker = tracker
        self.log = structlog.get_logger().bind(decoy_id=str(decoy_id), protocol=self.PROTOCOL)
    async def emit(self, source_ip, source_port, event_type, severity, raw_data, tags=None):
        event = RawEvent(tenant_id=self.tenant_id, decoy_id=self.decoy_id, source_ip=source_ip, source_port=source_port, protocol=Protocol(self.PROTOCOL), event_type=event_type, severity=Severity(severity), raw_data=raw_data, tags=tags or [])
        event.tags += get_techniques(self.PROTOCOL, event_type)
        await self.emitter.send('events.raw', event.model_dump_json())
