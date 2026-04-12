import asyncio
import structlog
from backend.shared.schemas.event import RawEvent
from backend.shared.enums import Protocol, Severity
from backend.shared.mitre_map import get_techniques

# Maximum bytes accepted per line for all line-based TCP protocols.
# asyncio.StreamReader raises LimitOverrunError when a line exceeds this.
_READLINE_MAX = 4096

# asyncio.start_server limit — controls the internal read buffer.
# Prevents a slow-loris client from holding an unbounded amount of memory.
SERVER_LIMIT = _READLINE_MAX


class BaseHoneypotHandler:
    PROTOCOL = 'HTTP'

    def __init__(self, decoy_id, tenant_id, config, emitter, tracker):
        self.decoy_id = decoy_id
        self.tenant_id = tenant_id
        self.config = config
        self.emitter = emitter
        self.tracker = tracker
        self.log = structlog.get_logger().bind(decoy_id=str(decoy_id), protocol=self.PROTOCOL)

    async def _start_server(self, handler, host, port):
        """Wrapper so all TCP handlers get a consistent read-buffer limit."""
        return await asyncio.start_server(handler, host, port, limit=SERVER_LIMIT)

    async def emit(self, source_ip, source_port, event_type, severity, raw_data,
                   tags=None, session_id=None):
        event = RawEvent(
            tenant_id=self.tenant_id,
            decoy_id=self.decoy_id,
            session_id=session_id,
            source_ip=source_ip,
            source_port=source_port,
            protocol=Protocol(self.PROTOCOL),
            event_type=event_type,
            severity=Severity(severity),
            raw_data=raw_data,
            tags=tags or [],
        )
        event.tags += get_techniques(self.PROTOCOL, event_type)
        await self.emitter.send('events.raw', event.model_dump_json())
