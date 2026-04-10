import asyncio
import signal
import structlog
from uuid import uuid4
from .config import Settings
from .event_emitter import EventEmitter
from .session_tracker import SessionTracker
from .protocols import HttpHandler, RedisHandler, FtpHandler, DnsHandler

log = structlog.get_logger()

async def run():
    s = Settings()
    emitter = EventEmitter(s.kafka_brokers)
    await emitter.start()
    tracker = SessionTracker(max_per_ip=50)

    tenant_id = uuid4()
    decoys = [
        ("http_honeypot", HttpHandler, {"bind_host": s.bind_host, "port": 18080}),
        ("redis_honeypot", RedisHandler, {"bind_host": s.bind_host, "port": 16379}),
        ("ftp_honeypot", FtpHandler, {"bind_host": s.bind_host, "port": 10021}),
        ("dns_honeypot", DnsHandler, {"bind_host": s.bind_host, "port": 15353}),
    ]

    servers = []
    for _, cls, cfg in decoys:
        h = cls(decoy_id=uuid4(), tenant_id=tenant_id, config=cfg, emitter=emitter, tracker=tracker)
        srv = await h.start()
        servers.append(srv)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    log.info("honeypot_engine_started", decoys=len(servers))
    await stop.wait()

if __name__ == "__main__":
    asyncio.run(run())
