import asyncio
import signal
import structlog
from uuid import uuid4

from config import Settings
from event_emitter import EventEmitter
from session_tracker import SessionTracker
from protocols import (
    HttpHandler,
    RedisHandler,
    FtpHandler,
    DnsHandler,
    SshHandler,
    TelnetHandler,
    AwsMetadataHandler,
    DockerApiHandler,
    SmtpHandler,
    SnmpHandler,
    VncHandler,
    MysqlHandler,
    PostgresqlHandler,
    SmbHandler,
    K8sApiHandler,
)

log = structlog.get_logger()


async def run():
    s = Settings()
    emitter = EventEmitter(s.kafka_brokers)
    await emitter.start()
    tracker = SessionTracker(max_per_ip=50)

    tenant_id = uuid4()
    decoys = [
        (HttpHandler, {"bind_host": s.bind_host, "port": 18080}),
        (RedisHandler, {"bind_host": s.bind_host, "port": 16379}),
        (FtpHandler, {"bind_host": s.bind_host, "port": 10021}),
        (DnsHandler, {"bind_host": s.bind_host, "port": 15353}),
        (SshHandler, {"bind_host": s.bind_host, "port": 10022}),
        (TelnetHandler, {"bind_host": s.bind_host, "port": 10023}),
        (AwsMetadataHandler, {"bind_host": s.bind_host, "port": 18169}),
        (DockerApiHandler, {"bind_host": s.bind_host, "port": 12375}),
        (SmtpHandler, {"bind_host": s.bind_host, "port": 10025}),
        (SnmpHandler, {"bind_host": s.bind_host, "port": 10161}),
        (VncHandler, {"bind_host": s.bind_host, "port": 15900}),
        (MysqlHandler, {"bind_host": s.bind_host, "port": 13306}),
        (PostgresqlHandler, {"bind_host": s.bind_host, "port": 15432}),
        (SmbHandler, {"bind_host": s.bind_host, "port": 10445}),
        (K8sApiHandler, {"bind_host": s.bind_host, "port": 16443}),
    ]

    servers = []
    for cls, cfg in decoys:
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
