"""
Honeypot Engine — lifecycle-driven protocol handler manager.

Listens on Kafka topic ``decoy.lifecycle`` for deploy/pause/destroy events
published by the decoy-manager.  For every "deploy" event it starts the
matching protocol handler bound to the correct tenant_id and decoy_id, then
calls back to decoy-manager to mark the decoy as active.
"""
import asyncio
import json
import signal
from uuid import UUID

import httpx
import structlog
from aiokafka import AIOKafkaConsumer

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
    RdpHandler,
    MssqlHandler,
    ModbusHandler,
    Dnp3Handler,
    S7Handler,
    MqttHandler,
    CoapHandler,
)

log = structlog.get_logger()

# Map decoy type string → handler class
_TYPE_MAP = {
    "http_honeypot":         HttpHandler,
    "https_honeypot":        HttpHandler,
    "redis_honeypot":        RedisHandler,
    "ftp_honeypot":          FtpHandler,
    "dns_honeypot":          DnsHandler,
    "ssh_honeypot":          SshHandler,
    "telnet_honeypot":       TelnetHandler,
    "aws_metadata_honeypot": AwsMetadataHandler,
    "docker_api_honeypot":   DockerApiHandler,
    "smtp_honeypot":         SmtpHandler,
    "snmp_honeypot":         SnmpHandler,
    "vnc_honeypot":          VncHandler,
    "mysql_honeypot":        MysqlHandler,
    "postgresql_honeypot":   PostgresqlHandler,
    "smb_honeypot":          SmbHandler,
    "k8s_api_honeypot":      K8sApiHandler,
    # New
    "rdp_honeypot":          RdpHandler,
    "mssql_honeypot":        MssqlHandler,
    "modbus_honeypot":       ModbusHandler,
    "dnp3_honeypot":         Dnp3Handler,
    "s7_honeypot":           S7Handler,
    "mqtt_honeypot":         MqttHandler,
    "coap_honeypot":         CoapHandler,
}

# Fallback ports when neither the decoy record nor its config specify one
_DEFAULT_PORTS = {
    "http_honeypot":         18080,
    "https_honeypot":        16443,
    "redis_honeypot":        16379,
    "ftp_honeypot":          10021,
    "dns_honeypot":          15353,
    "ssh_honeypot":          10022,
    "telnet_honeypot":       10023,
    "aws_metadata_honeypot": 18169,
    "docker_api_honeypot":   12375,
    "smtp_honeypot":         10025,
    "snmp_honeypot":         10161,
    "vnc_honeypot":          15900,
    "mysql_honeypot":        13306,
    "postgresql_honeypot":   15432,
    "smb_honeypot":          10445,
    "k8s_api_honeypot":      16443,
    # New
    "rdp_honeypot":          13389,
    "mssql_honeypot":        11433,
    "modbus_honeypot":       10502,
    "dnp3_honeypot":         10020,
    "s7_honeypot":           10102,
    "mqtt_honeypot":         11883,
    "coap_honeypot":         15683,
}


class HandlerRegistry:
    """Manages the set of currently-running protocol handlers."""

    def __init__(self, emitter: EventEmitter, tracker: SessionTracker, settings: Settings):
        self._emitter = emitter
        self._tracker = tracker
        self._settings = settings
        self._running: dict[str, object] = {}   # decoy_id → server handle

    async def deploy(self, msg: dict) -> None:
        decoy_id  = msg["decoy_id"]
        tenant_id = msg["tenant_id"]
        decoy_type = msg["type"]

        if decoy_id in self._running:
            log.warning("decoy_already_running", decoy_id=decoy_id)
            return

        cls = _TYPE_MAP.get(decoy_type)
        if cls is None:
            log.error("unknown_decoy_type", decoy_type=decoy_type, decoy_id=decoy_id)
            return

        port = (
            msg.get("port")
            or (msg.get("config") or {}).get("port")
            or _DEFAULT_PORTS.get(decoy_type, 9999)
        )
        cfg = {**(msg.get("config") or {}), "bind_host": self._settings.bind_host, "port": port}

        handler = cls(
            decoy_id=UUID(decoy_id),
            tenant_id=UUID(tenant_id),
            config=cfg,
            emitter=self._emitter,
            tracker=self._tracker,
        )
        try:
            srv = await handler.start()
            self._running[decoy_id] = srv
            log.info("decoy_started", decoy_id=decoy_id, type=decoy_type, port=port)
        except OSError as exc:
            log.error("decoy_start_failed", decoy_id=decoy_id, error=str(exc))
            return

        # Notify decoy-manager so the status flips to "active"
        await self._activate(tenant_id, decoy_id)

    async def stop(self, decoy_id: str) -> None:
        srv = self._running.pop(decoy_id, None)
        if srv is None:
            return
        try:
            if hasattr(srv, "close"):
                srv.close()
                if hasattr(srv, "wait_closed"):
                    await srv.wait_closed()
            elif hasattr(srv, "abort"):
                srv.abort()
        except Exception as exc:
            log.warning("decoy_stop_error", decoy_id=decoy_id, error=str(exc))
        log.info("decoy_stopped", decoy_id=decoy_id)

    async def stop_all(self) -> None:
        for decoy_id in list(self._running):
            await self.stop(decoy_id)

    async def _activate(self, tenant_id: str, decoy_id: str) -> None:
        url = f"{self._settings.decoy_manager_url}/api/decoys/{decoy_id}/activate"
        try:
            async with httpx.AsyncClient(timeout=5.0) as c:
                resp = await c.post(
                    url,
                    headers={
                        "X-Tenant-ID": tenant_id,
                        "X-User-ID":   "honeypot-engine",
                        "X-User-Role": "system",
                    },
                )
                # 409 = already active, that's fine
                if resp.status_code not in (200, 409):
                    log.warning("activate_failed", decoy_id=decoy_id, status=resp.status_code)
                else:
                    log.info("decoy_activated", decoy_id=decoy_id)
        except Exception as exc:
            log.warning("activate_error", decoy_id=decoy_id, error=str(exc))


async def _start_consumer(brokers: str) -> AIOKafkaConsumer:
    consumer = AIOKafkaConsumer(
        "decoy.lifecycle",
        bootstrap_servers=brokers,
        group_id="honeypot-engine",
        auto_offset_reset="earliest",
        value_deserializer=lambda v: json.loads(v.decode()),
    )
    for attempt in range(10):
        try:
            await consumer.start()
            log.info("kafka_consumer_started", topic="decoy.lifecycle")
            return consumer
        except Exception as exc:
            wait = 2 ** attempt
            log.warning("kafka_connect_retry", attempt=attempt + 1, wait=wait, error=str(exc))
            await asyncio.sleep(wait)
    raise RuntimeError(f"Could not connect to Kafka at {brokers} after 10 attempts")


async def run():
    s = Settings()
    emitter = EventEmitter(s.kafka_brokers)
    await emitter.start()

    tracker  = SessionTracker(max_per_ip=50)
    registry = HandlerRegistry(emitter, tracker, s)
    consumer = await _start_consumer(s.kafka_brokers)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)

    log.info("honeypot_engine_ready", mode="lifecycle-driven")

    async def _consume():
        try:
            async for msg in consumer:
                event  = msg.value
                action = event.get("event")
                decoy_id = event.get("decoy_id", "")
                log.info("lifecycle_event", action=action, decoy_id=decoy_id)
                if action == "deploy":
                    await registry.deploy(event)
                elif action in ("pause", "destroy"):
                    await registry.stop(decoy_id)
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            log.error("consume_loop_crashed", error=str(exc))

    task = asyncio.create_task(_consume())
    await stop.wait()

    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    await registry.stop_all()
    await consumer.stop()
    await emitter.stop()
    log.info("honeypot_engine_stopped")


if __name__ == "__main__":
    asyncio.run(run())
