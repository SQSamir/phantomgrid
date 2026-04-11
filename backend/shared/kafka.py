import asyncio
import os
import json
import structlog
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer
from aiokafka.errors import KafkaConnectionError

log = structlog.get_logger()

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
_SASL_MECHANISM = os.getenv("KAFKA_SASL_MECHANISM", "")          # PLAIN | SCRAM-SHA-256
_SASL_USER = os.getenv("KAFKA_SASL_USERNAME", "")
_SASL_PASS = os.getenv("KAFKA_SASL_PASSWORD", "")
_SECURITY_PROTOCOL = os.getenv("KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")  # PLAINTEXT | SASL_PLAINTEXT | SASL_SSL


def _kafka_kwargs() -> dict:
    kw: dict = {"bootstrap_servers": BOOTSTRAP, "security_protocol": _SECURITY_PROTOCOL}
    if _SASL_MECHANISM:
        kw["sasl_mechanism"] = _SASL_MECHANISM
        kw["sasl_plain_username"] = _SASL_USER
        kw["sasl_plain_password"] = _SASL_PASS
    return kw


async def create_producer() -> AIOKafkaProducer:
    kw = _kafka_kwargs()
    for attempt in range(10):
        try:
            p = AIOKafkaProducer(**kw, enable_idempotence=True, acks="all")
            await p.start()
            return p
        except KafkaConnectionError as exc:
            wait = 2 ** attempt
            log.warning("kafka_producer_connect_retry", attempt=attempt + 1, wait=wait, error=str(exc))
            await asyncio.sleep(wait)
    raise RuntimeError(f"Could not connect Kafka producer to {BOOTSTRAP}")


async def send_json(producer: AIOKafkaProducer, topic: str, payload: dict):
    await producer.send_and_wait(topic, json.dumps(payload, default=str).encode())


async def create_consumer(topic: str, group: str) -> AIOKafkaConsumer:
    kw = _kafka_kwargs()
    for attempt in range(10):
        try:
            c = AIOKafkaConsumer(
                topic,
                **kw,
                group_id=group,
                auto_offset_reset="earliest",
                enable_auto_commit=True,
            )
            await c.start()
            return c
        except KafkaConnectionError as exc:
            wait = 2 ** attempt
            log.warning("kafka_consumer_connect_retry", attempt=attempt + 1, wait=wait, error=str(exc))
            await asyncio.sleep(wait)
    raise RuntimeError(f"Could not connect Kafka consumer to {BOOTSTRAP}")
