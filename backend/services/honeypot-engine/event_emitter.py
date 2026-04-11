import asyncio
import json
import structlog
from aiokafka import AIOKafkaProducer
from aiokafka.errors import KafkaConnectionError

log = structlog.get_logger()


class EventEmitter:
    def __init__(self, brokers: str):
        self.brokers = brokers
        self._producer: AIOKafkaProducer | None = None
        self._dropped = 0

    async def start(self):
        for attempt in range(10):
            try:
                self._producer = AIOKafkaProducer(
                    bootstrap_servers=self.brokers,
                    enable_idempotence=True,
                    acks="all",
                )
                await self._producer.start()
                log.info("kafka_producer_started", brokers=self.brokers)
                return
            except KafkaConnectionError as exc:
                wait = 2 ** attempt
                log.warning("kafka_connect_retry", attempt=attempt + 1, wait=wait, error=str(exc))
                await asyncio.sleep(wait)
        raise RuntimeError(f"Could not connect to Kafka at {self.brokers} after 10 attempts")

    async def send(self, topic: str, payload: str | dict):
        if not self._producer:
            self._dropped += 1
            log.error("event_dropped_no_producer", topic=topic, total_dropped=self._dropped)
            return
        if isinstance(payload, dict):
            payload = json.dumps(payload, default=str)
        try:
            await self._producer.send_and_wait(topic, payload.encode())
        except Exception as exc:
            self._dropped += 1
            log.error("event_send_failed", topic=topic, error=str(exc), total_dropped=self._dropped)

    async def flush(self):
        if self._producer:
            await self._producer.flush()

    async def stop(self):
        if self._producer:
            await self.flush()
            await self._producer.stop()
            self._producer = None
