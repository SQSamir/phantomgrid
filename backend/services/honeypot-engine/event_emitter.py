import json
from aiokafka import AIOKafkaProducer

class EventEmitter:
    def __init__(self, brokers: str):
        self.brokers = brokers
        self._producer: AIOKafkaProducer | None = None

    async def start(self):
        self._producer = AIOKafkaProducer(bootstrap_servers=self.brokers)
        await self._producer.start()

    async def send(self, topic: str, payload: str | dict):
        if not self._producer:
            return
        if isinstance(payload, dict):
            payload = json.dumps(payload, default=str)
        await self._producer.send_and_wait(topic, payload.encode())

    async def flush(self):
        return

    async def stop(self):
        if self._producer:
            await self._producer.stop()
