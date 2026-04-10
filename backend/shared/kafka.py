import os, json
from aiokafka import AIOKafkaProducer, AIOKafkaConsumer

BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")

async def create_producer():
    p = AIOKafkaProducer(bootstrap_servers=BOOTSTRAP)
    await p.start()
    return p

async def send_json(producer, topic: str, payload: dict):
    await producer.send_and_wait(topic, json.dumps(payload, default=str).encode())

async def create_consumer(topic: str, group: str):
    c = AIOKafkaConsumer(topic, bootstrap_servers=BOOTSTRAP, group_id=group)
    await c.start()
    return c
