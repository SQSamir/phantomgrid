import os
import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")

def get_redis():
    return redis.from_url(REDIS_URL, decode_responses=True)
