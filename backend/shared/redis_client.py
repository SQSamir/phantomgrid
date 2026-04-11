import os
import redis.asyncio as redis

REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379/0")
# If REDIS_PASSWORD is set separately (e.g., Docker secret), build the URL with it.
_REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")
if _REDIS_PASSWORD and "://" in REDIS_URL and "@" not in REDIS_URL:
    # Insert password: redis://redis:6379 -> redis://:password@redis:6379
    proto, rest = REDIS_URL.split("://", 1)
    REDIS_URL = f"{proto}://:{_REDIS_PASSWORD}@{rest}"

_pool: redis.ConnectionPool | None = None


def _get_pool() -> redis.ConnectionPool:
    global _pool
    if _pool is None:
        _pool = redis.ConnectionPool.from_url(REDIS_URL, decode_responses=True, max_connections=20)
    return _pool


def get_redis() -> redis.Redis:
    return redis.Redis(connection_pool=_get_pool())
