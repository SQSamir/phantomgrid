"""
Redis-backed distributed session tracker.

Tracks concurrent connections per source IP across all honeypot-engine
instances. Counts survive restarts because they live in Redis, and a TTL
prevents counts from getting permanently stuck when the process crashes
mid-session before ``release()`` is called.
"""
from backend.shared.redis_client import get_redis

# How long (seconds) a counter key lives without activity.
# Any session open longer than this is considered abandoned.
_SESSION_TTL = 3600  # 1 hour


class SessionTracker:
    def __init__(self, max_per_ip: int = 50):
        self.max_per_ip = max_per_ip

    async def allow(self, ip: str) -> bool:
        """Atomically increment the session count for *ip*.

        Returns ``True`` if the connection is allowed, ``False`` if the
        per-IP limit has been reached.  On ``False`` the counter is left
        unchanged.
        """
        r = get_redis()
        key = f"sessions:{ip}"

        # Lua script: increment only if current value < max_per_ip.
        # The script is atomic — no race between read and write.
        script = """
local cur = tonumber(redis.call('GET', KEYS[1])) or 0
if cur >= tonumber(ARGV[1]) then
    return 0
end
redis.call('INCR', KEYS[1])
redis.call('EXPIRE', KEYS[1], ARGV[2])
return 1
"""
        result = await r.eval(script, 1, key, self.max_per_ip, _SESSION_TTL)
        return bool(result)

    async def release(self, ip: str):
        """Decrement the session count for *ip*, clamped at 0."""
        r = get_redis()
        key = f"sessions:{ip}"

        script = """
local cur = tonumber(redis.call('GET', KEYS[1])) or 0
if cur <= 0 then
    redis.call('DEL', KEYS[1])
    return 0
end
local new = redis.call('DECR', KEYS[1])
if new <= 0 then
    redis.call('DEL', KEYS[1])
end
return new
"""
        await r.eval(script, 1, key)
