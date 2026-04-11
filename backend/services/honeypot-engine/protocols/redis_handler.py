import asyncio
from .base import BaseHoneypotHandler

class RedisHandler(BaseHoneypotHandler):
    PROTOCOL = "REDIS"

    async def start(self):
        return await self._start_server(self._handle, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 16379))

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        ip = w.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            w.close(); return
        try:
            await self.emit(ip, None, "connection", "medium", {})
            while True:
                d = await asyncio.wait_for(r.read(1024), timeout=60)
                if not d: break
                txt = d.decode("utf-8", errors="ignore").upper()
                if "PING" in txt:
                    w.write(b"+PONG\r\n")
                else:
                    w.write(b"+OK\r\n")
                await w.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass  # Expected: client disconnected or timed out
        except Exception as exc:
            self.log.error("redis_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            w.close()
