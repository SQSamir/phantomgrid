import asyncio
from .base import BaseHoneypotHandler


class TelnetHandler(BaseHoneypotHandler):
    PROTOCOL = "TELNET"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 10023),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return
        try:
            await self.emit(ip, None, "connection", "medium", {})
            writer.write(b"BusyBox v1.35.0 built-in shell (ash)\nlogin: ")
            await writer.drain()
            user = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors="ignore").strip()
            writer.write(b"Password: ")
            await writer.drain()
            pwd = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors="ignore").strip()
            await self.emit(ip, None, "auth_attempt", "high", {"username": user, "password": pwd}, ["credential_capture"])
            writer.write(b"\n# ")
            await writer.drain()
            while True:
                cmd = (await asyncio.wait_for(reader.readline(), timeout=120)).decode(errors="ignore").strip()
                if not cmd:
                    writer.write(b"# "); await writer.drain(); continue
                tags = []
                if any(x in cmd.lower() for x in ["/bin/sh", "busybox", "cat /proc/mounts", "sh;sh;sh"]):
                    tags.append("iot_malware")
                await self.emit(ip, None, "command_executed", "critical" if tags else "high", {"command": cmd}, tags)
                if cmd in {"exit", "logout", "quit"}:
                    break
                writer.write(b"# ")
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass  # Expected: client disconnected, timed out, or sent oversized input
        except Exception as exc:
            self.log.error("telnet_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip); writer.close()
