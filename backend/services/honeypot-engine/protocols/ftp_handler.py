import asyncio
from .base import BaseHoneypotHandler

class FtpHandler(BaseHoneypotHandler):
    PROTOCOL = "FTP"

    async def start(self):
        return await asyncio.start_server(self._handle, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 10021))

    async def _handle(self, r, w):
        ip = w.get_extra_info("peername")[0]
        if not self.tracker.allow(ip):
            w.close(); return
        try:
            w.write(b"220 ProFTPD 1.3.8 Server (Phantom FTP)\r\n")
            await w.drain()
            await self.emit(ip, None, "connection", "medium", {})
            while True:
                line = await asyncio.wait_for(r.readline(), timeout=60)
                if not line: break
                cmd = line.decode(errors="ignore").strip().upper()
                if cmd.startswith("USER"):
                    w.write(b"331 Password required\r\n")
                elif cmd.startswith("PASS"):
                    await self.emit(ip, None, "auth_attempt", "high", {"password": line.decode(errors='ignore').strip()})
                    w.write(b"230 User logged in\r\n")
                elif cmd.startswith("QUIT"):
                    w.write(b"221 Goodbye\r\n"); await w.drain(); break
                else:
                    w.write(b"200 OK\r\n")
                await w.drain()
        except Exception:
            pass
        finally:
            self.tracker.release(ip); w.close()
