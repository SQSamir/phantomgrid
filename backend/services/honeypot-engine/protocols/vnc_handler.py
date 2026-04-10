import asyncio
import struct
from .base import BaseHoneypotHandler


class VncHandler(BaseHoneypotHandler):
    PROTOCOL = "VNC"

    async def start(self):
        return await asyncio.start_server(self._handle, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 15900))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not self.tracker.allow(ip):
            writer.close(); return
        try:
            writer.write(b"RFB 003.008\n")
            await writer.drain()
            client_version = await asyncio.wait_for(reader.read(12), timeout=10)
            writer.write(b"\x01\x02")
            await writer.drain()
            _ = await asyncio.wait_for(reader.read(1), timeout=10)
            challenge = bytes(range(16))
            writer.write(challenge)
            await writer.drain()
            response = await asyncio.wait_for(reader.read(16), timeout=10)
            await self.emit(ip, None, "auth_attempt", "high", {
                "client_version": client_version.decode("utf-8", errors="replace").strip(),
                "challenge_hex": challenge.hex(),
                "response_hex": response.hex(),
            }, ["credential_capture"])
            writer.write(b"\x00\x00\x00\x00")
            await writer.drain()
            server_init = (
                struct.pack("!HH", 1920, 1080)
                + b"\x20\x18\x00\x01\x00\xff\x00\xff\x00\xff\x10\x08\x00\x00\x00\x00"
                + struct.pack("!I", 12)
                + b"PHANTOMGRID "
            )
            writer.write(server_init)
            await writer.drain()
            await asyncio.sleep(2)
        except Exception:
            pass
        finally:
            self.tracker.release(ip); writer.close()
