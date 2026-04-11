import asyncio
import struct
from .base import BaseHoneypotHandler


class MysqlHandler(BaseHoneypotHandler):
    PROTOCOL = "MYSQL"

    async def start(self):
        return await self._start_server(self._handle, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 13306))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return
        try:
            # protocol v10 greeting
            payload = (
                b"\x0a"
                + b"8.0.35-phantomgrid\x00"
                + b"\x01\x00\x00\x00"
                + b"12345678\x00"
                + struct.pack("<H", 0xF7FF)
                + b"\x08"
                + struct.pack("<H", 0x0002)
                + struct.pack("<H", 0x81FF)
                + b"\x15"
                + b"\x00" * 10
                + b"123456789012\x00"
                + b"caching_sha2_password\x00"
            )
            packet = struct.pack("<I", len(payload))[:3] + b"\x00" + payload
            writer.write(packet)
            await writer.drain()

            auth_data = await asyncio.wait_for(reader.read(4096), timeout=30)
            username = self._extract_username(auth_data)
            await self.emit(ip, None, "auth_attempt", "high", {"username": username, "auth_packet_hex": auth_data.hex()[:100]}, ["credential_capture"])

            ok = b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00"
            writer.write(ok)
            await writer.drain()

            while True:
                data = await asyncio.wait_for(reader.read(4096), timeout=120)
                if not data or len(data) < 5:
                    break
                if data[4] == 0x03:  # COM_QUERY
                    query = data[5:].decode("utf-8", errors="replace").strip()
                    await self.emit(ip, None, "query_executed", "medium", {"query": query[:500], "username": username})
                    q = query.upper()
                    if any(q.startswith(k) for k in ("DROP", "DELETE", "TRUNCATE")):
                        await self.emit(ip, None, "drop_attempt", "critical", {"query": query[:200]}, ["data_destruction"])
                    writer.write(b"\x07\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00")
                    await writer.drain()
                elif data[4] == 0x01:  # COM_QUIT
                    break
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass  # Expected: client disconnected or timed out
        except struct.error as exc:
            self.log.warning("mysql_malformed_packet", error=str(exc), ip=ip)
        except Exception as exc:
            self.log.error("mysql_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip); writer.close()

    def _extract_username(self, data: bytes) -> str:
        try:
            pos = 36
            end = data.index(b"\x00", pos)
            return data[pos:end].decode("utf-8", errors="replace")
        except (ValueError, IndexError):
            return "unknown"
