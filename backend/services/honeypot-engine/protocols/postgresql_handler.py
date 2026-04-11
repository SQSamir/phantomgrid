import asyncio
import struct
from .base import BaseHoneypotHandler


class PostgresqlHandler(BaseHoneypotHandler):
    PROTOCOL = "POSTGRESQL"

    async def start(self):
        return await self._start_server(self._handle, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 15432))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return
        try:
            length_bytes = await reader.read(4)
            if len(length_bytes) < 4:
                return
            length = struct.unpack("!I", length_bytes)[0]
            startup = await reader.read(length - 4)
            params = startup[4:]
            username, database = "unknown", "unknown"
            parts = params.split(b"\x00")
            for i, part in enumerate(parts):
                if part == b"user" and i + 1 < len(parts):
                    username = parts[i + 1].decode("utf-8", errors="replace")
                elif part == b"database" and i + 1 < len(parts):
                    database = parts[i + 1].decode("utf-8", errors="replace")

            salt = b"\x01\x02\x03\x04"
            auth_req = struct.pack("!cIi", b"R", 12, 5) + salt
            writer.write(auth_req)
            await writer.drain()

            msg_type = await reader.read(1)
            if msg_type != b"p":
                return
            lb = await reader.read(4)
            l = struct.unpack("!I", lb)[0]
            password_hash = await reader.read(l - 4)
            await self.emit(ip, None, "auth_attempt", "high", {
                "username": username,
                "database": database,
                "password_hash": password_hash.decode("utf-8", errors="replace").strip("\x00"),
            }, ["credential_capture"])

            auth_ok = struct.pack("!cIi", b"R", 8, 0)
            param_status = self._param("server_version", "16.1")
            ready = struct.pack("!cIc", b"Z", 5, b"I")
            writer.write(auth_ok + param_status + ready)
            await writer.drain()

            while True:
                mt = await asyncio.wait_for(reader.read(1), timeout=120)
                if not mt:
                    break
                if mt == b"Q":
                    lb = await reader.read(4)
                    l = struct.unpack("!I", lb)[0]
                    query = (await reader.read(l - 4)).decode("utf-8", errors="replace").strip("\x00")
                    await self.emit(ip, None, "query_executed", "medium", {"query": query[:500], "username": username})
                    q = query.upper()
                    if "PG_READ_FILE" in q or "PG_LS_DIR" in q:
                        await self.emit(ip, None, "file_read_attempt", "critical", {"query": query[:200]}, ["privilege_escalation"])
                    if "COPY TO" in q:
                        await self.emit(ip, None, "data_exfil", "critical", {"query": query[:200]}, ["data_exfil"])
                    empty = struct.pack("!cIH", b"T", 6, 0) + struct.pack("!cI", b"C", 11) + b"SELECT 0\x00" + struct.pack("!cIc", b"Z", 5, b"I")
                    writer.write(empty)
                    await writer.drain()
                elif mt == b"X":
                    break
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass  # Expected: client disconnected or timed out
        except struct.error as exc:
            self.log.warning("postgresql_malformed_packet", error=str(exc), ip=ip)
        except Exception as exc:
            self.log.error("postgresql_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip); writer.close()

    def _param(self, name, value):
        payload = f"{name}\x00{value}\x00".encode()
        return struct.pack("!cI", b"S", len(payload) + 4) + payload
