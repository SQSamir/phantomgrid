import asyncio
import struct
from .base import BaseHoneypotHandler


class MssqlHandler(BaseHoneypotHandler):
    PROTOCOL = "MSSQL"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 11433),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return
        try:
            await self.emit(ip, None, "connection", "medium", {"server": "Microsoft SQL Server 2019"})

            # Read PRELOGIN packet (TDS type 0x12)
            data = await asyncio.wait_for(reader.read(4096), timeout=15)
            if len(data) < 8:
                return

            writer.write(self._prelogin_response())
            await writer.drain()

            # Read LOGIN7 (TDS type 0x10)
            login_data = await asyncio.wait_for(reader.read(4096), timeout=15)
            creds = self._parse_login7(login_data)
            await self.emit(
                ip, None, "auth_attempt", "critical",
                creds or {"raw_length": len(login_data)},
                ["credential_capture"],
            )

            writer.write(self._error_response())
            await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:
            self.log.error("mssql_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            writer.close()

    # ------------------------------------------------------------------
    def _prelogin_response(self) -> bytes:
        # Minimal PRELOGIN response: VERSION + ENCRYPTION=NOT_SUPPORTED + TERMINATOR
        payload = (
            b"\x00\x00\x06\x00\x01"   # VERSION option  (offset=6, len=1)
            b"\x01\x00\x07\x00\x01"   # ENCRYPTION option (offset=7, len=1)
            b"\xff"                    # TERMINATOR
            b"\x0e\x00\x0c\x00\x06\x01\x00\x72\x09\x00\x00"  # version bytes
            b"\x02"                    # ENCRYPT_NOT_SUPPORTED
        )
        hdr = struct.pack(">BBHBBBB", 0x04, 0x01, len(payload) + 8, 0, 0, 1, 0)
        return hdr + payload

    def _parse_login7(self, data: bytes) -> dict | None:
        if len(data) < 16 or data[0] != 0x10:
            return None
        try:
            pl = data[8:]                      # skip TDS header
            if len(pl) < 36:
                return None
            u_off = struct.unpack("<H", pl[24:26])[0]
            u_len = struct.unpack("<H", pl[26:28])[0]
            p_off = struct.unpack("<H", pl[28:30])[0]
            p_len = struct.unpack("<H", pl[30:32])[0]
            a_off = struct.unpack("<H", pl[32:34])[0]
            a_len = struct.unpack("<H", pl[34:36])[0]
            username = pl[u_off * 2:(u_off + u_len) * 2].decode("utf-16-le", errors="replace")
            password = self._deobfuscate(pl[p_off * 2:(p_off + p_len) * 2])
            app_name = pl[a_off * 2:(a_off + a_len) * 2].decode("utf-16-le", errors="replace")
            return {"username": username, "password": password, "app_name": app_name}
        except Exception:
            return None

    def _deobfuscate(self, data: bytes) -> str:
        out = bytearray()
        for b in data:
            b ^= 0xA5
            b = ((b << 4) | (b >> 4)) & 0xFF
            out.append(b)
        try:
            return out.decode("utf-16-le", errors="replace")
        except Exception:
            return out.hex()

    def _error_response(self) -> bytes:
        msg = "Login failed for user.".encode("utf-16-le")
        token = (
            b"\xaa"
            + struct.pack("<H", 4 + 1 + 1 + 2 + len(msg) + 2 + 2 + 4)
            + struct.pack("<I", 18456)   # error number: login failed
            + b"\x0e\x0e"               # state, class
            + struct.pack("<H", len(msg) // 2) + msg
            + b"\x00\x00"               # server name
            + b"\x00\x00"               # proc name
            + struct.pack("<I", 1)
        )
        hdr = struct.pack(">BBHBBBB", 0x04, 0x01, len(token) + 8, 0, 0, 1, 0)
        return hdr + token
