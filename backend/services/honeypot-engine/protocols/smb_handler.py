import asyncio
import struct
from .base import BaseHoneypotHandler


class SmbHandler(BaseHoneypotHandler):
    PROTOCOL = "SMB"

    async def start(self):
        return await asyncio.start_server(self._handle, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 10445))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not self.tracker.allow(ip):
            writer.close(); return
        try:
            data = await asyncio.wait_for(reader.read(4096), timeout=30)
            if len(data) < 4:
                return
            writer.write(self._build_smb2_negotiate())
            await writer.drain()

            session_setup = await asyncio.wait_for(reader.read(4096), timeout=30)
            ntlm_type = self._detect_ntlm_type(session_setup)
            if ntlm_type == 1:
                writer.write(self._build_ntlm_challenge())
                await writer.drain()
                auth_response = await asyncio.wait_for(reader.read(4096), timeout=30)
                ntlm_info = self._parse_ntlm_authenticate(auth_response)
                if ntlm_info:
                    await self.emit(ip, None, "ntlm_captured", "critical", {
                        "username": ntlm_info.get("username"),
                        "domain": ntlm_info.get("domain"),
                        "ntlm_hash": ntlm_info.get("net_ntlmv2_hash"),
                        "hash_for_analysis": ntlm_info.get("formatted_hash"),
                    }, ["ntlm_hash_captured", "lateral_movement"])
                await self.emit(ip, None, "share_enumeration", "high", {"fake_shares": ["ADMIN$", "C$", "Finance", "HR"]})
        except Exception:
            pass
        finally:
            self.tracker.release(ip); writer.close()

    def _build_smb2_negotiate(self) -> bytes:
        return b"\x00\x00\x01\x00" + b"\xfe\x53\x4d\x42" + b"\x00" * 60

    def _detect_ntlm_type(self, data: bytes) -> int:
        sig = b"NTLMSSP\x00"
        pos = data.find(sig)
        if pos >= 0 and len(data) > pos + 12:
            return struct.unpack("<I", data[pos + 8:pos + 12])[0]
        return 0

    def _build_ntlm_challenge(self) -> bytes:
        challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        ntlm = (
            b"NTLMSSP\x00"
            + struct.pack("<I", 2)
            + b"\x00" * 8
            + struct.pack("<I", 0x000082B7)
            + challenge
            + b"\x00" * 8
            + b"\x00" * 8
        )
        return b"\x00\x00\x00\x00" + ntlm

    def _parse_ntlm_authenticate(self, data: bytes) -> dict:
        sig = b"NTLMSSP\x00"
        pos = data.find(sig)
        if pos < 0:
            return {}
        try:
            msg = data[pos:]
            domain_len = struct.unpack("<H", msg[28:30])[0]
            domain_off = struct.unpack("<I", msg[32:36])[0]
            user_len = struct.unpack("<H", msg[36:38])[0]
            user_off = struct.unpack("<I", msg[40:44])[0]
            nt_len = struct.unpack("<H", msg[20:22])[0]
            nt_off = struct.unpack("<I", msg[24:28])[0]
            domain = msg[domain_off:domain_off + domain_len].decode("utf-16-le", errors="replace")
            username = msg[user_off:user_off + user_len].decode("utf-16-le", errors="replace")
            nt_response = msg[nt_off:nt_off + nt_len].hex()
            return {
                "username": username,
                "domain": domain,
                "net_ntlmv2_hash": nt_response,
                "formatted_hash": f"{username}::{domain}:0102030405060708:{nt_response[:32]}:{nt_response[32:]}",
            }
        except Exception:
            return {}
