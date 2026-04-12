import asyncio
import struct
from .base import BaseHoneypotHandler


class RdpHandler(BaseHoneypotHandler):
    PROTOCOL = "RDP"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 13389),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return
        try:
            await self.emit(ip, None, "connection", "medium", {})

            # Read X.224 Connection Request (TPKT)
            tpkt = await asyncio.wait_for(reader.read(4096), timeout=15)
            if len(tpkt) < 4:
                return

            # Extract username from RDP cookie: "Cookie: mstshash=<user>\r\n"
            username = None
            marker = b"Cookie: mstshash="
            pos = tpkt.find(marker)
            if pos >= 0:
                end = tpkt.find(b"\r\n", pos)
                username = tpkt[pos + len(marker):end].decode("utf-8", errors="replace")

            # Detect requested security protocol from RDP_NEG_REQ
            neg_pos = tpkt.find(b"\x01\x00\x08\x00")
            req_proto = 0
            if neg_pos >= 0 and len(tpkt) >= neg_pos + 8:
                req_proto = struct.unpack("<I", tpkt[neg_pos + 4:neg_pos + 8])[0]
            proto_hint = {0: "CLASSIC_RDP", 1: "SSL/TLS", 2: "NLA/CredSSP", 3: "NLA+TLS"}.get(req_proto, "UNKNOWN")

            # X.224 Connection Confirm — advertise SSL required
            cc = (
                b"\x03\x00\x00\x13"          # TPKT: ver=3, len=19
                b"\x0e"                       # COTP length indicator
                b"\xd0"                       # PDU type: CC
                b"\x00\x00"                  # DST-REF
                b"\x00\x00"                  # SRC-REF
                b"\x00"                      # class 0
                b"\x02\x00\x08\x00"          # RDP_NEG_RSP type+flags+length
                b"\x01\x00\x00\x00"          # selected protocol: SSL
            )
            writer.write(cc)
            await writer.drain()

            # Read next packet (TLS ClientHello or MCS Connect-Initial)
            next_data = await asyncio.wait_for(reader.read(4096), timeout=15)

            # Try to detect NTLMSSP in CredSSP/NLA flow
            ntlm_user = ntlm_domain = None
            ntlm = self._parse_ntlmssp(next_data) or self._parse_ntlmssp(tpkt)
            if ntlm:
                ntlm_user = ntlm.get("user")
                ntlm_domain = ntlm.get("domain")

            await self.emit(ip, None, "auth_attempt", "critical", {
                "username": username,
                "protocol": proto_hint,
                "ntlm_user": ntlm_user,
                "ntlm_domain": ntlm_domain,
            }, ["credential_capture", "rdp_brute_force"])

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:
            self.log.error("rdp_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            writer.close()

    def _parse_ntlmssp(self, data: bytes) -> dict | None:
        sig = b"NTLMSSP\x00"
        pos = data.find(sig)
        if pos < 0:
            return None
        try:
            msg = data[pos:]
            msg_type = struct.unpack("<I", msg[8:12])[0]
            if msg_type == 3 and len(msg) >= 44:
                domain_len = struct.unpack("<H", msg[28:30])[0]
                domain_off = struct.unpack("<I", msg[32:36])[0]
                user_len   = struct.unpack("<H", msg[36:38])[0]
                user_off   = struct.unpack("<I", msg[40:44])[0]
                domain = msg[domain_off:domain_off + domain_len].decode("utf-16-le", errors="replace")
                user   = msg[user_off:user_off + user_len].decode("utf-16-le", errors="replace")
                return {"domain": domain, "user": user}
        except Exception:
            pass
        return None
