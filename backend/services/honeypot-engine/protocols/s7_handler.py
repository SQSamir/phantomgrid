"""
Siemens S7comm honeypot (ISO-TSAP / COTP, port 102).
Simulates a Siemens S7-300/400 PLC — famously targeted by Stuxnet.

Frame structure:
  TPKT (4B): 0x03 0x00 <len 2B>
  COTP (variable): length-indicator | PDU-type | ...
  S7 PDU: 0x32 | ROSCTR | reserved(2) | pdu-ref(2) | param-len(2) | data-len(2) | ...
"""
import asyncio
import struct
from uuid import uuid4
from .base import BaseHoneypotHandler

_S7_ROSCTR = {1: "JOB", 2: "ACK", 3: "ACK_DATA", 7: "USERDATA"}
_S7_FUNC = {
    0x00: "CPU Services",
    0x04: "Read Variable",
    0x05: "Write Variable",
    0x1A: "Request Download",
    0x1B: "Download Block",
    0x1C: "Download Ended",
    0x1D: "Start Upload",
    0x1E: "Upload Block",
    0x1F: "End Upload",
    0x28: "PLC Control",
    0x29: "PLC Stop",
    0xF0: "Setup Communication",
}


class S7Handler(BaseHoneypotHandler):
    PROTOCOL = "S7COMM"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 10102),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return

        session_id = uuid4()
        try:
            await self.emit(ip, None, "connection", "medium",
                            {"device": "Siemens SIMATIC S7-315-2 PN/DP"},
                            session_id=session_id)

            while True:
                # TPKT header
                tpkt = await asyncio.wait_for(reader.readexactly(4), timeout=30)
                if tpkt[0] != 0x03:
                    break
                tpkt_len = struct.unpack(">H", tpkt[2:4])[0]
                if tpkt_len < 7 or tpkt_len > 1024:
                    break

                payload = await asyncio.wait_for(reader.readexactly(tpkt_len - 4), timeout=10)

                # COTP: first byte is length-indicator, second is PDU type
                cotp_len  = payload[0]
                cotp_type = payload[1] if len(payload) > 1 else 0

                # Connection Request (0xE0) → reply with Connection Confirm (0xD0)
                if cotp_type == 0xE0:
                    cc = (
                        b"\x03\x00\x00\x16"     # TPKT
                        b"\x11\xd0\x00\x01"     # COTP CC, DST-REF=1
                        b"\x00\x01\x00"         # SRC-REF=1, class=0
                        b"\xc0\x01\x0a"         # tpdu-size=1024
                        b"\xc1\x02\x01\x00"     # src-tsap
                        b"\xc2\x02\x01\x02"     # dst-tsap
                    )
                    writer.write(cc)
                    await writer.drain()
                    continue

                # Data PDU (0xF0) — contains S7 PDU
                if cotp_type == 0xF0 and len(payload) > cotp_len + 1:
                    s7 = payload[cotp_len + 1:]
                    if len(s7) >= 10 and s7[0] == 0x32:
                        rosctr  = s7[1]
                        func    = s7[8] if len(s7) > 8 else 0
                        tags    = ["ot_recon", "siemens_s7"]
                        severity = "high"
                        if func in (0x05, 0x1A, 0x1B, 0x1C, 0x28, 0x29):
                            tags.append("ot_control_attempt")
                            severity = "critical"

                        await self.emit(ip, None, "ot_command", severity, {
                            "rosctr": _S7_ROSCTR.get(rosctr, f"ROSCTR_{rosctr}"),
                            "function_code": hex(func),
                            "function_name": _S7_FUNC.get(func, f"FC_{hex(func)}"),
                            "raw_hex": s7.hex()[:80],
                        }, tags=tags, session_id=session_id)

                        # Reply: Setup Communication ACK (minimal)
                        ack_s7 = (
                            b"\x32\x03\x00\x00"   # S7 ACK_DATA
                            b"\x00\x00\x00\x08"   # pdu-ref, param-len=0, data-len=8
                            b"\x00\x00"           # error class, error code
                            b"\xf0\x00"           # param: SetupComm
                            b"\x00\x01\x00\x01"   # max-amq-calling/called
                            b"\x03\xc0"           # pdu-length=960
                        )
                        ack_cotp = b"\x02\xf0\x80"
                        ack_tpkt_len = 4 + len(ack_cotp) + len(ack_s7)
                        ack = struct.pack(">BBH", 0x03, 0x00, ack_tpkt_len) + ack_cotp + ack_s7
                        writer.write(ack)
                        await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:
            self.log.error("s7_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            writer.close()
