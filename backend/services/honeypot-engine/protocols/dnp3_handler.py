"""
DNP3 (Distributed Network Protocol 3) honeypot — simulates a SCADA RTU/IED.
Used in electric utilities, water treatment, and oil & gas SCADA systems.

DNP3 TCP frame:
  Start bytes: 0x05 0x64
  Length (1B) | Control (1B) | Destination (2B LE) | Source (2B LE) | CRC (2B)
  [Data blocks with CRCs ...]
"""
import asyncio
import struct
from uuid import uuid4
from .base import BaseHoneypotHandler

_APP_FC_NAMES = {
    0:  "CONFIRM",
    1:  "READ",
    2:  "WRITE",
    3:  "SELECT",
    4:  "OPERATE",
    5:  "DIRECT_OPERATE",
    6:  "DIRECT_OPERATE_NR",
    7:  "IMMED_FREEZE",
    13: "COLD_RESTART",
    14: "WARM_RESTART",
    20: "ENABLE_UNSOLICITED",
    21: "DISABLE_UNSOLICITED",
    22: "ASSIGN_CLASS",
    23: "DELAY_MEASURE",
    28: "GET_FILE_INFO",
    129: "RESPONSE",
    130: "UNSOLICITED_RESPONSE",
}

DNP3_START = b"\x05\x64"


class Dnp3Handler(BaseHoneypotHandler):
    PROTOCOL = "DNP3"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 10020),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return

        session_id = uuid4()
        try:
            await self.emit(ip, None, "connection", "medium",
                            {"device": "GE Multilin 750 Feeder Protection Relay"},
                            session_id=session_id)

            while True:
                # Read until DNP3 start bytes
                sync = await asyncio.wait_for(reader.readexactly(2), timeout=30)
                if sync != DNP3_START:
                    # Try to re-sync
                    leftover = await asyncio.wait_for(reader.read(256), timeout=5)
                    raw = sync + leftover
                    pos = raw.find(DNP3_START)
                    if pos < 0:
                        break
                    sync_data = raw[pos:]
                    reader = asyncio.StreamReader()  # simplified: just break
                    break

                # Link-layer header (8 bytes total after start bytes)
                ll_hdr = await asyncio.wait_for(reader.readexactly(8), timeout=10)
                length    = ll_hdr[0]       # number of octets following, min 5
                control   = ll_hdr[1]
                dest      = struct.unpack("<H", ll_hdr[2:4])[0]
                src       = struct.unpack("<H", ll_hdr[4:6])[0]
                # ll_hdr[6:8] = CRC (we don't verify)

                data_len  = length - 5      # subtract fixed header fields
                if data_len < 0 or data_len > 250:
                    break

                app_data = await asyncio.wait_for(reader.read(data_len + 2), timeout=10)  # +2 CRC

                # Parse application-layer function code (rough — ignores transport layer)
                fc = None
                fc_name = "UNKNOWN"
                if len(app_data) >= 2:
                    fc = app_data[1] & 0x7F    # mask off FIR/FIN bits
                    fc_name = _APP_FC_NAMES.get(fc, f"FC_{fc}")

                tags = ["ot_recon", "scada"]
                severity = "high"
                if fc in (3, 4, 5, 6):
                    tags.append("ot_control_attempt")
                    severity = "critical"
                if fc in (13, 14):
                    tags.append("ot_restart_attempt")
                    severity = "critical"

                await self.emit(ip, None, "ot_command", severity, {
                    "function_code": fc,
                    "function_name": fc_name,
                    "src_address": src,
                    "dst_address": dest,
                    "control_byte": hex(control),
                }, tags=tags, session_id=session_id)

                # Send a minimal DNP3 ACK (link-layer ACK, control=0x00)
                ack = DNP3_START + bytes([5, 0x00]) + struct.pack("<HH", src, dest) + b"\x00\x00"
                writer.write(ack)
                await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:
            self.log.error("dnp3_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            writer.close()
