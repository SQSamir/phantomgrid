"""
Modbus/TCP honeypot — simulates a PLC/RTU on the OT network.

Modbus TCP frame:
  [Transaction ID 2B][Protocol ID 2B = 0x0000][Length 2B][Unit ID 1B][FC 1B][Data ...]
"""
import asyncio
import struct
from uuid import uuid4
from .base import BaseHoneypotHandler

_FC_NAMES = {
    1:  "Read Coils",
    2:  "Read Discrete Inputs",
    3:  "Read Holding Registers",
    4:  "Read Input Registers",
    5:  "Write Single Coil",
    6:  "Write Single Register",
    8:  "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    43: "Encapsulated Interface Transport (MEI)",
}


class ModbusHandler(BaseHoneypotHandler):
    PROTOCOL = "MODBUS"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 10502),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return

        session_id = uuid4()
        try:
            await self.emit(ip, None, "connection", "medium",
                            {"device": "Schneider Electric Modicon M340"},
                            session_id=session_id)

            while True:
                # MBAP header is always 6 bytes
                hdr = await asyncio.wait_for(reader.readexactly(6), timeout=30)
                trans_id, proto_id, length = struct.unpack(">HHH", hdr)
                if proto_id != 0 or length < 2 or length > 256:
                    break

                body = await asyncio.wait_for(reader.readexactly(length), timeout=10)
                unit_id  = body[0]
                fc       = body[1]
                payload  = body[2:]

                tags = ["ot_recon"]
                severity = "high"
                if fc in (5, 6, 15, 16):           # write functions
                    tags.append("ot_write_attempt")
                    severity = "critical"
                if fc == 43:                        # MEI — device identification
                    tags.append("device_fingerprint")

                await self.emit(ip, None, "ot_command", severity, {
                    "function_code": fc,
                    "function_name": _FC_NAMES.get(fc, f"FC_{fc}"),
                    "unit_id": unit_id,
                    "data_hex": payload.hex(),
                }, tags=tags, session_id=session_id)

                # Reply: exception code 0x06 — Server Device Busy
                resp_body = bytes([unit_id, fc | 0x80, 0x06])
                writer.write(struct.pack(">HHH", trans_id, 0, len(resp_body)) + resp_body)
                await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:
            self.log.error("modbus_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            writer.close()
