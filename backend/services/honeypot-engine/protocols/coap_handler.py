"""
CoAP (Constrained Application Protocol) honeypot — UDP, IoT devices.
Simulates a CoAP server on an embedded/IoT device.

CoAP header (4 bytes):
  Byte 0: Ver(2b) | Type(2b) | TKL(4b)
  Byte 1: Code class(3b) | detail(5b)
  Bytes 2-3: Message ID
  Bytes 4+: Token (TKL bytes), then Options, then 0xFF + Payload
"""
import asyncio
import struct
from .base import BaseHoneypotHandler

_CODE_NAMES = {
    (0, 1): "GET",  (0, 2): "POST", (0, 3): "PUT",   (0, 4): "DELETE",
    (2, 1): "Created", (2, 4): "Changed", (2, 5): "Content",
    (4, 4): "Not Found", (4, 5): "Method Not Allowed",
    (5, 0): "Internal Server Error",
}
_TYPES = {0: "CON", 1: "NON", 2: "ACK", 3: "RST"}


class CoapHandler(BaseHoneypotHandler):
    PROTOCOL = "COAP"

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: _CoapProtocol(self),
            local_addr=(self.config.get("bind_host", "0.0.0.0"),
                        self.config.get("port", 15683)),
        )
        return transport


class _CoapProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: CoapHandler):
        self.h = handler
        self._transport = None

    def connection_made(self, transport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr):
        ip, port = addr
        if len(data) < 4:
            return
        try:
            byte0    = data[0]
            ver      = (byte0 >> 6) & 0x03
            msg_type = (byte0 >> 4) & 0x03
            tkl      = byte0 & 0x0F
            code_raw = data[1]
            msg_id   = struct.unpack(">H", data[2:4])[0]
            token    = data[4:4 + tkl]

            code_class  = (code_raw >> 5) & 0x07
            code_detail = code_raw & 0x1F
            code_name   = _CODE_NAMES.get((code_class, code_detail),
                                          f"{code_class}.{code_detail:02d}")
            type_name   = _TYPES.get(msg_type, "UNKNOWN")

            # Parse options to extract Uri-Path
            off = 4 + tkl
            uri_parts = []
            opt_num   = 0
            while off < len(data) and data[off] != 0xFF:
                delta_nibble  = (data[off] >> 4) & 0x0F
                length_nibble = data[off] & 0x0F
                off += 1
                delta = delta_nibble
                if delta_nibble == 13:
                    delta = data[off] + 13; off += 1
                elif delta_nibble == 14:
                    delta = struct.unpack(">H", data[off:off+2])[0] + 269; off += 2
                length = length_nibble
                if length_nibble == 13:
                    length = data[off] + 13; off += 1
                elif length_nibble == 14:
                    length = struct.unpack(">H", data[off:off+2])[0] + 269; off += 2
                opt_num += delta
                opt_val = data[off:off + length]
                if opt_num == 11:           # Uri-Path
                    uri_parts.append(opt_val.decode("utf-8", errors="replace"))
                off += length

            uri_path = "/" + "/".join(uri_parts) if uri_parts else "/"
            payload  = data[off + 1:].decode("utf-8", errors="replace") if (off < len(data) and data[off] == 0xFF) else ""

            tags     = ["iot_recon", "coap"]
            severity = "medium"
            sensitive_paths = ["/config", "/credentials", "/admin", "/.well-known/core"]
            if any(s in uri_path for s in sensitive_paths):
                tags.append("iot_sensitive_path")
                severity = "high"
            if code_class == 0 and code_detail in (2, 3, 4):  # POST/PUT/DELETE
                tags.append("iot_write_attempt")
                severity = "high"

            await self.h.emit(ip, port, "iot_request", severity, {
                "type": type_name,
                "method": code_name,
                "message_id": msg_id,
                "uri_path": uri_path,
                "token_hex": token.hex(),
                "payload": payload[:200],
            }, tags=tags)

            # Send ACK with 2.05 Content response
            if msg_type == 0:      # CON → send ACK
                ack_code = (2 << 5) | 5   # 2.05 Content
                ack = bytes([0x60 | tkl, ack_code]) + struct.pack(">H", msg_id) + token
                ack += b"\xFF" + b'{"status":"ok","device":"IoT-GW-001"}'
                if self._transport:
                    self._transport.sendto(ack, addr)

        except Exception as exc:
            self.h.log.error("coap_handler_error", error=str(exc), ip=ip)
