import asyncio, struct
from .base import BaseHoneypotHandler

class DnsHandler(BaseHoneypotHandler):
    PROTOCOL = "DNS"

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(lambda: DnsProtocol(self), local_addr=(self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 15353)))
        return transport

class DnsProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: DnsHandler):
        self.h = handler
        self.t = None
    def connection_made(self, t): self.t = t
    def datagram_received(self, data, addr):
        asyncio.create_task(self._h(data, addr))
    async def _h(self, data: bytes, addr):
        ip, port = addr
        await self.h.emit(ip, port, "recon_query", "medium", {"raw": data.hex()[:80]})
        if len(data) < 12:
            return
        tid = data[:2]
        # QR=1 (response) | OPCODE=0 | AA=0 | TC=0 | RD=0 | RA=0 | RCODE=3 (NXDOMAIN)
        # RA bit (0x0080) intentionally cleared — do not advertise recursive capability,
        # which would allow this listener to be abused for DNS amplification attacks.
        flags = 0x8003
        header = struct.pack("!HHHHHH", int.from_bytes(tid, "big"), flags, 1, 0, 0, 0)
        q = data[12:]
        self.t.sendto(header + q, addr)
