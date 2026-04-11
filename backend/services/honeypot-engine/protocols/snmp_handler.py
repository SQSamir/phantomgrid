import asyncio
import struct
from .base import BaseHoneypotHandler


class SnmpHandler(BaseHoneypotHandler):
    PROTOCOL = "SNMP"

    async def start(self):
        loop = asyncio.get_running_loop()
        transport, _ = await loop.create_datagram_endpoint(lambda: SnmpProtocol(self), local_addr=(self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 10161)))
        return transport


class SnmpProtocol(asyncio.DatagramProtocol):
    def __init__(self, handler: SnmpHandler):
        self.h = handler

    def datagram_received(self, data, addr):
        asyncio.create_task(self._handle(data, addr))

    async def _handle(self, data: bytes, addr):
        ip, port = addr
        community = self._extract_community(data)
        pdu_type = self._get_pdu_type(data)
        await self.h.emit(ip, port, "community_string", "high", {
            "community": community,
            "pdu_type": pdu_type,
            "oid": ".1.3.6.1.2.1",
            "raw_hex": data.hex()[:100],
        }, ["credential_capture", "snmp_recon"])

    def _extract_community(self, data: bytes) -> str:
        try:
            pos = 2
            if data[pos] == 0x02:
                ver_len = data[pos + 1]
                pos += 2 + ver_len
            if data[pos] == 0x04:
                com_len = data[pos + 1]
                return data[pos + 2:pos + 2 + com_len].decode("utf-8", errors="replace")
        except (IndexError, struct.error):
            pass
        return "unknown"

    def _get_pdu_type(self, data: bytes) -> str:
        pdu_types = {0xA0: "GetRequest", 0xA1: "GetNextRequest", 0xA2: "GetResponse", 0xA3: "SetRequest", 0xA5: "GetBulkRequest"}
        for b in data:
            if b in pdu_types:
                return pdu_types[b]
        return "Unknown"
