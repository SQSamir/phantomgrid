"""
MQTT honeypot — simulates an IoT broker (e.g. Mosquitto).
Captures CONNECT packets: clientId, username, password, will-topic.
Also records PUBLISH/SUBSCRIBE attempts post-auth.

MQTT CONNECT packet layout (variable header + payload):
  Protocol name (length-prefixed) | Protocol level | Connect flags | Keep alive
  Payload: clientId | [will-topic] | [will-msg] | [username] | [password]
"""
import asyncio
import struct
from uuid import uuid4
from .base import BaseHoneypotHandler


def _read_utf8(data: bytes, offset: int) -> tuple[str, int]:
    """Read a length-prefixed UTF-8 string; return (value, new_offset)."""
    if offset + 2 > len(data):
        return "", offset
    length = struct.unpack(">H", data[offset:offset + 2])[0]
    value  = data[offset + 2:offset + 2 + length].decode("utf-8", errors="replace")
    return value, offset + 2 + length


class MqttHandler(BaseHoneypotHandler):
    PROTOCOL = "MQTT"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 11883),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return

        session_id = uuid4()
        try:
            await self.emit(ip, None, "connection", "medium",
                            {"broker": "Mosquitto 2.0.18"},
                            session_id=session_id)

            # Read fixed header
            fixed_hdr = await asyncio.wait_for(reader.readexactly(2), timeout=15)
            pkt_type   = (fixed_hdr[0] >> 4) & 0x0F
            remain_len = fixed_hdr[1]          # simplified: single-byte remaining length

            if pkt_type != 1:                  # 1 = CONNECT
                return

            payload = await asyncio.wait_for(reader.readexactly(remain_len), timeout=15)
            creds   = self._parse_connect(payload)

            severity = "high" if creds.get("username") else "medium"
            await self.emit(ip, None, "auth_attempt", severity, creds,
                            ["credential_capture", "iot_device"],
                            session_id=session_id)

            # Send CONNACK: session-present=0, return-code=0 (accepted)
            writer.write(b"\x20\x02\x00\x00")
            await writer.drain()

            # Keep connection open and capture PUBLISH / SUBSCRIBE
            while True:
                hdr = await asyncio.wait_for(reader.readexactly(2), timeout=60)
                pkt_type = (hdr[0] >> 4) & 0x0F
                r_len    = hdr[1]
                body     = await asyncio.wait_for(reader.read(r_len), timeout=10)

                if pkt_type == 3:          # PUBLISH
                    topic, off = _read_utf8(body, 0)
                    msg = body[off:].decode("utf-8", errors="replace")
                    await self.emit(ip, None, "mqtt_publish", "high",
                                    {"topic": topic, "message": msg[:200]},
                                    ["iot_data_exfil"],
                                    session_id=session_id)
                    # Send PUBACK (qos=1)
                    if (hdr[0] & 0x06) == 0x02 and len(body) >= 2:
                        msg_id = struct.unpack(">H", body[off:off + 2])[0]
                        writer.write(b"\x40\x02" + struct.pack(">H", msg_id))
                        await writer.drain()

                elif pkt_type == 8:        # SUBSCRIBE
                    topics = self._parse_subscribe(body)
                    await self.emit(ip, None, "mqtt_subscribe", "medium",
                                    {"topics": topics},
                                    ["iot_recon"],
                                    session_id=session_id)
                    # Send SUBACK
                    if len(body) >= 2:
                        msg_id = struct.unpack(">H", body[0:2])[0]
                        writer.write(b"\x90\x03" + struct.pack(">H", msg_id) + b"\x00")
                        await writer.drain()

                elif pkt_type == 14:       # DISCONNECT
                    break
                elif pkt_type == 12:       # PINGREQ
                    writer.write(b"\xd0\x00")
                    await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:
            self.log.error("mqtt_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            writer.close()

    def _parse_connect(self, data: bytes) -> dict:
        try:
            proto_name, off = _read_utf8(data, 0)
            proto_level     = data[off]
            connect_flags   = data[off + 1]
            # keep_alive      = struct.unpack(">H", data[off+2:off+4])[0]
            off += 4

            has_will     = bool(connect_flags & 0x04)
            has_username = bool(connect_flags & 0x80)
            has_password = bool(connect_flags & 0x40)
            clean_session= bool(connect_flags & 0x02)

            client_id, off = _read_utf8(data, off)
            will_topic = will_msg = username = password = None

            if has_will:
                will_topic, off = _read_utf8(data, off)
                will_msg,   off = _read_utf8(data, off)
            if has_username:
                username, off   = _read_utf8(data, off)
            if has_password:
                password, off   = _read_utf8(data, off)

            return {
                "protocol": proto_name,
                "protocol_level": proto_level,
                "client_id": client_id,
                "username": username,
                "password": password,
                "will_topic": will_topic,
                "clean_session": clean_session,
            }
        except Exception:
            return {"raw_hex": data.hex()[:100]}

    def _parse_subscribe(self, data: bytes) -> list[str]:
        topics = []
        try:
            off = 2   # skip message ID
            while off < len(data):
                topic, off = _read_utf8(data, off)
                off += 1  # QoS byte
                topics.append(topic)
        except Exception:
            pass
        return topics
