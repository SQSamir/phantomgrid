import asyncio
from datetime import datetime, timezone
from uuid import uuid4

from .base import BaseHoneypotHandler


class TelnetHandler(BaseHoneypotHandler):
    PROTOCOL = "TELNET"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 10023),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close(); return

        session_id = uuid4()
        started_at = datetime.now(timezone.utc)
        transcript: list[dict] = []

        try:
            await self.emit(ip, None, "connection", "medium", {}, session_id=session_id)

            writer.write(b"BusyBox v1.35.0 built-in shell (ash)\nlogin: ")
            await writer.drain()
            user = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors="ignore").strip()
            writer.write(b"Password: ")
            await writer.drain()
            pwd = (await asyncio.wait_for(reader.readline(), timeout=60)).decode(errors="ignore").strip()

            await self.emit(
                ip, None, "auth_attempt", "high",
                {"username": user, "password": pwd},
                tags=["credential_capture"],
                session_id=session_id,
            )

            writer.write(b"\n# ")
            await writer.drain()

            while True:
                cmd = (await asyncio.wait_for(reader.readline(), timeout=120)).decode(errors="ignore").strip()
                if not cmd:
                    writer.write(b"# "); await writer.drain(); continue

                transcript.append({
                    "seq": len(transcript) + 1,
                    "cmd": cmd,
                    "ts": datetime.now(timezone.utc).isoformat(),
                })

                tags = []
                if any(x in cmd.lower() for x in ["/bin/sh", "busybox", "cat /proc/mounts", "sh;sh;sh"]):
                    tags.append("iot_malware")

                await self.emit(
                    ip, None, "command_executed",
                    "critical" if tags else "high",
                    {"command": cmd},
                    tags=tags,
                    session_id=session_id,
                )

                if cmd in {"exit", "logout", "quit"}:
                    break

                writer.write(b"# ")
                await writer.drain()

        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:
            self.log.error("telnet_handler_error", error=str(exc), ip=ip)
        finally:
            # Emit a session_closed summary with the full transcript
            duration_s = round((datetime.now(timezone.utc) - started_at).total_seconds())
            await self.emit(
                ip, None, "session_closed", "medium",
                {
                    "duration_seconds": duration_s,
                    "command_count": len(transcript),
                    "transcript": transcript,
                },
                session_id=session_id,
            )
            await self.tracker.release(ip)
            writer.close()
