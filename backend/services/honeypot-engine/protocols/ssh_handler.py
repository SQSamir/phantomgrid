import asyncio
from .base import BaseHoneypotHandler


class SshHandler(BaseHoneypotHandler):
    PROTOCOL = "SSH"

    async def start(self):
        return await self._start_server(
            self._handle,
            self.config.get("bind_host", "0.0.0.0"),
            self.config.get("port", 10022),
        )

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not await self.tracker.allow(ip):
            writer.close()
            return

        try:
            writer.write(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
            await writer.drain()
            await self.emit(ip, None, "connection", "medium", {"banner": "OpenSSH_8.9p1"}, ["new_connection"])

            # very lightweight auth/command trap
            writer.write(b"login as: ")
            await writer.drain()
            username = (await asyncio.wait_for(reader.readline(), timeout=30)).decode("utf-8", errors="ignore").strip()
            writer.write(b"Password: ")
            await writer.drain()
            password = (await asyncio.wait_for(reader.readline(), timeout=30)).decode("utf-8", errors="ignore").strip()

            await self.emit(ip, None, "auth_attempt", "high", {
                "username": username,
                "password": password,
                "auth_type": "password",
            }, ["credential_capture"])

            writer.write(b"Welcome to Ubuntu 22.04.3 LTS\nroot@web-prod-01:~# ")
            await writer.drain()

            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=120)
                if not line:
                    break
                cmd = line.decode("utf-8", errors="ignore").strip()
                if not cmd:
                    writer.write(b"root@web-prod-01:~# ")
                    await writer.drain()
                    continue
                await self.emit(ip, None, "command_executed", "high", {"command": cmd, "username": username}, ["shell_interaction"])
                if cmd in {"exit", "logout", "quit"}:
                    writer.write(b"logout\n")
                    await writer.drain()
                    break
                if cmd.startswith(("wget ", "curl ")):
                    parts = cmd.split()
                    url = parts[-1] if parts else ""
                    await self.emit(ip, None, "download_attempt", "critical", {"command": cmd, "url": url}, ["malware_download"])
                    writer.write(f"Connecting to {url}... HTTP request sent, awaiting response... 200 OK\n".encode())
                elif cmd == "whoami":
                    writer.write(b"root\n")
                elif cmd == "uname -a":
                    writer.write(b"Linux web-prod-01 5.15.0-91-generic x86_64 GNU/Linux\n")
                else:
                    writer.write(f"bash: {cmd.split()[0]}: command not found\n".encode())
                writer.write(b"root@web-prod-01:~# ")
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError,
                asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass  # Expected: client disconnected, timed out, or sent oversized input
        except Exception as exc:
            self.log.error("ssh_handler_error", error=str(exc), ip=ip)
        finally:
            await self.tracker.release(ip)
            writer.close()
