import asyncio
from .base import BaseHoneypotHandler


class SmtpHandler(BaseHoneypotHandler):
    PROTOCOL = "SMTP"

    async def start(self):
        return await asyncio.start_server(self._handle, self.config.get("bind_host", "0.0.0.0"), self.config.get("port", 10025))

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        ip = writer.get_extra_info("peername")[0]
        if not self.tracker.allow(ip):
            writer.close(); return
        sender = None
        recipients = []
        try:
            writer.write(b"220 mail.corp.local ESMTP Postfix (Ubuntu)\r\n")
            await writer.drain()
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=120)
                if not line:
                    break
                cmd_line = line.decode("utf-8", errors="ignore").strip()
                cmd = cmd_line.split(" ")[0].upper()
                arg = cmd_line[len(cmd):].strip()
                if cmd in ("EHLO", "HELO"):
                    writer.write(b"250-mail.corp.local\r\n250-PIPELINING\r\n250 AUTH PLAIN LOGIN\r\n")
                    await self.emit(ip, None, "ehlo", "low", {"client": arg})
                elif cmd == "AUTH":
                    writer.write(b"334 \r\n")
                    await writer.drain()
                    creds = await asyncio.wait_for(reader.readline(), timeout=30)
                    await self.emit(ip, None, "auth_attempt", "high", {"mechanism": arg.split()[0] if arg else "", "credentials_b64": creds.decode(errors='ignore').strip()}, ["credential_capture"])
                    writer.write(b"235 2.7.0 Authentication successful\r\n")
                elif cmd == "MAIL":
                    sender = arg.replace("FROM:", "").strip().strip("<>")
                    writer.write(b"250 2.1.0 Ok\r\n")
                elif cmd == "RCPT":
                    rcpt = arg.replace("TO:", "").strip().strip("<>")
                    recipients.append(rcpt)
                    writer.write(b"250 2.1.5 Ok\r\n")
                elif cmd == "DATA":
                    writer.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    await writer.drain()
                    body = []
                    while True:
                        dl = await asyncio.wait_for(reader.readline(), timeout=60)
                        if dl.strip() == b".":
                            break
                        body.append(dl.decode(errors="ignore"))
                    preview = "".join(body[:50])[:500]
                    await self.emit(ip, None, "email_received", "medium", {"sender": sender, "recipients": recipients, "body_preview": preview})
                    external = [r for r in recipients if not r.endswith((".corp.local", ".internal"))]
                    if external:
                        await self.emit(ip, None, "open_relay", "critical", {"external_recipients": external}, ["open_relay"])
                    writer.write(b"250 2.0.0 Ok: queued\r\n")
                elif cmd == "QUIT":
                    writer.write(b"221 2.0.0 Bye\r\n")
                    await writer.drain()
                    break
                else:
                    writer.write(b"502 5.5.2 Error: command not recognized\r\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            self.tracker.release(ip); writer.close()
