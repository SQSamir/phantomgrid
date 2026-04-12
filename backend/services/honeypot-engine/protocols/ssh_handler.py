"""
SSH Honeypot — asyncssh implementation with:
  - Phantom AI Engine for command responses
  - Fingerprint evasion (rotating banners)
  - Full session recording
  - Brute force detection
"""
import asyncio
import asyncssh
from datetime import datetime, timezone
from uuid import uuid4, UUID

import structlog

from ai.phantom_ai import PhantomAI
from evasion.fingerprint_manager import get_fingerprint_manager
from .base import BaseHoneypotHandler

log = structlog.get_logger()


class _PhantomSSHServer(asyncssh.SSHServer):
    """Per-connection auth handler."""

    def __init__(self, handler: "SshHandler"):
        self._handler = handler
        self._ip:   str = "0.0.0.0"
        self._port: int = 0

    def connection_made(self, conn):
        peer = conn.get_extra_info("peername")
        if peer:
            self._ip, self._port = peer[0], peer[1]

    def begin_auth(self, username: str) -> bool:
        return True  # always require password phase

    def password_auth_supported(self) -> bool:
        return True

    def public_key_auth_supported(self) -> bool:
        return False

    def validate_password(self, username: str, password: str) -> bool:
        # Capture credential (fire-and-forget)
        asyncio.ensure_future(
            self._handler.emit(
                self._ip, self._port,
                "auth_attempt", "high",
                {"username": username, "password": password, "auth_type": "password"},
                tags=["credential_capture"],
            )
        )
        key = f"{self._ip}:{username}"
        attempts = self._handler._auth_attempts.get(key, 0) + 1
        self._handler._auth_attempts[key] = attempts

        if attempts >= 5:
            asyncio.ensure_future(
                self._handler.emit(
                    self._ip, self._port,
                    "brute_force_detected", "critical",
                    {"attempts": attempts, "username": username},
                    tags=["brute_force"],
                )
            )
        # Always accept after the first failed attempt so attackers drop into the shell
        return attempts >= 2


class SshHandler(BaseHoneypotHandler):
    PROTOCOL = "SSH"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._auth_attempts: dict[str, int] = {}
        self._fp = get_fingerprint_manager()
        self._server = None

    async def start(self):
        host = self.config.get("bind_host", "0.0.0.0")
        port = self.config.get("port", 10022)

        host_key = asyncssh.generate_private_key("ssh-rsa", key_size=3072)
        banner   = self._fp.get_ssh_banner(self.decoy_id)
        # asyncssh expects only the version string after "SSH-2.0-"
        version  = banner.replace("SSH-2.0-", "").strip()

        self._server = await asyncssh.create_server(
            lambda: _PhantomSSHServer(self),
            host,
            port,
            server_host_keys=[host_key],
            process_factory=self._handle_process,
            server_version=version,
            allow_pty=True,
            x11_forwarding=False,
            agent_forwarding=False,
            encoding="utf-8",       # text mode — required for async for line in stdin
        )
        self.log.info("ssh_started", port=port, banner=banner)
        return self._server

    # ------------------------------------------------------------------
    # Shell session
    # ------------------------------------------------------------------

    async def _handle_process(self, process: asyncssh.SSHServerProcess):
        conn     = process.get_extra_info("connection")
        peer     = conn.get_extra_info("peername") or ("0.0.0.0", 0)
        ip, src_port = peer[0], peer[1]
        username = process.get_extra_info("username") or "root"
        session_id = uuid4()
        started_at = datetime.now(timezone.utc)
        transcript: list[dict] = []

        if not await self.tracker.allow(ip):
            process.exit(1)
            return

        fp   = self._fp
        ai   = PhantomAI("SSH", {
            "os_version":   self.config.get("os_version",   "Ubuntu 22.04 LTS"),
            "hostname":     self.config.get("hostname",     "web-prod-01"),
            "fake_purpose": self.config.get("fake_purpose", "internal payment processing system"),
        })
        kernel = fp.get_kernel_version(self.decoy_id)
        host   = self.config.get("hostname", "web-prod-01")
        updays = fp.get_uptime_seconds(self.decoy_id) // 86400

        await self.emit(ip, src_port, "connection", "medium",
                        {"banner": fp.get_ssh_banner(self.decoy_id), "username": username},
                        session_id=session_id)

        # ── MOTD ───────────────────────────────────────────────────────
        motd = (
            f"\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux {kernel} x86_64)\r\n"
            f"\r\n * Documentation:  https://help.ubuntu.com\r\n"
            f" * Management:     https://landscape.canonical.com\r\n"
            f"\r\n  System information as of "
            f"{datetime.now(timezone.utc).strftime('%a %d %b %Y %H:%M:%S UTC')}\r\n"
            f"\r\n  System load:  0.08              Processes:              142\r\n"
            f"  Usage of /:   23.1% of 28.90GB   Users logged in:        1\r\n"
            f"  Memory usage: 31%                IPv4 address for eth0:  10.0.1.5\r\n"
            f"  Swap usage:   0%\r\n"
            f"\r\n  => {updays} updates can be applied immediately.\r\n\r\n"
        )
        process.stdout.write(motd)

        prompt = f"{username}@{host}:~$ "

        # ── Command loop — use async-for which works with PTY ──────────
        try:
            async for raw_line in _line_iter(process, prompt, timeout=180):
                cmd = raw_line.strip()
                if not cmd:
                    continue

                # classify severity / tags
                tags: list[str] = []
                if any(x in cmd.lower() for x in ["wget ", "curl "]):
                    tags.append("download_attempt")
                if any(x in cmd.lower() for x in
                       ["chmod +x", "/bin/sh", "bash -i", "python -c", "perl -e",
                        "mkfifo", "nc -e", "socat"]):
                    tags.append("malicious_command")

                # realistic timing jitter
                await asyncio.sleep(fp.get_response_delay(cmd))

                ai_resp = await ai.respond(str(session_id), cmd)
                response = ai_resp.text

                if ai_resp.evasion_detected:
                    tags.append("evasion_attempt")

                sev = "critical" if "malicious_command" in tags else "high"
                await self.emit(
                    ip, src_port, "command_executed", sev,
                    {
                        "command":          cmd,
                        "username":         username,
                        "response_preview": (response or "")[:200],
                        "attacker_skill":   ai_resp.skill_level,
                        "evasion_detected": ai_resp.evasion_detected,
                    },
                    tags=tags + ai_resp.mitre_techniques,
                    session_id=session_id,
                )
                transcript.append({
                    "seq":      len(transcript) + 1,
                    "cmd":      cmd,
                    "response": (response or "")[:500],
                    "ts":       datetime.now(timezone.utc).isoformat(),
                })

                if cmd in {"exit", "logout", "quit"}:
                    process.stdout.write("logout\r\n")
                    break

                if response:
                    process.stdout.write(response.replace("\n", "\r\n") + "\r\n")

        except (asyncssh.DisconnectError, asyncssh.ConnectionLost,
                asyncio.TimeoutError, BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            self.log.error("ssh_session_error", error=str(exc), ip=ip)
        finally:
            duration = round((datetime.now(timezone.utc) - started_at).total_seconds())
            await self.emit(
                ip, src_port, "session_closed", "medium",
                {
                    "duration_seconds": duration,
                    "command_count":    len(transcript),
                    "transcript":       transcript,
                    "attacker_profile": ai.get_profile(),
                },
                session_id=session_id,
            )
            await self.tracker.release(ip)
            try:
                process.exit(0)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Helper: async line iterator that prints prompt then reads a line
# ---------------------------------------------------------------------------

async def _line_iter(process: asyncssh.SSHServerProcess,
                     prompt: str,
                     timeout: float = 180):
    """
    Yield one stripped line per iteration, printing the prompt first.

    Works in both PTY (raw) and non-PTY (line-buffered) modes because we
    accumulate bytes until \\r or \\n ourselves when using PTY, and rely on
    asyncssh's readline() for non-PTY.
    """
    stdin  = process.stdin
    stdout = process.stdout
    is_pty = process.get_terminal_type() is not None

    if is_pty:
        # PTY mode: asyncssh delivers chars individually; accumulate manually
        buf = ""
        while True:
            stdout.write(prompt)
            buf = ""
            try:
                while True:
                    ch = await asyncio.wait_for(stdin.read(1), timeout=timeout)
                    if ch in ("\r", "\n"):
                        stdout.write("\r\n")
                        yield buf
                        break
                    elif ch in ("\x03", "\x04"):   # Ctrl-C / Ctrl-D
                        return
                    elif ch in ("\x7f", "\x08"):   # Backspace / DEL
                        if buf:
                            buf = buf[:-1]
                            stdout.write("\x08 \x08")  # erase char visually
                    else:
                        buf += ch
                        stdout.write(ch)               # local echo
            except asyncio.TimeoutError:
                return
            except Exception:
                return
    else:
        # Non-PTY mode: reliable readline
        while True:
            stdout.write(prompt)
            try:
                line = await asyncio.wait_for(stdin.readline(), timeout=timeout)
            except asyncio.TimeoutError:
                return
            if line is None or line == "":
                return
            yield line
