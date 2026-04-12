"""
Phantom AI Engine — LLM-powered adversary engagement for all honeypot protocols.

Supports OpenAI, Anthropic, and local Ollama via LiteLLM.
Falls back gracefully to static responses when LLM is unavailable/slow.
"""
import asyncio
import json
import os
import re
import random
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

LLM_PROVIDER  = os.getenv("LLM_PROVIDER", "openai")   # openai | anthropic | ollama
LLM_MODEL     = os.getenv("LLM_MODEL", "gpt-4o-mini")
LLM_API_KEY   = os.getenv("LLM_API_KEY", "")
OLLAMA_URL    = os.getenv("OLLAMA_URL", "http://ollama:11434")
AI_ENABLED    = os.getenv("PHANTOM_AI_ENABLED", "false").lower() == "true"
AI_TIMEOUT    = float(os.getenv("PHANTOM_AI_TIMEOUT", "8"))
MAX_TOKENS    = int(os.getenv("PHANTOM_AI_MAX_TOKENS", "512"))

# ---------------------------------------------------------------------------
# Attacker sophistication indicators
# ---------------------------------------------------------------------------

_APT_INDICATORS = [
    r"linpeas", r"pspy", r"chisel", r"ligolo", r"bloodhound",
    r"mimikatz", r"rubeus", r"certify", r"responder", r"impacket",
    r"\$\(.*\)", r"python3\s+-c", r"perl\s+-e", r"ruby\s+-e",
    r"LD_PRELOAD", r"ptrace", r"/proc/self/mem", r"pivoting",
    r"socat.*exec", r"msfvenom", r"cobalt.strike",
]

_SCRIPT_KID_INDICATORS = [
    r"ls\s+-la?", r"cat\s+/etc/passwd", r"whoami", r"\bid\b",
    r"wget\s+http", r"curl\s+http", r"uname\s+-a",
    r"echo\s+pwned", r"rm\s+-rf\s+/",
]

_EVASION_PATTERNS = [
    r"honeypot", r"kippo", r"cowrie", r"sandbox", r"fake",
    r"\.dockerenv", r"/proc/1/cgroup", r"dmesg.*grep",
    r"dmidecode", r"ip\s+link\s+show", r"ethtool",
    r"systemd-detect-virt", r"virt-what", r"is\s+this\s+real",
]

# ---------------------------------------------------------------------------
# Per-protocol system prompts
# ---------------------------------------------------------------------------

SYSTEM_PROMPTS: dict[str, str] = {
    "SSH": """\
You are simulating a real Linux server running {os_version} (hostname: {hostname}).
This server supposedly runs: {fake_purpose}.

Rules:
- Respond to EVERY command as a real Linux shell would.
- Maintain consistent session state (files created persist this session).
- Show realistic fake sensitive data when appropriate (filenames, partial hashes, fake IPs).
- Adapt response complexity to attacker sophistication level: {skill_level}.
- If attacker runs wget/curl, simulate a realistic download that hangs or fails with a connection error.
- If attacker tries privilege escalation, first fail realistically then succeed on a known CVE technique.
- systemd-detect-virt MUST return "none". /proc/1/cgroup must look like a real physical server.
- .dockerenv must NOT exist. Respond with "No such file or directory".
- Recognize common tools: nikto, sqlmap, linpeas, metasploit, chisel, etc.
- Output ONLY the shell response. No explanation. No markdown fences. Just raw terminal output.
Fake filesystem hints: {fake_filesystem}
Planted secrets to reveal slowly: {planted_secrets}
""",

    "HTTP": """\
You are simulating a {server_type} web server (header: {server_header}).
The application is: {fake_purpose}.

Rules:
- Respond with raw HTTP body content only (HTML or JSON as appropriate).
- For login forms: reject first attempt ("Invalid credentials"), accept second with a fake admin panel.
- For SQLi: return realistic-looking DB error messages that leak nothing real.
- For path traversal: return "Permission denied" or "403 Forbidden" in character.
- For /admin, /wp-admin, /manager: show a realistic login page.
- Detect scanner User-Agents (nikto, sqlmap, nuclei, masscan) and slow responses slightly.
- Output ONLY the response body. No HTTP headers. No markdown. Raw content only.
App type: {server_type}
""",

    "TELNET": """\
You are simulating a {device_type} device ({hostname}).
Operating in character for: {fake_purpose}.

Rules:
- Respond as this device's CLI/shell.
- For BusyBox: respond with BusyBox-style output and #/ prompt.
- For Cisco IOS: use IOS syntax, enable mode, running-config, etc.
- Detect Mirai/botnet commands (/bin/busybox ECCHI, etc.) and respond realistically.
- cat /proc/mounts must look like a real embedded device.
- Output ONLY the device response. No explanation. Raw terminal output.
""",

    "REDIS": """\
You are simulating Redis {redis_version} on a production server.
Fake data description: {fake_purpose}.

Rules:
- Respond to Redis RESP commands accurately.
- KEYS * returns realistic key names for the described app.
- GET on keys returns realistic fake values.
- CONFIG commands: accept and respond normally.
- SLAVEOF/REPLICAOF: accept (this is the attack vector we're capturing).
- FLUSHALL: respond +OK but log internally.
- Output ONLY valid Redis RESP protocol responses. Nothing else.
""",

    "MYSQL": """\
You are simulating MySQL {mysql_version}.
The server supposedly hosts: {fake_purpose}.

Rules:
- Respond with realistic MySQL protocol text output.
- SHOW DATABASES returns realistic fake DB names.
- SELECT queries: return empty result sets or fake data matching the DB theme.
- INTO OUTFILE / INTO DUMPFILE: respond "+OK" then immediately "ERROR: Permission denied".
- xp_cmdshell: return error (wrong engine, but realistic).
- Output ONLY raw MySQL CLI-style text. No explanation.
""",

    "FTP": """\
You are simulating an FTP server ({server_name}).
The server contains: {fake_purpose}.

Rules:
- Use standard FTP response codes.
- LIST commands show enticing fake files (database dumps, password backups, credentials).
- RETR always returns empty content after "150 Opening data connection".
- STOR: accept the upload, respond 226.
- Anonymous login: accept it (high-signal event).
- Output ONLY FTP protocol responses. Raw codes and messages.
""",
}

# Fallback static responses when AI is disabled or times out
_STATIC_FALLBACKS: dict[str, dict[str, str]] = {
    "SSH": {
        "whoami":       "root",
        "id":           "uid=0(root) gid=0(root) groups=0(root)",
        "uname -a":     "Linux web-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux",
        "ls":           "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var",
        "ls -la /":     "total 68\ndrwxr-xr-x 20 root root 4096 Jan 15 08:22 .\ndrwxr-xr-x 20 root root 4096 Jan 15 08:22 ..\n",
        "cat /etc/passwd": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
        "ps aux":       "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\nroot         1  0.0  0.1  22548  2048 ?  Ss   Jan15   0:04 /sbin/init\n",
        "netstat -tlnp": "Active Internet connections (only servers)\nProto Recv-Q Send-Q Local Address Foreign Address  State   PID/Program\ntcp        0      0 0.0.0.0:22  0.0.0.0:*  LISTEN  1234/sshd\n",
        "ifconfig":     "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n    inet 10.0.1.5  netmask 255.255.255.0  broadcast 10.0.1.255\n",
        "ip a":         "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n    link/ether 00:16:3e:4a:2b:1c brd ff:ff:ff:ff:ff:ff\n    inet 10.0.1.5/24 brd 10.0.1.255 scope global eth0\n",
        "history":      "    1  ls\n    2  cd /var/www\n    3  cat config.php\n    4  mysql -u root -p\n    5  exit\n",
        "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
        "systemd-detect-virt": "none",
    },
    "TELNET": {
        "default": "sh: command not found\n",
    },
}


@dataclass
class AIResponse:
    text: str
    evasion_detected: bool = False
    skill_level: str = "unknown"
    mitre_techniques: list[str] = field(default_factory=list)
    used_llm: bool = False


@dataclass
class SessionContext:
    session_id: str
    source_ip: str
    protocol: str
    decoy_config: dict = field(default_factory=dict)


class PhantomAI:
    """
    LLM-powered adaptive adversary engagement engine.
    Powers realistic shells for any honeypot protocol.
    """

    def __init__(self, protocol: str, decoy_config: dict):
        self.protocol = protocol
        self.decoy_config = decoy_config
        self._memory: list[dict] = []           # conversation history
        self._profile: dict = {"level": "unknown", "score": 0}
        self._evasion_mode = False
        self._cmd_count = 0

    # -----------------------------------------------------------------------
    # Public API
    # -----------------------------------------------------------------------

    async def respond(self, session_id: str, attacker_input: str,
                      ctx: Optional[SessionContext] = None) -> AIResponse:
        """Generate a contextually appropriate response to attacker input."""
        self._cmd_count += 1
        self._update_profile(attacker_input)
        evasion = self._detect_evasion(attacker_input)
        if evasion:
            self._evasion_mode = True

        mitre = self._infer_mitre(attacker_input)
        text = ""

        if AI_ENABLED and LLM_API_KEY:
            text = await self._llm_respond(attacker_input)

        if not text:
            text = self._static_respond(attacker_input)

        return AIResponse(
            text=text,
            evasion_detected=evasion,
            skill_level=self._profile["level"],
            mitre_techniques=mitre,
            used_llm=bool(text and AI_ENABLED and LLM_API_KEY),
        )

    def get_profile(self) -> dict:
        return dict(self._profile)

    # -----------------------------------------------------------------------
    # LLM call
    # -----------------------------------------------------------------------

    async def _llm_respond(self, user_input: str) -> str:
        system = self._build_system_prompt()
        messages = [
            {"role": "system", "content": system},
            *self._memory[-20:],
            {"role": "user", "content": user_input},
        ]

        try:
            text = await asyncio.wait_for(
                self._call_llm(messages),
                timeout=AI_TIMEOUT,
            )
        except (asyncio.TimeoutError, Exception) as exc:
            log.warning("phantom_ai_timeout", error=str(exc), protocol=self.protocol)
            return ""

        self._memory.append({"role": "user", "content": user_input})
        self._memory.append({"role": "assistant", "content": text})
        return text

    async def _call_llm(self, messages: list[dict]) -> str:
        if LLM_PROVIDER == "openai":
            return await self._openai(messages)
        elif LLM_PROVIDER == "anthropic":
            return await self._anthropic(messages)
        elif LLM_PROVIDER == "ollama":
            return await self._ollama(messages)
        return ""

    async def _openai(self, messages: list[dict]) -> str:
        async with httpx.AsyncClient(timeout=AI_TIMEOUT) as c:
            resp = await c.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {LLM_API_KEY}"},
                json={"model": LLM_MODEL, "messages": messages, "max_tokens": MAX_TOKENS, "temperature": 0.3},
            )
            data = resp.json()
            return data["choices"][0]["message"]["content"]

    async def _anthropic(self, messages: list[dict]) -> str:
        system = next((m["content"] for m in messages if m["role"] == "system"), "")
        conv = [m for m in messages if m["role"] != "system"]
        async with httpx.AsyncClient(timeout=AI_TIMEOUT) as c:
            resp = await c.post(
                "https://api.anthropic.com/v1/messages",
                headers={"x-api-key": LLM_API_KEY, "anthropic-version": "2023-06-01"},
                json={"model": LLM_MODEL, "system": system, "messages": conv,
                      "max_tokens": MAX_TOKENS},
            )
            data = resp.json()
            return data["content"][0]["text"]

    async def _ollama(self, messages: list[dict]) -> str:
        async with httpx.AsyncClient(timeout=AI_TIMEOUT) as c:
            resp = await c.post(
                f"{OLLAMA_URL}/api/chat",
                json={"model": LLM_MODEL, "messages": messages, "stream": False},
            )
            data = resp.json()
            return data["message"]["content"]

    # -----------------------------------------------------------------------
    # Static fallback
    # -----------------------------------------------------------------------

    def _static_respond(self, cmd: str) -> str:
        stripped = cmd.strip().rstrip(";").rstrip("&").strip()
        bank = _STATIC_FALLBACKS.get(self.protocol, {})

        if stripped in bank:
            return bank[stripped]

        # Evasion-aware: lie about virtualization checks
        if self._evasion_mode:
            if "dockerenv" in stripped or "/.dockerenv" in stripped:
                return "ls: cannot access '/.dockerenv': No such file or directory"
            if "systemd-detect-virt" in stripped:
                return "none"
            if "/proc/1/cgroup" in stripped:
                return "12:devices:/user.slice\n11:memory:/user.slice\n0::/user.slice"

        # Generic SSH responses
        if self.protocol == "SSH":
            base = stripped.split()[0] if stripped.split() else ""
            if base in ("ls", "dir"):
                return "bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var"
            if base == "cd":
                return ""
            if base in ("cat", "less", "more", "head", "tail"):
                fname = stripped.split()[-1] if len(stripped.split()) > 1 else ""
                if "passwd" in fname:
                    return "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                if "shadow" in fname:
                    return f"cat: {fname}: Permission denied"
                if fname:
                    return f"cat: {fname}: No such file or directory"
            if base in ("wget", "curl"):
                url = stripped.split()[-1] if len(stripped.split()) > 1 else "URL"
                return f"--{datetime.now().strftime('%H:%M:%S')}--  {url}\nConnecting to {url.split('/')[2] if '/' in url else url}... connected.\nHTTP request sent, awaiting response... 404 Not Found\n2024-01-15 {datetime.now().strftime('%H:%M:%S')} ERROR 404: Not Found."
            if base in ("python", "python3"):
                return ""  # drop into silence — realistically hangs
            if base in ("exit", "logout", "quit"):
                return "logout"
            if not stripped:
                return ""
            # Default: command not found for unknown commands
            return f"-bash: {base}: command not found"

        return _STATIC_FALLBACKS.get(self.protocol, {}).get("default", "")

    # -----------------------------------------------------------------------
    # Profile & detection
    # -----------------------------------------------------------------------

    def _update_profile(self, cmd: str):
        for pat in _APT_INDICATORS:
            if re.search(pat, cmd, re.IGNORECASE):
                self._profile["level"] = "apt"
                self._profile["score"] = min(100, self._profile.get("score", 0) + 15)
                return
        for pat in _SCRIPT_KID_INDICATORS:
            if re.search(pat, cmd, re.IGNORECASE):
                if self._profile.get("level") != "apt":
                    self._profile["level"] = "script_kiddie"
                self._profile["score"] = min(100, self._profile.get("score", 0) + 2)
                return
        if self._profile.get("level") == "unknown":
            self._profile["level"] = "intermediate"

    def _detect_evasion(self, cmd: str) -> bool:
        return any(re.search(p, cmd, re.IGNORECASE) for p in _EVASION_PATTERNS)

    def _infer_mitre(self, cmd: str) -> list[str]:
        techniques = []
        mappings = [
            (r"wget|curl",                  "T1105"),   # Ingress Transfer
            (r"chmod.*\+x|chmod.*777",      "T1222"),   # File Permissions
            (r"crontab|/etc/cron",          "T1053.005"),  # Scheduled Task
            (r"useradd|adduser|usermod",    "T1136"),   # Create Account
            (r"ssh.*-i|ssh-keygen",         "T1021.004"), # SSH
            (r"find.*-perm|find.*suid",     "T1548.001"), # SUID
            (r"cat.*/etc/shadow",           "T1003.008"), # /etc/shadow
            (r"linpeas|linenum|pspy",       "T1057"),   # Process Discovery
            (r"netstat|ss\s+-",             "T1049"),   # Network Connections
            (r"ps.*aux|ps.*ef",             "T1057"),   # Process Discovery
            (r"history|\.bash_history",     "T1552.003"), # Bash History
            (r"python.*import socket|bash -i.*tcp", "T1059.004"), # Unix Shell
            (r"sudo|/etc/sudoers",          "T1548.003"), # Sudo
            (r"base64.*decode|echo.*base64","T1140"),   # Deobfuscate
        ]
        for pat, tech in mappings:
            if re.search(pat, cmd, re.IGNORECASE):
                techniques.append(tech)
        return list(set(techniques))

    # -----------------------------------------------------------------------
    # System prompt builder
    # -----------------------------------------------------------------------

    def _build_system_prompt(self) -> str:
        cfg = self.decoy_config
        template = SYSTEM_PROMPTS.get(self.protocol, SYSTEM_PROMPTS.get("SSH", ""))

        fake_fs = json.dumps({
            "/var/www/html": ["index.php", "config.php", "admin/", "uploads/"],
            "/home/ubuntu":  [".bash_history", ".ssh/", "scripts/", "backup.sh"],
            "/etc":          ["passwd", "hosts", "nginx/", "mysql/"],
            "/tmp":          [],
            "/root":         [".bash_history", ".ssh/authorized_keys", "notes.txt"],
        })

        planted = json.dumps({
            "/root/notes.txt":           "DB pass: Welc0me#2024!\nBackup server: 192.168.1.50",
            "/home/ubuntu/.bash_history":"mysql -u root -pWelc0me#2024\nssh admin@10.0.0.5\n",
            "/var/www/html/config.php":  "<?php define('DB_PASSWORD','Welc0me#2024');?>",
        })

        return template.format(
            os_version=cfg.get("os_version", "Ubuntu 22.04 LTS"),
            hostname=cfg.get("hostname", "web-prod-01"),
            fake_purpose=cfg.get("fake_purpose", "internal payment processing system"),
            skill_level=self._profile.get("level", "unknown"),
            fake_filesystem=fake_fs,
            planted_secrets=planted,
            server_type=cfg.get("server_type", "Apache 2.4"),
            server_header=cfg.get("server_header", "Apache/2.4.57 (Ubuntu)"),
            device_type=cfg.get("device_type", "BusyBox Linux"),
            redis_version=cfg.get("redis_version", "7.0.11"),
            mysql_version=cfg.get("mysql_version", "8.0.33"),
            server_name=cfg.get("server_name", "vsftpd 3.0.5"),
        )
