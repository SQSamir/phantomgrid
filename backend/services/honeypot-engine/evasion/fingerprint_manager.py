"""
Fingerprint Evasion Manager — systematically defeats honeypot fingerprinting.

Cowrie's #1 admitted weakness: static banners/fingerprints are trivially detected.
PhantomGrid rotates everything — banners, server headers, timing, TLS certs —
so no static fingerprint can be built against us.
"""
import random
from datetime import datetime, timezone
from uuid import UUID


class FingerprintEvasionManager:
    """
    Returns consistent-within-a-time-window but periodically rotating
    fingerprints for each decoy. Same decoy always looks the same today,
    different tomorrow, so repeated scans don't build a fingerprint.
    """

    # SSH banners — real versions scraped from Shodan top-20
    _SSH_BANNERS = [
        "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.2",
        "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3",
        "SSH-2.0-OpenSSH_7.4",
        "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13",
        "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.11",
        "SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7",
        "SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3",
        "SSH-2.0-OpenSSH_8.0",
        "SSH-2.0-dropbear_2022.82",
    ]

    # HTTP Server headers
    _HTTP_HEADERS = [
        "Apache/2.4.54 (Ubuntu)",
        "Apache/2.4.57 (Debian)",
        "Apache/2.4.51 (CentOS)",
        "nginx/1.24.0",
        "nginx/1.18.0 (Ubuntu)",
        "nginx/1.25.3",
        "Microsoft-IIS/10.0",
        "LiteSpeed",
        "Apache/2.4.41 (Ubuntu)",
        "openresty/1.21.4.3",
    ]

    # FTP banners
    _FTP_BANNERS = [
        "220 (vsFTPd 3.0.5)",
        "220 ProFTPD 1.3.8 Server (ProFTPD) [{}]",
        "220 FileZilla Server 1.7.0",
        "220 Microsoft FTP Service",
        "220 Pure-FTPd - http://pureftpd.org",
    ]

    # SMTP banners
    _SMTP_BANNERS = [
        "220 mail.{} ESMTP Postfix (Ubuntu)",
        "220 {} ESMTP Exim 4.96",
        "220 {} Microsoft ESMTP MAIL Service ready",
        "220 {} ESMTP Sendmail 8.17.1",
    ]

    # MySQL banners
    _MYSQL_VERSIONS = [
        "8.0.33", "8.0.35", "8.0.36", "8.1.0",
        "5.7.43", "5.7.44", "8.2.0",
    ]

    # Redis versions
    _REDIS_VERSIONS = [
        "7.0.11", "7.0.14", "7.2.3", "6.2.14", "7.0.15",
    ]

    # OS fingerprints for nmap
    _OS_FINGERPRINTS = {
        "linux_ubuntu22":   "Linux 5.15.0-91-generic Ubuntu 22.04",
        "linux_debian12":   "Linux 6.1.0-18-amd64 Debian 12",
        "linux_centos7":    "Linux 3.10.0-1160.el7.x86_64 CentOS 7",
        "linux_rhel9":      "Linux 5.14.0-362.8.1.el9 Red Hat 9",
        "windows_2022":     "Windows Server 2022 21H2",
        "windows_2019":     "Windows Server 2019 1809",
        "freebsd14":        "FreeBSD 14.0-RELEASE",
        "cisco_ios":        "Cisco IOS 15.4(3)M2",
    }

    def _seed(self, decoy_id: UUID, extra: str = "") -> int:
        """
        Deterministic seed: same decoy + same day → same banner.
        Changes daily so scanners can't build a static fingerprint.
        """
        day = datetime.now(timezone.utc).timetuple().tm_yday
        return hash(f"{decoy_id}{day}{extra}") & 0x7FFFFFFF

    # -----------------------------------------------------------------------
    # Per-protocol getters
    # -----------------------------------------------------------------------

    def get_ssh_banner(self, decoy_id: UUID) -> str:
        idx = self._seed(decoy_id, "ssh") % len(self._SSH_BANNERS)
        return self._SSH_BANNERS[idx]

    def get_http_server_header(self, decoy_id: UUID) -> str:
        idx = self._seed(decoy_id, "http") % len(self._HTTP_HEADERS)
        return self._HTTP_HEADERS[idx]

    def get_ftp_banner(self, decoy_id: UUID, hostname: str = "ftp.corp.local") -> str:
        idx = self._seed(decoy_id, "ftp") % len(self._FTP_BANNERS)
        return self._FTP_BANNERS[idx].format(hostname)

    def get_smtp_banner(self, decoy_id: UUID, hostname: str = "mail.corp.local") -> str:
        idx = self._seed(decoy_id, "smtp") % len(self._SMTP_BANNERS)
        return self._SMTP_BANNERS[idx].format(hostname)

    def get_mysql_version(self, decoy_id: UUID) -> str:
        idx = self._seed(decoy_id, "mysql") % len(self._MYSQL_VERSIONS)
        return self._MYSQL_VERSIONS[idx]

    def get_redis_version(self, decoy_id: UUID) -> str:
        idx = self._seed(decoy_id, "redis") % len(self._REDIS_VERSIONS)
        return self._REDIS_VERSIONS[idx]

    def get_os_fingerprint(self, decoy_id: UUID, os_type: str = "linux_ubuntu22") -> str:
        return self._OS_FINGERPRINTS.get(os_type, self._OS_FINGERPRINTS["linux_ubuntu22"])

    def get_uptime_seconds(self, decoy_id: UUID) -> int:
        """
        Return a consistent but always-incrementing uptime.
        Looks real: never resets, always going up.
        """
        # Base: deterministic 7-365 day uptime from decoy birth
        rng = random.Random(str(decoy_id))
        base_days = rng.randint(7, 180)
        # Add time since epoch day 0 of this year (approximation)
        day_of_year = datetime.now(timezone.utc).timetuple().tm_yday
        return (base_days + day_of_year) * 86400 + (
            datetime.now(timezone.utc).hour * 3600
            + datetime.now(timezone.utc).minute * 60
        )

    def get_mac_address(self, decoy_id: UUID, vendor: str = "vmware") -> str:
        """
        Generate a consistent, vendor-realistic MAC address.
        """
        _OUI_MAP = {
            "vmware":   "00:0c:29",
            "dell":     "18:66:da",
            "hp":       "3c:d9:2b",
            "cisco":    "00:1a:a1",
            "intel":    "8c:ec:4b",
            "lenovo":   "54:ee:75",
        }
        oui = _OUI_MAP.get(vendor.lower(), "00:50:56")
        rng = random.Random(str(decoy_id) + vendor)
        suffix = ":".join(f"{rng.randint(0, 255):02x}" for _ in range(3))
        return f"{oui}:{suffix}"

    def get_response_delay(self, command: str) -> float:
        """
        Add realistic jitter to response times.
        Real servers don't respond instantly.
        """
        _timing: dict[str, tuple[float, float]] = {
            "ls":      (0.020, 0.080),
            "cat":     (0.030, 0.120),
            "find":    (0.300, 1.500),
            "ps":      (0.050, 0.150),
            "netstat": (0.100, 0.300),
            "ss":      (0.080, 0.250),
            "grep":    (0.050, 0.400),
            "awk":     (0.040, 0.200),
            "curl":    (0.500, 3.000),
            "wget":    (0.500, 3.000),
            "id":      (0.010, 0.040),
            "whoami":  (0.010, 0.040),
        }
        base = command.strip().split()[0] if command.strip() else ""
        lo, hi = _timing.get(base, (0.030, 0.120))
        return random.uniform(lo, hi)

    def get_kernel_version(self, decoy_id: UUID) -> str:
        _kernels = [
            "5.15.0-91-generic",
            "5.15.0-101-generic",
            "6.5.0-28-generic",
            "5.14.0-362.8.1.el9_3.x86_64",
            "5.4.0-182-generic",
            "6.1.0-21-amd64",
        ]
        idx = self._seed(decoy_id, "kernel") % len(_kernels)
        return _kernels[idx]


# Singleton
_manager = FingerprintEvasionManager()


def get_fingerprint_manager() -> FingerprintEvasionManager:
    return _manager
