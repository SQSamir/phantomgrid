"""
Realistic fake Linux shell for honeypot handlers.
Shared by SSH, Telnet, and any future interactive-shell honeypot.
"""
import random
import secrets
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Fake filesystem
# ---------------------------------------------------------------------------

_FILES: dict[str, str] = {
    "/etc/passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "syslog:x:104:110::/home/syslog:/usr/sbin/nologin\n"
        "deploy:x:1000:1000:Deploy User,,,:/home/deploy:/bin/bash\n"
        "jenkins:x:1001:1001::/home/jenkins:/bin/bash\n"
    ),
    "/etc/shadow": (
        "root:$6$rounds=5000$salt$hashed_password_placeholder:19000:0:99999:7:::\n"
        "deploy:$6$rounds=5000$salt$hashed_password_placeholder:19100:0:99999:7:::\n"
    ),
    "/etc/hostname": "web-prod-01\n",
    "/etc/hosts": (
        "127.0.0.1\tlocalhost\n"
        "127.0.1.1\tweb-prod-01\n"
        "10.10.0.10\tdc01.corp.internal dc01\n"
        "10.10.0.11\tdc02.corp.internal dc02\n"
        "10.10.1.20\tfs01.corp.internal fs01\n"
        "10.10.2.50\tfin-db.corp.internal fin-db\n"
        "10.10.2.51\thr-db.corp.internal hr-db\n"
    ),
    "/etc/os-release": (
        'NAME="Ubuntu"\n'
        'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
        'ID=ubuntu\nID_LIKE=debian\n'
        'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n'
        'VERSION_ID="22.04"\n'
        'HOME_URL="https://www.ubuntu.com/"\n'
        'SUPPORT_URL="https://help.ubuntu.com/"\n'
    ),
    "/etc/issue": "Ubuntu 22.04.3 LTS \\n \\l\n",
    "/proc/version": (
        "Linux version 5.15.0-91-generic "
        "(buildd@lcy02-amd64-059) "
        "(gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0) "
        "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023\n"
    ),
    "/proc/uptime": "1523847.12 6094203.44\n",
    "/proc/cpuinfo": (
        "processor\t: 0\nvendor_id\t: GenuineIntel\n"
        "cpu family\t: 6\nmodel\t\t: 85\n"
        "model name\t: Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz\n"
        "cpu MHz\t\t: 2299.998\ncache size\t: 25344 KB\n"
        "bogomips\t: 4599.99\nflags\t\t: fpu vme de pse tsc msr\n\n"
        "processor\t: 1\nvendor_id\t: GenuineIntel\n"
        "model name\t: Intel(R) Xeon(R) Gold 6140 CPU @ 2.30GHz\n"
        "cpu MHz\t\t: 2299.998\n"
    ),
    "/proc/meminfo": (
        "MemTotal:       16383564 kB\n"
        "MemFree:          284732 kB\n"
        "MemAvailable:    4291848 kB\n"
        "Buffers:          215084 kB\n"
        "Cached:          4231048 kB\n"
        "SwapTotal:       2097148 kB\n"
        "SwapFree:        1832960 kB\n"
    ),
    "/etc/crontab": (
        "# /etc/crontab: system-wide crontab\n"
        "SHELL=/bin/sh\nPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
        "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
        "25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
        "0 2\t* * 7\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
        "* * * * *\troot\t/opt/monitoring/health_check.sh > /dev/null 2>&1\n"
        "0 3 * * *\tdeploy\t/home/deploy/backup.sh >> /var/log/backup.log 2>&1\n"
    ),
    "/etc/nginx/nginx.conf": (
        "user www-data;\nworker_processes auto;\npid /run/nginx.pid;\n\n"
        "events { worker_connections 768; }\n\n"
        "http {\n"
        "    sendfile on;\n    tcp_nopush on;\n    types_hash_max_size 2048;\n\n"
        "    include /etc/nginx/mime.types;\n"
        "    default_type application/octet-stream;\n\n"
        "    ssl_protocols TLSv1.2 TLSv1.3;\n\n"
        "    access_log /var/log/nginx/access.log;\n"
        "    error_log /var/log/nginx/error.log;\n\n"
        "    include /etc/nginx/conf.d/*.conf;\n"
        "    include /etc/nginx/sites-enabled/*;\n}\n"
    ),
    "/root/.bash_history": (
        "ls -la\ncd /var/www/html\ncat /etc/passwd\n"
        "ssh deploy@10.10.0.50\n"
        "mysql -h 10.10.2.50 -u root -pS3cr3tPr0d\n"
        "tail -f /var/log/nginx/access.log\n"
        "systemctl restart nginx\nsystemctl status postgresql\n"
        "df -h\nfree -m\nps aux | grep nginx\n"
        "find / -name '*.conf' -type f 2>/dev/null\n"
        "cat /root/.ssh/authorized_keys\n"
        "netstat -tlnp\n"
    ),
    "/root/.bashrc": (
        "# ~/.bashrc\nexport PS1='\\u@\\h:\\w\\$ '\n"
        "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\n"
        "alias grep='grep --color=auto'\n"
    ),
    "/root/.ssh/authorized_keys": (
        "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDKnxkpQ8JvvmAk"
        "Rnd9xT4mPqO7nV2cYuL5s8Fp3bJhW deploy@bastion\n"
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMH jenkins@ci-01\n"
    ),
    "/home/deploy/.bash_history": (
        "git pull origin main\nnpm run build\n"
        "sudo systemctl restart app\ncurl localhost:3000/health\n"
        "cat /etc/nginx/sites-enabled/app.conf\nsudo tail -100 /var/log/app/error.log\n"
        "psql -h 10.10.2.50 -U app_user -d app_production\n"
    ),
    "/var/log/auth.log": (
        "Apr 12 09:15:01 web-prod-01 sshd[1234]: Accepted publickey for deploy from 10.10.0.5 port 52341 ssh2\n"
        "Apr 12 09:15:02 web-prod-01 sshd[1235]: pam_unix(sshd:session): session opened for user deploy\n"
        "Apr 12 10:22:33 web-prod-01 sudo[2341]: deploy : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/apt update\n"
        "Apr 12 11:04:17 web-prod-01 sshd[3102]: Failed password for invalid user admin from 185.220.101.42 port 43821\n"
        "Apr 12 11:04:19 web-prod-01 sshd[3103]: Failed password for invalid user root from 185.220.101.42 port 43825\n"
    ),
    "/var/log/syslog": (
        "Apr 12 11:00:01 web-prod-01 CRON[4521]: (root) CMD (cd / && run-parts --report /etc/cron.hourly)\n"
        "Apr 12 11:00:01 web-prod-01 CRON[4522]: (deploy) CMD (/home/deploy/backup.sh >> /var/log/backup.log 2>&1)\n"
        "Apr 12 11:17:01 web-prod-01 systemd[1]: nginx.service: Reloading configuration.\n"
        "Apr 12 11:17:01 web-prod-01 nginx[4801]: 2026/04/12 11:17:01 [notice] signal process started\n"
    ),
    "/var/www/html/wp-config.php": (
        "<?php\n"
        "define('DB_NAME', 'wordpress_prod');\n"
        "define('DB_USER', 'wp_user');\n"
        "define('DB_PASSWORD', 'Wpr0d@2024!');\n"
        "define('DB_HOST', '10.10.2.50');\n"
        "define('DB_CHARSET', 'utf8mb4');\n"
        "define('AUTH_KEY', '" + secrets.token_hex(32) + "');\n"
        "define('SECURE_AUTH_KEY', '" + secrets.token_hex(32) + "');\n"
        "?>\n"
    ),
    "/opt/monitoring/health_check.sh": (
        "#!/bin/bash\n"
        "curl -sf http://localhost/health || systemctl restart app\n"
        "df -h | awk '$5 > 90 {print \"DISK ALERT:\", $0}' | mail -s 'Disk Alert' ops@corp.internal\n"
    ),
}

# Directory listing data: dirname → list of (name, type, size, mtime, perms)
_DIRS: dict[str, list[tuple[str, str, str, str, str]]] = {
    "/": [
        ("bin",  "d", "4096",  "Jan 15 08:12", "drwxr-xr-x"),
        ("boot", "d", "262144","Mar  2 14:01", "drwxr-xr-x"),
        ("dev",  "d", "3980",  "Apr 12 00:01", "drwxr-xr-x"),
        ("etc",  "d", "4096",  "Apr 12 09:15", "drwxr-xr-x"),
        ("home", "d", "4096",  "Feb 20 11:30", "drwxr-xr-x"),
        ("lib",  "d", "4096",  "Mar  2 14:01", "drwxr-xr-x"),
        ("opt",  "d", "4096",  "Mar 15 10:22", "drwxr-xr-x"),
        ("proc", "d", "0",     "Apr 12 00:00", "dr-xr-xr-x"),
        ("root", "d", "4096",  "Apr 12 09:15", "drwx------"),
        ("run",  "d", "780",   "Apr 12 00:00", "drwxr-xr-x"),
        ("sbin", "d", "4096",  "Mar  2 14:01", "drwxr-xr-x"),
        ("srv",  "d", "4096",  "Jan 15 08:12", "drwxr-xr-x"),
        ("sys",  "d", "0",     "Apr 12 00:00", "dr-xr-xr-x"),
        ("tmp",  "d", "4096",  "Apr 12 11:00", "drwxrwxrwt"),
        ("usr",  "d", "4096",  "Mar  2 14:01", "drwxr-xr-x"),
        ("var",  "d", "4096",  "Apr  1 03:00", "drwxr-xr-x"),
    ],
    "/root": [
        (".bash_history", "f", "312",  "Apr 12 09:15", "-rw-------"),
        (".bashrc",       "f", "3526", "Jan 15 08:12", "-rw-r--r--"),
        (".profile",      "f", "807",  "Jan 15 08:12", "-rw-r--r--"),
        (".ssh",          "d", "4096", "Feb 20 11:30", "drwx------"),
        (".viminfo",      "f", "11534","Apr 10 14:22", "-rw-------"),
    ],
    "/root/.ssh": [
        ("authorized_keys", "f", "189",  "Feb 20 11:30", "-rw-------"),
        ("known_hosts",     "f", "2847", "Apr 12 09:15", "-rw-r--r--"),
    ],
    "/home": [
        ("deploy",  "d", "4096", "Apr 12 09:15", "drwxr-xr-x"),
        ("jenkins", "d", "4096", "Mar  1 15:00", "drwxr-xr-x"),
    ],
    "/home/deploy": [
        (".bash_history", "f", "256",     "Apr 12 09:15", "-rw-------"),
        (".bashrc",       "f", "3526",    "Jan 15 08:12", "-rw-r--r--"),
        (".ssh",          "d", "4096",    "Feb 20 11:30", "drwx------"),
        ("backup.sh",     "f", "512",     "Mar 10 09:00", "-rwxr-x---"),
        ("backup.tar.gz", "f", "45678902","Apr 12 03:00", "-rw-r-----"),
    ],
    "/etc": [
        ("crontab",    "f", "1042", "Jan 15 08:12", "-rw-r--r--"),
        ("hostname",   "f", "13",   "Jan 15 08:12", "-rw-r--r--"),
        ("hosts",      "f", "215",  "Feb 20 11:30", "-rw-r--r--"),
        ("issue",      "f", "28",   "Jan 15 08:12", "-rw-r--r--"),
        ("nginx",      "d", "4096", "Mar  5 10:00", "drwxr-xr-x"),
        ("os-release", "f", "266",  "Jan 15 08:12", "-rw-r--r--"),
        ("passwd",     "f", "1762", "Feb 20 11:30", "-rw-r--r--"),
        ("shadow",     "f", "1492", "Feb 20 11:30", "-rw-r-----"),
        ("ssh",        "d", "4096", "Jan 15 08:12", "drwxr-xr-x"),
        ("systemd",    "d", "4096", "Mar  2 14:01", "drwxr-xr-x"),
    ],
    "/var/log": [
        ("auth.log",    "f", "51200",  "Apr 12 11:04", "-rw-r-----"),
        ("syslog",      "f", "102400", "Apr 12 11:17", "-rw-r-----"),
        ("dpkg.log",    "f", "24576",  "Apr  1 03:00", "-rw-r--r--"),
        ("nginx",       "d", "4096",   "Apr 12 00:00", "drwxr-x---"),
        ("backup.log",  "f", "4096",   "Apr 12 03:00", "-rw-r--r--"),
    ],
    "/var/www/html": [
        (".htaccess",    "f", "543",     "Mar  1 10:00", "-rw-r--r--"),
        ("index.php",    "f", "420",     "Mar  1 10:00", "-rw-r--r--"),
        ("wp-config.php","f", "3241",    "Mar  1 10:00", "-rw-r--r--"),
        ("wp-login.php", "f", "47742",   "Mar  1 10:00", "-rw-r--r--"),
        ("wp-includes",  "d", "4096",    "Mar  1 10:00", "drwxr-xr-x"),
        ("wp-content",   "d", "4096",    "Apr 10 14:00", "drwxr-xr-x"),
    ],
    "/tmp": [
        (".ICE-unix",             "d", "4096", "Apr 12 00:00", "drwxrwxrwt"),
        ("systemd-private-abc123","d", "4096", "Apr 12 00:00", "drwx------"),
    ],
    "/opt": [
        ("monitoring", "d", "4096", "Mar 15 10:22", "drwxr-xr-x"),
    ],
    "/opt/monitoring": [
        ("health_check.sh", "f", "128", "Mar 15 10:22", "-rwxr-x---"),
    ],
}

_PS_OUTPUT = """\
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.0  0.1  22548  9876 ?        Ss   Apr10   0:08 /sbin/init splash
root         412  0.0  0.0      0     0 ?        S    Apr10   0:00 [kworker/0:5]
root         512  0.0  0.1  15856  7680 ?        Ss   Apr10   0:02 /lib/systemd/systemd-journald
root         892  0.0  0.1  24816  9216 ?        Ss   Apr10   0:01 /lib/systemd/systemd-udevd
root        1024  0.0  0.2  72904 18432 ?        Ss   Apr10   0:03 /usr/sbin/sshd -D
www-data    1080  0.0  0.4 394488 34816 ?        Ss   Apr10   0:15 nginx: master process
www-data    1081  0.3  0.8 407256 68096 ?        S    Apr10   2:47 nginx: worker process
www-data    1082  0.2  0.8 407256 67072 ?        S    Apr10   2:31 nginx: worker process
postgres    1201  0.1  1.2 387204 98304 ?        Ss   Apr10   0:42 postgres: 14/main
deploy      1350  0.0  0.5 891904 40960 ?        Sl   Apr10   0:22 node /home/deploy/app/server.js
root        1402  0.0  0.1  14856  8960 ?        Ss   Apr10   0:00 /usr/sbin/cron -f
root        2048  0.0  0.0  11716  3072 pts/0    Ss   09:15   0:00 -bash
root        2049  0.0  0.0   8196  1536 pts/0    R+   09:15   0:00 ps aux
"""

_NETSTAT_OUTPUT = """\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      1024/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1080/nginx
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      1080/nginx
tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN      1201/postgres
tcp        0      0 127.0.0.1:3000          0.0.0.0:*               LISTEN      1350/node
tcp        0      0 0.0.0.0:22              185.220.101.42:43980    ESTABLISHED 2048/sshd
tcp6       0      0 :::22                   :::*                    LISTEN      1024/sshd
tcp6       0      0 :::80                   :::*                    LISTEN      1080/nginx
"""

_SS_OUTPUT = """\
Netid State  Recv-Q Send-Q  Local Address:Port   Peer Address:Port  Process
tcp   LISTEN 0      128     0.0.0.0:22           0.0.0.0:*          users:(("sshd",pid=1024))
tcp   LISTEN 0      511     0.0.0.0:80           0.0.0.0:*          users:(("nginx",pid=1080))
tcp   LISTEN 0      511     0.0.0.0:443          0.0.0.0:*          users:(("nginx",pid=1080))
tcp   LISTEN 0      128     127.0.0.1:5432       0.0.0.0:*          users:(("postgres",pid=1201))
tcp   LISTEN 0      511     127.0.0.1:3000       0.0.0.0:*          users:(("node",pid=1350))
tcp   ESTAB  0      0       10.10.0.1:22         185.220.101.42:43980
"""

_IFCONFIG_OUTPUT = """\
ens3: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.10.0.100  netmask 255.255.255.0  broadcast 10.10.0.255
        inet6 fe80::216:3eff:fe4b:8a2c  prefixlen 64  scopeid 0x20<link>
        ether 00:16:3e:4b:8a:2c  txqueuelen 1000  (Ethernet)
        RX packets 18432847  bytes 24398053248 (24.3 GB)
        TX packets 12847392  bytes 18293847392 (18.2 GB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
"""

_IP_ADDR_OUTPUT = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:16:3e:4b:8a:2c brd ff:ff:ff:ff:ff:ff
    inet 10.10.0.100/24 brd 10.10.0.255 scope global dynamic ens3
       valid_lft 85234sec preferred_lft 85234sec
"""

_ENV_OUTPUT = """\
SHELL=/bin/bash
TERM=xterm-256color
USER=root
HOME=/root
LOGNAME=root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MAIL=/var/mail/root
LANG=en_US.UTF-8
HISTSIZE=1000
HISTFILESIZE=2000
"""

_DF_OUTPUT = """\
Filesystem      Size  Used Avail Use% Mounted on
/dev/vda1        50G   34G   14G  72% /
tmpfs           7.8G     0  7.8G   0% /dev/shm
tmpfs           1.6G  2.1M  1.6G   1% /run
/dev/vda15      105M  6.1M   99M   6% /boot/efi
tmpfs           1.6G   12K  1.6G   1% /run/user/1000
"""

_FREE_OUTPUT = """\
               total        used        free      shared  buff/cache   available
Mem:        16383564     8421376      284732      217088     7677456     7505024
Swap:        2097148      264188     1832960
"""

_SYSTEMCTL_STATUS = {
    "nginx":      ("● nginx.service - A high performance web server",    "active (running)", "1080"),
    "ssh":        ("● ssh.service - OpenBSD Secure Shell server",         "active (running)", "1024"),
    "sshd":       ("● ssh.service - OpenBSD Secure Shell server",         "active (running)", "1024"),
    "postgresql":("● postgresql.service - PostgreSQL RDBMS",              "active (running)", "1201"),
    "cron":       ("● cron.service - Regular background program processing","active (running)", "1402"),
    "ufw":        ("● ufw.service - Uncomplicated firewall",              "active (exited)",  "—"),
    "fail2ban":   ("● fail2ban.service - Fail2Ban Service",               "active (running)", "1501"),
}


# ---------------------------------------------------------------------------
# Shell class
# ---------------------------------------------------------------------------

class FakeShell:
    """
    Stateful fake Linux shell.  Call execute(cmd) for each line of input.
    Returns the response string.  Returns the sentinel "__EXIT__" on exit.
    """

    def __init__(self, hostname: str = "web-prod-01", username: str = "root"):
        self.hostname  = hostname
        self.username  = username
        self.cwd       = "/root" if username == "root" else f"/home/{username}"
        self.history: list[str] = []
        self._startup  = datetime.now(timezone.utc)

    # ------------------------------------------------------------------
    def prompt(self) -> str:
        display = "~" if self.cwd in ("/root", f"/home/{self.username}") else self.cwd
        sym = "#" if self.username == "root" else "$"
        return f"{self.username}@{self.hostname}:{display}{sym} "

    def execute(self, raw: str) -> str:
        cmd = raw.strip()
        if not cmd or cmd.startswith("#"):
            return ""
        self.history.append(cmd)

        # Pipe / redirect — just run the first segment for simplicity
        base_cmd = cmd.split("|")[0].split(">")[0].split("<")[0].strip()
        parts    = base_cmd.split()
        verb     = parts[0]
        args     = parts[1:]

        # Aliases
        _alias = {"dir": "ls", "ll": "ls", "l": "ls", "la": "ls",
                  "quit": "exit", "logout": "exit",
                  "bash": "_shell", "sh": "_shell", "zsh": "_shell",
                  "python": "python3", "py": "python3", "perl": "_interp",
                  "vi": "nano", "vim": "nano"}
        verb = _alias.get(verb, verb)

        handler = getattr(self, f"_cmd_{verb}", None)
        if handler:
            try:
                return handler(args, raw)
            except Exception:
                return ""

        # Executable-looking path
        if verb.startswith("./") or verb.startswith("/"):
            name = verb.split("/")[-1]
            return f"bash: {verb}: Permission denied"

        # sudo pass-through
        if verb == "sudo" and args:
            return self.execute(" ".join(args))

        return f"{verb}: command not found"

    # ------------------------------------------------------------------
    # Filesystem helpers
    # ------------------------------------------------------------------

    def _resolve(self, path: str) -> str:
        if not path or path == "~":
            return "/root" if self.username == "root" else f"/home/{self.username}"
        if path.startswith("~"):
            home = "/root" if self.username == "root" else f"/home/{self.username}"
            path = home + path[1:]
        if not path.startswith("/"):
            path = self.cwd.rstrip("/") + "/" + path
        # Normalise: remove . and ..
        parts, out = path.split("/"), []
        for p in parts:
            if p in ("", "."):
                continue
            if p == "..":
                if out:
                    out.pop()
            else:
                out.append(p)
        return "/" + "/".join(out)

    def _ls_dir(self, path: str, long: bool = False) -> str:
        entries = _DIRS.get(path)
        if entries is None:
            # Check if it's a file
            if path in _FILES:
                return f"ls: cannot access '{path}': Not a directory"
            return f"ls: cannot access '{path}': No such file or directory"
        if not long:
            names = [e[0] for e in entries]
            # Format in columns
            cols, line, lines = 4, [], []
            for n in names:
                line.append(n.ljust(18))
                if len(line) >= cols:
                    lines.append("".join(line).rstrip())
                    line = []
            if line:
                lines.append("".join(line).rstrip())
            return "\n".join(lines)
        total = sum(int(e[2]) for e in entries) // 512 + 1
        rows  = [f"total {total}"]
        for name, ftype, size, mtime, perms in entries:
            owner = "root" if perms[0] != "-" or "root" in name else "deploy"
            rows.append(f"{perms}  1 {owner:<8} {owner:<8} {size:>9} {mtime}  {name}")
        return "\n".join(rows)

    # ------------------------------------------------------------------
    # Built-in commands
    # ------------------------------------------------------------------

    def _cmd_ls(self, args, _raw):
        long  = any(a for a in args if "-" in a and "l" in a)
        paths = [a for a in args if not a.startswith("-")] or [self.cwd]
        out   = []
        for p in paths:
            resolved = self._resolve(p)
            if len(paths) > 1:
                out.append(f"{p}:")
            out.append(self._ls_dir(resolved, long))
        return "\n".join(out)

    def _cmd_pwd(self, args, _raw):
        return self.cwd

    def _cmd_cd(self, args, _raw):
        dest = self._resolve(args[0] if args else "~")
        if dest in _DIRS or dest in _FILES:
            if dest in _FILES:
                return f"bash: cd: {dest}: Not a directory"
            self.cwd = dest
            return ""
        return f"bash: cd: {dest}: No such file or directory"

    def _cmd_cat(self, args, _raw):
        if not args:
            return ""
        out = []
        for a in args:
            path = self._resolve(a)
            if path in _FILES:
                out.append(_FILES[path].rstrip("\n"))
            elif path in _DIRS:
                out.append(f"cat: {a}: Is a directory")
            else:
                out.append(f"cat: {a}: No such file or directory")
        return "\n".join(out)

    def _cmd_head(self, args, _raw):
        n, files = 10, []
        i = 0
        while i < len(args):
            if args[i] in ("-n",) and i + 1 < len(args):
                try: n = int(args[i + 1])
                except ValueError: pass
                i += 2
            elif args[i].startswith("-") and len(args[i]) > 1:
                try: n = int(args[i][1:])
                except ValueError: pass
                i += 1
            else:
                files.append(args[i]); i += 1
        files = files or [self.cwd]
        out = []
        for f in files:
            path = self._resolve(f)
            content = _FILES.get(path, f"head: cannot open '{f}' for reading: No such file or directory")
            out.append("\n".join(content.splitlines()[:n]))
        return "\n".join(out)

    def _cmd_tail(self, args, _raw):
        n, files = 10, []
        i = 0
        while i < len(args):
            if args[i] in ("-n",) and i + 1 < len(args):
                try: n = int(args[i + 1])
                except ValueError: pass
                i += 2
            elif args[i].startswith("-") and len(args[i]) > 1:
                try: n = int(args[i][1:])
                except ValueError: pass
                i += 1
            else:
                files.append(args[i]); i += 1
        out = []
        for f in (files or [self.cwd]):
            path = self._resolve(f)
            content = _FILES.get(path, f"tail: cannot open '{f}' for reading: No such file or directory")
            out.append("\n".join(content.splitlines()[-n:]))
        return "\n".join(out)

    def _cmd_less(self, args, _raw):
        return self._cmd_cat(args, _raw)

    def _cmd_more(self, args, _raw):
        return self._cmd_cat(args, _raw)

    def _cmd_echo(self, args, _raw):
        text = " ".join(args)
        # Handle basic variable substitution
        for var, val in [("$HOME", "/root"), ("$USER", self.username),
                         ("$SHELL", "/bin/bash"), ("$PATH", _ENV_OUTPUT.split("PATH=")[1].splitlines()[0]),
                         ("$PWD", self.cwd), ("$$", "2048"), ("$HOSTNAME", self.hostname)]:
            text = text.replace(var, val)
        return text.replace('"', "").replace("'", "")

    def _cmd_whoami(self, args, _raw):
        return self.username

    def _cmd_id(self, args, _raw):
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        return f"uid=1000({self.username}) gid=1000({self.username}) groups=1000({self.username}),27(sudo),4(adm)"

    def _cmd_hostname(self, args, _raw):
        return self.hostname

    def _cmd_uname(self, args, _raw):
        raw_a = "-a" in " ".join(args)
        if raw_a or not args:
            if raw_a:
                return f"Linux {self.hostname} 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux"
            return "Linux"
        flags = " ".join(args)
        if "-r" in flags: return "5.15.0-91-generic"
        if "-m" in flags: return "x86_64"
        if "-n" in flags: return self.hostname
        if "-s" in flags: return "Linux"
        if "-v" in flags: return "#101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023"
        return "Linux"

    def _cmd_uptime(self, args, _raw):
        now = datetime.now(timezone.utc)
        days = (now - self._startup).days + 17   # fake uptime
        return (f" {now.strftime('%H:%M:%S')} up {days} days, 14:33, "
                f"2 users,  load average: 0.42, 0.38, 0.41")

    def _cmd_date(self, args, _raw):
        return datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")

    def _cmd_ps(self, args, _raw):
        return _PS_OUTPUT.rstrip()

    def _cmd_top(self, args, _raw):
        return _PS_OUTPUT.rstrip()

    def _cmd_htop(self, args, _raw):
        return _PS_OUTPUT.rstrip()

    def _cmd_pstree(self, args, _raw):
        return "systemd─┬─cron\n        ├─nginx─┬─nginx\n        │       └─nginx\n        ├─postgres\n        ├─sshd───sshd───bash───pstree\n        └─node"

    def _cmd_netstat(self, args, _raw):
        return _NETSTAT_OUTPUT.rstrip()

    def _cmd_ss(self, args, _raw):
        return _SS_OUTPUT.rstrip()

    def _cmd_ifconfig(self, args, _raw):
        return _IFCONFIG_OUTPUT.rstrip()

    def _cmd_ip(self, args, _raw):
        joined = " ".join(args)
        if "addr" in joined or "a" == (args[0] if args else ""):
            return _IP_ADDR_OUTPUT.rstrip()
        if "route" in joined or "r" == (args[0] if args else ""):
            return ("default via 10.10.0.1 dev ens3 proto dhcp src 10.10.0.100 metric 100\n"
                    "10.10.0.0/24 dev ens3 proto kernel scope link src 10.10.0.100\n"
                    "169.254.0.0/16 dev ens3 scope link metric 1000")
        if "link" in joined or "l" == (args[0] if args else ""):
            return ("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
                    "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
                    "2: ens3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
                    "    link/ether 00:16:3e:4b:8a:2c brd ff:ff:ff:ff:ff:ff")
        return _IP_ADDR_OUTPUT.rstrip()

    def _cmd_env(self, args, _raw):
        return _ENV_OUTPUT.rstrip()

    def _cmd_printenv(self, args, _raw):
        return _ENV_OUTPUT.rstrip()

    def _cmd_export(self, args, _raw):
        return ""  # silently accept

    def _cmd_history(self, args, _raw):
        lines = []
        for i, h in enumerate(self.history[-50:], 1):
            lines.append(f"  {i:4d}  {h}")
        return "\n".join(lines)

    def _cmd_df(self, args, _raw):
        return _DF_OUTPUT.rstrip()

    def _cmd_free(self, args, _raw):
        return _FREE_OUTPUT.rstrip()

    def _cmd_du(self, args, _raw):
        target = args[-1] if args and not args[-1].startswith("-") else self.cwd
        return f"4.0K\t{target}"

    def _cmd_find(self, args, _raw):
        # Minimal simulation — just list some relevant matches
        raw = " ".join(args)
        if ".conf" in raw:
            return "/etc/nginx/nginx.conf\n/etc/nginx/sites-enabled/default.conf\n/etc/ssh/sshd_config"
        if "passwd" in raw or "shadow" in raw:
            return "/etc/passwd\n/etc/shadow"
        if "*.sh" in raw or ".sh" in raw:
            return "/opt/monitoring/health_check.sh\n/home/deploy/backup.sh"
        if "*.php" in raw:
            return "/var/www/html/index.php\n/var/www/html/wp-config.php\n/var/www/html/wp-login.php"
        if "*.key" in raw or "id_rsa" in raw:
            return "/root/.ssh/id_rsa\n/home/deploy/.ssh/id_rsa"
        return ""

    def _cmd_grep(self, args, _raw):
        if len(args) < 2:
            return ""
        pattern = args[0].strip('"\'')
        target  = args[-1]
        path    = self._resolve(target)
        content = _FILES.get(path, "")
        if not content:
            return f"grep: {target}: No such file or directory"
        matches = [l for l in content.splitlines() if pattern.lower() in l.lower()]
        return "\n".join(matches)

    def _cmd_wc(self, args, _raw):
        if not args:
            return ""
        path = self._resolve(args[-1])
        content = _FILES.get(path, "")
        if not content:
            return f"wc: {args[-1]}: No such file or directory"
        lines = len(content.splitlines())
        words = len(content.split())
        chars = len(content)
        return f"  {lines}   {words}  {chars} {args[-1]}"

    def _cmd_cut(self, args, _raw):
        return ""

    def _cmd_awk(self, args, _raw):
        return ""

    def _cmd_sed(self, args, _raw):
        return ""

    def _cmd_sort(self, args, _raw):
        return ""

    def _cmd_uniq(self, args, _raw):
        return ""

    def _cmd_mkdir(self, args, _raw):
        if not args:
            return "mkdir: missing operand"
        return ""  # silently succeed

    def _cmd_touch(self, args, _raw):
        return ""

    def _cmd_rm(self, args, _raw):
        files = [a for a in args if not a.startswith("-")]
        for f in files:
            path = self._resolve(f)
            if path in ("/etc/passwd", "/etc/shadow", "/root", "/"):
                return f"rm: cannot remove '{f}': Operation not permitted"
        return ""

    def _cmd_cp(self, args, _raw):
        if len(args) < 2:
            return "cp: missing destination file operand"
        return ""

    def _cmd_mv(self, args, _raw):
        if len(args) < 2:
            return "mv: missing destination file operand"
        return ""

    def _cmd_chmod(self, args, _raw):
        return ""

    def _cmd_chown(self, args, _raw):
        return ""

    def _cmd_ln(self, args, _raw):
        return ""

    def _cmd_which(self, args, _raw):
        known = {"ls": "/usr/bin/ls", "cat": "/usr/bin/cat", "bash": "/usr/bin/bash",
                 "python3": "/usr/bin/python3", "nginx": "/usr/sbin/nginx",
                 "grep": "/usr/bin/grep", "find": "/usr/bin/find",
                 "wget": "/usr/bin/wget", "curl": "/usr/bin/curl",
                 "ssh": "/usr/bin/ssh", "scp": "/usr/bin/scp",
                 "git": "/usr/bin/git", "systemctl": "/usr/bin/systemctl"}
        if args and args[0] in known:
            return known[args[0]]
        return f"which: no {args[0] if args else '?'} in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin)"

    def _cmd_whereis(self, args, _raw):
        if not args:
            return ""
        cmd = args[0]
        return f"{cmd}: /usr/bin/{cmd} /usr/share/man/man1/{cmd}.1.gz"

    def _cmd_file(self, args, _raw):
        if not args:
            return ""
        path = self._resolve(args[0])
        if path in _FILES:
            if path.endswith(".sh"):
                return f"{args[0]}: Bourne-Again shell script, ASCII text executable"
            if path.endswith(".php"):
                return f"{args[0]}: PHP script, ASCII text"
            if path.endswith(".gz"):
                return f"{args[0]}: gzip compressed data"
            return f"{args[0]}: ASCII text"
        if path in _DIRS:
            return f"{args[0]}: directory"
        return f"{args[0]}: cannot open (No such file or directory)"

    def _cmd_stat(self, args, _raw):
        if not args:
            return ""
        path = self._resolve(args[0])
        if path not in _FILES and path not in _DIRS:
            return f"stat: cannot statx '{args[0]}': No such file or directory"
        return (f"  File: {args[0]}\n"
                f"  Size: 4096\t\tBlocks: 8\tIO Block: 4096   regular file\n"
                f"Device: fd01h/64769d\tInode: 524289\tLinks: 1\n"
                f"Access: (0644/-rw-r--r--)\tUid: (0/root)\tGid: (0/root)\n"
                f"Modify: 2026-04-12 09:15:01.000000000 +0000")

    def _cmd_systemctl(self, args, _raw):
        if not args:
            return ""
        action = args[0]
        service = args[1].replace(".service", "") if len(args) > 1 else ""

        if action == "status":
            info = _SYSTEMCTL_STATUS.get(service)
            if info:
                title, state, pid = info
                color_state = state
                return (f"{title}\n"
                        f"   Loaded: loaded (/lib/systemd/system/{service}.service; enabled)\n"
                        f"   Active: {color_state} since Mon 2026-04-10 00:01:02 UTC; 2 days ago\n"
                        f"  Process: {pid}\n"
                        f"   CGroup: /system.slice/{service}.service\n"
                        f"           └─{pid} {service}")
            return f"Unit {service}.service could not be found."
        if action in ("start", "stop", "restart", "reload", "enable", "disable"):
            if service in _SYSTEMCTL_STATUS:
                return ""
            return f"Failed to {action} {service}.service: Unit {service}.service not found."
        if action == "list-units":
            return ("  nginx.service         loaded active running  nginx web server\n"
                    "  ssh.service           loaded active running  OpenSSH server\n"
                    "  postgresql.service    loaded active running  PostgreSQL\n"
                    "  cron.service          loaded active running  Regular background processing\n"
                    "  fail2ban.service      loaded active running  Fail2Ban Service")
        return ""

    def _cmd_service(self, args, _raw):
        if len(args) >= 2:
            return self._cmd_systemctl([args[1], args[0]], _raw)
        return ""

    def _cmd_apt(self, args, _raw):
        if not args:
            return "apt 2.4.11 (amd64)"
        action = args[0]
        if action in ("update",):
            return ("Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                    "Hit:2 http://security.ubuntu.com/ubuntu jammy-security InRelease\n"
                    "Reading package lists... Done\n"
                    "Building dependency tree... Done\n"
                    "All packages are up to date.")
        if action in ("install",):
            pkg = args[1] if len(args) > 1 else "?"
            return (f"Reading package lists... Done\n"
                    f"Building dependency tree... Done\n"
                    f"The following NEW packages will be installed:\n  {pkg}\n"
                    f"0 upgraded, 1 newly installed, 0 to remove.\n"
                    f"Fetched 1,234 kB in 1s (1,234 kB/s)\n"
                    f"Selecting previously unselected package {pkg}.\n"
                    f"Unpacking {pkg} ...\n"
                    f"Setting up {pkg} ...\n"
                    f"Processing triggers for man-db ...")
        if action in ("list",):
            return ("Listing... Done\nnginx/jammy-updates,now 1.18.0-6ubuntu14 amd64 [installed]\n"
                    "python3/jammy,now 3.10.6-1~22.04 amd64 [installed]\n"
                    "openssh-server/jammy-updates,now 1:8.9p1-3ubuntu0.6 amd64 [installed]")
        return ""

    def _cmd_apt_get(self, args, _raw):
        return self._cmd_apt(args, _raw)

    def _cmd_yum(self, args, _raw):
        return "This system uses apt, not yum. Try: apt " + " ".join(args)

    def _cmd_wget(self, args, _raw):
        if not args:
            return "wget: missing URL"
        url = next((a for a in args if a.startswith("http")), args[-1])
        filename = url.split("/")[-1] or "index.html"
        return (f"--2026-04-12 {datetime.now(timezone.utc).strftime('%H:%M:%S')}--  {url}\n"
                f"Resolving {url.split('/')[2]}... 93.184.216.34\n"
                f"Connecting to {url.split('/')[2]}|93.184.216.34|:80... connected.\n"
                f"HTTP request sent, awaiting response... 200 OK\n"
                f"Length: 12345 (12K) [application/octet-stream]\n"
                f"Saving to: '{filename}'\n\n"
                f"{filename}         100%[===================>]  12.06K  --.-KB/s    in 0.03s\n\n"
                f"2026-04-12 {datetime.now(timezone.utc).strftime('%H:%M:%S')} (402 KB/s) - '{filename}' saved [12345/12345]")

    def _cmd_curl(self, args, _raw):
        urls = [a for a in args if a.startswith("http")]
        if not urls:
            return "curl: try 'curl --help' for more information"
        url = urls[0]
        if "localhost" in url or "127.0.0.1" in url:
            return '{"status":"ok","service":"web-app","version":"2.4.1"}'
        return '{"error":"connection refused"}'

    def _cmd_ssh(self, args, _raw):
        target = next((a for a in args if "@" in a or (not a.startswith("-") and "." in a)), "")
        return f"ssh: connect to host {target} port 22: Connection timed out"

    def _cmd_scp(self, args, _raw):
        return "scp: Connection timed out"

    def _cmd_git(self, args, _raw):
        if not args:
            return "usage: git [-v | --version] [-h | --help] <command> [<args>]"
        action = args[0]
        if action == "status":
            return "On branch main\nYour branch is up to date with 'origin/main'.\nnothing to commit, working tree clean"
        if action in ("pull", "fetch"):
            return "Already up to date."
        if action == "log":
            return ("commit a3f4b2c1d5e6 (HEAD -> main, origin/main)\nAuthor: Deploy Bot <deploy@corp.internal>\nDate:   Mon Apr 10 14:22:33 2026 +0000\n\n    chore: update dependencies\n\ncommit 9d8c7b6a5f4e\nAuthor: Dev Team <dev@corp.internal>\nDate:   Fri Apr  7 09:15:00 2026 +0000\n\n    feat: add payment processing module")
        if action == "branch":
            return "* main\n  develop\n  hotfix/cve-2024-1234"
        return f"git: '{action}' is not a git command."

    def _cmd_python3(self, args, _raw):
        if "-c" in args:
            idx = args.index("-c")
            code = args[idx + 1] if idx + 1 < len(args) else ""
            if "import" in code and ("os" in code or "subprocess" in code):
                return ""   # silently execute (attacker sees no error = thinks it worked)
            if "print" in code:
                return "Hello"
            return ""
        if args and not args[0].startswith("-"):
            return f"python3: can't open file '{args[0]}': [Errno 2] No such file or directory"
        return "Python 3.10.12 (main, Nov  6 2023, 20:22:14) [GCC 11.4.0]\nType \"help\", \"copyright\", \"credits\" or \"license\" for more information.\n>>>"

    def _cmd__interp(self, args, _raw):
        return ""

    def _cmd_nano(self, args, _raw):
        f = args[0] if args else ""
        return f"  GNU nano 6.2                  {f}"

    def _cmd_crontab(self, args, _raw):
        if "-l" in args:
            return "# m h  dom mon dow   command\n* * * * * /opt/monitoring/health_check.sh\n0 3 * * * /home/deploy/backup.sh"
        if "-e" in args:
            return "(opens editor)"
        return ""

    def _cmd_passwd(self, args, _raw):
        return ("Changing password for root.\nCurrent password: ")

    def _cmd_su(self, args, _raw):
        user = args[0] if args else "root"
        return f"Password: "

    def _cmd_man(self, args, _raw):
        cmd = args[0] if args else ""
        return f"No manual entry for {cmd}" if cmd else "What manual page do you want?"

    def _cmd_help(self, args, _raw):
        return ("GNU bash, version 5.1.16(1)-release\n"
                "These shell commands are defined internally. Type 'help' to see this list.\n\n"
                " cd [-L|[-P [-e]] [-@]] [dir]\n"
                " echo [-neE] [arg ...]\n"
                " exit [n]\n"
                " export [-fn] [name[=value] ...]\n"
                " history [-c] [-d offset] [n]\n"
                " pwd [-LP]\n"
                " read [-ers] [-a array] [-d delim] [-i text] [-n nchars] [-N nchars]\n"
                " source filename [arguments]\n"
                " type [-afptP] name [name ...]")

    def _cmd_clear(self, args, _raw):
        return "\x1b[2J\x1b[H"   # ANSI clear screen

    def _cmd_alias(self, args, _raw):
        if not args:
            return ("alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\n"
                    "alias grep='grep --color=auto'")
        return ""

    def _cmd_type(self, args, _raw):
        if not args:
            return ""
        cmd = args[0]
        known = ["ls", "cat", "echo", "cd", "pwd", "grep", "find", "bash"]
        if cmd in known:
            return f"{cmd} is /usr/bin/{cmd}"
        return f"{cmd} not found"

    def _cmd_tar(self, args, _raw):
        if not args:
            return "tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options"
        return ""

    def _cmd_gzip(self, args, _raw):
        return ""

    def _cmd_gunzip(self, args, _raw):
        return ""

    def _cmd_unzip(self, args, _raw):
        if not args:
            return "UnZip 6.00 of 20 April 2009"
        return f"Archive:  {args[-1]}\n  inflating: config.json\n  inflating: data.csv"

    def _cmd_nc(self, args, _raw):
        return ""

    def _cmd_ncat(self, args, _raw):
        return ""

    def _cmd_nmap(self, args, _raw):
        return "bash: nmap: command not found"

    def _cmd__shell(self, args, _raw):
        return ""   # stay in shell silently

    def _cmd_exit(self, args, _raw):
        return "__EXIT__"
