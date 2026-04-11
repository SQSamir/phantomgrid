"""
MITRE ATT&CK technique mappings for PhantomGrid honeypot events.

Keys: (protocol, event_type) — both normalised to uppercase/lowercase as stored.
Values: list of technique IDs (may include sub-techniques).
"""

MITRE_MAPPING: dict[tuple[str, str], list[str]] = {
    # -------------------------------------------------------------------------
    # SSH
    # -------------------------------------------------------------------------
    ("SSH", "auth_attempt"):            ["T1110", "T1110.001"],   # Brute Force / Password Guessing
    ("SSH", "auth_success"):            ["T1078"],                 # Valid Accounts
    ("SSH", "command_executed"):        ["T1059.004"],             # Unix Shell
    ("SSH", "file_download"):           ["T1105"],                 # Ingress Tool Transfer
    ("SSH", "file_upload"):             ["T1105"],
    ("SSH", "port_forward"):            ["T1572"],                 # Protocol Tunneling
    ("SSH", "key_added"):               ["T1098.004"],             # SSH Authorized Keys
    ("SSH", "credential_reuse"):        ["T1078", "T1110.004"],   # Valid Accounts / Credential Stuffing
    ("SSH", "scan"):                    ["T1046"],                 # Network Service Discovery

    # -------------------------------------------------------------------------
    # HTTP / HTTPS
    # -------------------------------------------------------------------------
    ("HTTP", "sqli_attempt"):           ["T1190"],                 # Exploit Public-Facing Application
    ("HTTP", "xss_attempt"):            ["T1189"],                 # Drive-by Compromise
    ("HTTP", "lfi_attempt"):            ["T1190"],
    ("HTTP", "rfi_attempt"):            ["T1190"],
    ("HTTP", "path_traversal"):         ["T1083"],                 # File and Directory Discovery
    ("HTTP", "command_injection"):      ["T1190", "T1059"],
    ("HTTP", "auth_attempt"):           ["T1110.003"],             # Password Spraying
    ("HTTP", "admin_panel_access"):     ["T1078"],
    ("HTTP", "webshell_upload"):        ["T1505.003"],             # Web Shell
    ("HTTP", "credential_harvesting"):  ["T1056.003"],             # Web Portal Capture
    ("HTTP", "scan"):                   ["T1595.002"],             # Vulnerability Scanning
    ("HTTP", "ssrf_attempt"):           ["T1090"],                 # Proxy
    ("HTTP", "xxe_attempt"):            ["T1190"],
    ("HTTP", "deserialization"):        ["T1190"],
    ("HTTPS", "sqli_attempt"):          ["T1190"],
    ("HTTPS", "auth_attempt"):          ["T1110.003"],
    ("HTTPS", "webshell_upload"):       ["T1505.003"],
    ("HTTPS", "scan"):                  ["T1595.002"],
    ("HTTPS", "admin_panel_access"):    ["T1078"],
    ("HTTPS", "credential_harvesting"): ["T1056.003"],

    # -------------------------------------------------------------------------
    # DNS
    # -------------------------------------------------------------------------
    ("DNS", "honeytoken_callback"):     ["T1071.004"],             # DNS C2
    ("DNS", "zone_transfer"):           ["T1590.002"],             # DNS lookup
    ("DNS", "subdomain_enum"):          ["T1595.001"],             # Active Scanning / Wordlist Scanning
    ("DNS", "dga_query"):               ["T1568.002"],             # Domain Generation Algorithms
    ("DNS", "covert_channel"):          ["T1071.004"],

    # -------------------------------------------------------------------------
    # RDP
    # -------------------------------------------------------------------------
    ("RDP", "auth_attempt"):            ["T1110", "T1110.001"],
    ("RDP", "auth_success"):            ["T1021.001"],             # Remote Desktop Protocol
    ("RDP", "screenshot"):              ["T1113"],                 # Screen Capture
    ("RDP", "credential_reuse"):        ["T1078"],
    ("RDP", "clipboard_access"):        ["T1115"],                 # Clipboard Data

    # -------------------------------------------------------------------------
    # SMB
    # -------------------------------------------------------------------------
    ("SMB", "ntlm_captured"):           ["T1187"],                 # Forced Authentication
    ("SMB", "auth_attempt"):            ["T1110"],
    ("SMB", "auth_success"):            ["T1021.002"],             # SMB / Windows Admin Shares
    ("SMB", "share_enum"):              ["T1135"],                 # Network Share Discovery
    ("SMB", "file_access"):             ["T1039"],                 # Data from Network Shared Drive
    ("SMB", "lateral_movement"):        ["T1570"],                 # Lateral Tool Transfer
    ("SMB", "pass_the_hash"):           ["T1550.002"],             # Pass the Hash
    ("SMB", "relay_attack"):            ["T1557.001"],             # LLMNR/NBT-NS Poisoning

    # -------------------------------------------------------------------------
    # FTP
    # -------------------------------------------------------------------------
    ("FTP", "auth_attempt"):            ["T1110"],
    ("FTP", "auth_success"):            ["T1078"],
    ("FTP", "file_upload"):             ["T1105"],
    ("FTP", "file_download"):           ["T1005"],                 # Data from Local System
    ("FTP", "anonymous_login"):         ["T1078.001"],             # Default Accounts

    # -------------------------------------------------------------------------
    # Telnet
    # -------------------------------------------------------------------------
    ("TELNET", "auth_attempt"):         ["T1110"],
    ("TELNET", "auth_success"):         ["T1078"],
    ("TELNET", "command_executed"):     ["T1059"],
    ("TELNET", "credential_reuse"):     ["T1078"],

    # -------------------------------------------------------------------------
    # Redis
    # -------------------------------------------------------------------------
    ("REDIS", "eval"):                  ["T1059"],                 # Command and Scripting Interpreter
    ("REDIS", "config_set"):            ["T1562.001"],             # Disable Security Tools
    ("REDIS", "slaveof"):               ["T1074"],                 # Data Staged
    ("REDIS", "auth_attempt"):          ["T1110"],
    ("REDIS", "data_exfil"):            ["T1041"],                 # Exfiltration Over C2 Channel
    ("REDIS", "scan"):                  ["T1046"],

    # -------------------------------------------------------------------------
    # MongoDB
    # -------------------------------------------------------------------------
    ("MONGODB", "auth_attempt"):        ["T1110"],
    ("MONGODB", "no_auth_access"):      ["T1078.001"],
    ("MONGODB", "data_dump"):           ["T1530"],                 # Data from Cloud Storage
    ("MONGODB", "js_injection"):        ["T1059"],

    # -------------------------------------------------------------------------
    # MySQL / PostgreSQL / MSSQL
    # -------------------------------------------------------------------------
    ("MYSQL", "auth_attempt"):          ["T1110"],
    ("MYSQL", "auth_success"):          ["T1078"],
    ("MYSQL", "sqli_attempt"):          ["T1190"],
    ("MYSQL", "outfile_write"):         ["T1505"],                 # Server Software Component
    ("MYSQL", "udf_exec"):              ["T1059"],
    ("POSTGRESQL", "auth_attempt"):     ["T1110"],
    ("POSTGRESQL", "auth_success"):     ["T1078"],
    ("POSTGRESQL", "copy_to"):          ["T1048"],                 # Exfiltration Over Alternative Protocol
    ("POSTGRESQL", "extension_load"):  ["T1059"],
    ("MSSQL", "auth_attempt"):          ["T1110"],
    ("MSSQL", "auth_success"):          ["T1078"],
    ("MSSQL", "xp_cmdshell"):           ["T1059.003"],             # Windows Command Shell
    ("MSSQL", "linked_server"):         ["T1021"],

    # -------------------------------------------------------------------------
    # Elasticsearch
    # -------------------------------------------------------------------------
    ("ELASTICSEARCH", "no_auth_access"): ["T1078.001"],
    ("ELASTICSEARCH", "data_dump"):      ["T1530"],
    ("ELASTICSEARCH", "index_delete"):   ["T1485"],                # Data Destruction
    ("ELASTICSEARCH", "ransomware"):     ["T1486"],                # Data Encrypted for Impact

    # -------------------------------------------------------------------------
    # AWS Metadata / Cloud
    # -------------------------------------------------------------------------
    ("AWS_METADATA", "iam_access"):     ["T1552.005"],             # Cloud Instance Metadata API
    ("AWS_METADATA", "credential_access"): ["T1552.005"],
    ("AWS_METADATA", "token_theft"):    ["T1528"],                 # Steal Application Access Token

    # -------------------------------------------------------------------------
    # Kubernetes API
    # -------------------------------------------------------------------------
    ("K8S_API", "auth_attempt"):        ["T1110"],
    ("K8S_API", "auth_success"):        ["T1078"],
    ("K8S_API", "pod_create"):          ["T1610"],                 # Deploy Container
    ("K8S_API", "secret_access"):       ["T1552.007"],             # Container API
    ("K8S_API", "exec_into_pod"):       ["T1609"],                 # Container Administration Command
    ("K8S_API", "cluster_scan"):        ["T1046"],

    # -------------------------------------------------------------------------
    # Docker API
    # -------------------------------------------------------------------------
    ("DOCKER_API", "container_create"): ["T1610"],
    ("DOCKER_API", "privileged_run"):   ["T1611"],                 # Escape to Host
    ("DOCKER_API", "host_mount"):       ["T1611"],
    ("DOCKER_API", "image_pull"):       ["T1105"],
    ("DOCKER_API", "no_auth_access"):   ["T1078.001"],

    # -------------------------------------------------------------------------
    # Memcached
    # -------------------------------------------------------------------------
    ("MEMCACHED", "no_auth_access"):    ["T1078.001"],
    ("MEMCACHED", "data_dump"):         ["T1005"],
    ("MEMCACHED", "amplification"):     ["T1498.002"],             # Reflection Amplification

    # -------------------------------------------------------------------------
    # LDAP
    # -------------------------------------------------------------------------
    ("LDAP", "auth_attempt"):           ["T1110"],
    ("LDAP", "enum"):                   ["T1087.002"],             # Domain Account Discovery
    ("LDAP", "password_spray"):         ["T1110.003"],
    ("LDAP", "kerberoasting"):          ["T1558.003"],             # Kerberoasting

    # -------------------------------------------------------------------------
    # VNC
    # -------------------------------------------------------------------------
    ("VNC", "auth_attempt"):            ["T1110"],
    ("VNC", "auth_success"):            ["T1021.005"],             # VNC
    ("VNC", "screenshot"):              ["T1113"],

    # -------------------------------------------------------------------------
    # SMTP
    # -------------------------------------------------------------------------
    ("SMTP", "auth_attempt"):           ["T1110"],
    ("SMTP", "open_relay"):             ["T1534"],                 # Internal Spearphishing (abuse)
    ("SMTP", "spam_relay"):             ["T1534"],

    # -------------------------------------------------------------------------
    # SNMP
    # -------------------------------------------------------------------------
    ("SNMP", "community_string"):       ["T1040"],                 # Network Sniffing
    ("SNMP", "walk"):                   ["T1590"],                 # Gather Victim Network Information
    ("SNMP", "write_attempt"):          ["T1565.002"],             # Transmitted Data Manipulation

    # -------------------------------------------------------------------------
    # SIP
    # -------------------------------------------------------------------------
    ("SIP", "auth_attempt"):            ["T1110"],
    ("SIP", "scan"):                    ["T1595.001"],
    ("SIP", "toll_fraud"):              ["T1496"],                 # Resource Hijacking
}


def get_techniques(protocol: str, event_type: str) -> list[str]:
    """Return MITRE technique IDs for a (protocol, event_type) pair."""
    return MITRE_MAPPING.get((protocol.upper(), event_type), [])


def get_all_technique_ids() -> list[str]:
    """Distinct technique IDs referenced across all mappings."""
    seen: set[str] = set()
    result = []
    for ids in MITRE_MAPPING.values():
        for tid in ids:
            if tid not in seen:
                seen.add(tid)
                result.append(tid)
    return sorted(result)
