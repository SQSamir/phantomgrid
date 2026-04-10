MITRE_MAPPING = {
    ("SSH", "auth_attempt"): ["T1110.001"],
    ("SSH", "command_executed"): ["T1059.004"],
    ("HTTP", "sqli_attempt"): ["T1190"],
    ("DNS", "honeytoken_callback"): ["T1071.004"],
    ("AWS_METADATA", "iam_access"): ["T1552.005"],
    ("REDIS", "eval"): ["T1059"],
    ("SMB", "ntlm_captured"): ["T1187"],
}

def get_techniques(protocol: str, event_type: str) -> list[str]:
    return MITRE_MAPPING.get((protocol.upper(), event_type), [])
