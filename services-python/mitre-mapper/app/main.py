from fastapi import FastAPI

app = FastAPI(title="phantomgrid-mitre-mapper")

MAP = {
    "ssh_bruteforce": {"technique_id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "ssh_success_after_fail": {"technique_id": "T1021.004", "name": "Remote Services: SSH", "tactic": "Lateral Movement"},
    "dns_callback": {"technique_id": "T1071.004", "name": "Application Layer Protocol: DNS", "tactic": "Command and Control"},
}

@app.get('/health')
def health():
    return {"status": "ok", "service": "mitre-mapper"}

@app.get('/api/v1/mitre/map')
def map_event(key: str):
    return MAP.get(key, {"technique_id": "T1595", "name": "Active Scanning", "tactic": "Reconnaissance"})
