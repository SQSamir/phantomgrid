-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  plan VARCHAR(50) DEFAULT 'enterprise',
  max_decoys INTEGER DEFAULT 1000,
  max_events_per_day BIGINT DEFAULT 10000000,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  suspended_at TIMESTAMPTZ,
  config JSONB DEFAULT '{}'
);

-- Default tenant (for single-tenant deployments)
INSERT INTO tenants (id, name)
VALUES ('00000000-0000-0000-0000-000000000001', 'Default')
ON CONFLICT DO NOTHING;

-- Users
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'analyst' CHECK (role IN ('super_admin','tenant_admin','analyst','readonly')),
  mfa_secret VARCHAR(100),
  mfa_enabled BOOLEAN DEFAULT FALSE,
  display_name VARCHAR(255),
  failed_login_attempts INTEGER DEFAULT 0,
  locked_until TIMESTAMPTZ,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  deactivated_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_users_tenant ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Sessions (refresh tokens)
CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  refresh_token_hash VARCHAR(255) NOT NULL UNIQUE,
  ip_address INET,
  user_agent TEXT,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- API Keys
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  key_hash VARCHAR(255) NOT NULL UNIQUE,
  permissions TEXT[] DEFAULT ARRAY['read','write'],
  last_used_at TIMESTAMPTZ,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Decoy Networks
CREATE TABLE IF NOT EXISTS decoy_networks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  cidr VARCHAR(50),
  vlan_id INTEGER,
  environment_type VARCHAR(100) DEFAULT 'corporate',
  description TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_networks_tenant ON decoy_networks(tenant_id);

-- Decoys
CREATE TABLE IF NOT EXISTS decoys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  network_id UUID REFERENCES decoy_networks(id),
  name VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,
  config JSONB NOT NULL DEFAULT '{}',
  status VARCHAR(50) DEFAULT 'draft' CHECK (status IN ('draft','deploying','active','paused','error','destroyed')),
  ip_address INET,
  port INTEGER,
  tags TEXT[] DEFAULT ARRAY[]::TEXT[],
  interaction_count BIGINT DEFAULT 0,
  last_interaction_at TIMESTAMPTZ,
  deployed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_decoys_tenant ON decoys(tenant_id);
CREATE INDEX IF NOT EXISTS idx_decoys_status ON decoys(status);
CREATE INDEX IF NOT EXISTS idx_decoys_network ON decoys(network_id);
CREATE INDEX IF NOT EXISTS idx_decoys_config ON decoys USING GIN(config);

-- Decoy Templates
CREATE TABLE IF NOT EXISTS decoy_templates (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  type VARCHAR(100) NOT NULL,
  description TEXT,
  default_config JSONB NOT NULL DEFAULT '{}',
  tags TEXT[] DEFAULT ARRAY[]::TEXT[],
  built_in BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert built-in templates
INSERT INTO decoy_templates (name, type, description, default_config, tags, built_in) VALUES
('Ubuntu 22.04 SSH Server', 'ssh_honeypot', 'Realistic SSH server mimicking Ubuntu 22.04', '{"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6","fake_hostname":"web-prod-01","motd":"Ubuntu 22.04.3 LTS Welcome to Ubuntu! ","os_fingerprint":"ubuntu_22","log_keystrokes":true}', ARRAY['linux','ssh','ubuntu'], TRUE),
('Windows Server 2022 RDP', 'rdp_honeypot', 'Fake RDP endpoint mimicking Windows Server 2022', '{"os":"Windows Server 2022","domain":"CORP","fake_hostname":"DC01"}', ARRAY['windows','rdp','active-directory'], TRUE),
('Apache Web Server', 'http_honeypot', 'Apache 2.4 default page with login trap', '{"server_header":"Apache/2.4.54 (Ubuntu)","template":"apache_default","capture_forms":true}', ARRAY['http','apache','web'], TRUE),
('WordPress Login', 'http_honeypot', 'Fake WordPress admin login page', '{"server_header":"Apache/2.4.54","template":"wordpress","wp_version":"6.4.2","capture_forms":true}', ARRAY['http','wordpress','cms'], TRUE),
('Redis 7 Server', 'redis_honeypot', 'Fake Redis instance for detecting lateral movement', '{"version":"7.0.11","log_all_commands":true}', ARRAY['redis','database','cache'], TRUE),
('MySQL 8 Database', 'mysql_honeypot', 'Fake MySQL server with decoy schema', '{"version":"8.0.35","fake_databases":["customers","orders","users","finance"]}', ARRAY['mysql','database'], TRUE),
('PostgreSQL 16', 'postgresql_honeypot', 'Fake PostgreSQL instance', '{"version":"16.1","fake_databases":["app_db","analytics","reporting"]}', ARRAY['postgresql','database'], TRUE),
('FTP File Server', 'ftp_honeypot', 'Fake FTP with enticing fake files', '{"banner":"220 ProFTPD 1.3.8 Server","fake_files":["backup_2024.tar.gz","passwords.txt","config.zip","db_dump.sql"]}', ARRAY['ftp','file-transfer'], TRUE),
('LDAP Directory', 'ldap_honeypot', 'Fake LDAP/AD directory with fake user objects', '{"domain":"corp.local","dc":"DC=corp,DC=local","fake_user_count":150}', ARRAY['ldap','active-directory','identity'], TRUE),
('SMB File Share', 'smb_honeypot', 'Fake Windows SMB share for NTLM hash capture', '{"shares":["ADMIN$","C$","Finance","HR","IT_Backups"],"capture_hashes":true}', ARRAY['smb','windows','lateral-movement'], TRUE),
('DNS Resolver', 'dns_honeypot', 'DNS honeypot for callback/beacon detection', '{"listen_udp":true,"listen_tcp":true,"callback_domain":"beacon.internal"}', ARRAY['dns','callback','honeytoken'], TRUE),
('Elasticsearch Node', 'elasticsearch_honeypot', 'Fake Elasticsearch with decoy indices', '{"version":"8.11.0","fake_indices":["users","logs","transactions","credentials"]}', ARRAY['elasticsearch','database','nosql'], TRUE),
('MongoDB Instance', 'mongodb_honeypot', 'Fake MongoDB with decoy collections', '{"version":"7.0.4","fake_dbs":["admin","users","analytics"]}', ARRAY['mongodb','database','nosql'], TRUE),
('Kubernetes API Server', 'kubernetes_api_honeypot', 'Fake K8s API endpoint', '{"k8s_version":"1.28.4","fake_namespaces":["default","production","kube-system"]}', ARRAY['kubernetes','cloud','container'], TRUE),
('AWS EC2 Metadata', 'aws_metadata_honeypot', 'Fake AWS metadata endpoint (169.254.169.254)', '{"account_id":"123456789012","region":"us-east-1","fake_role":"EC2InstanceRole","fake_access_key":"AKIAIOSFODNN7EXAMPLE"}', ARRAY['aws','cloud','metadata','imds'], TRUE),
('VNC Desktop', 'vnc_honeypot', 'Fake VNC server', '{"version":"RFB 003.008","fake_os":"Windows 10","resolution":"1920x1080"}', ARRAY['vnc','remote-desktop'], TRUE),
('Telnet Console', 'telnet_honeypot', 'Fake Telnet for IoT/legacy device detection', '{"banner":"BusyBox v1.35.0 (2023-01-01) built-in shell","fake_device":"router"}', ARRAY['telnet','iot','legacy'], TRUE),
('MSSQL Server', 'mssql_honeypot', 'Fake Microsoft SQL Server', '{"version":"Microsoft SQL Server 2019","fake_databases":["master","HR_DB","Finance_DB"]}', ARRAY['mssql','database','windows'], TRUE),
('Honey Document (PDF)', 'fake_file', 'PDF with embedded DNS callback beacon', '{"file_type":"pdf","template":"financial_report","beacon_type":"dns","embed_tracking":true}', ARRAY['honeyfile','pdf','beacon'], TRUE),
('AWS API Key Honeytoken', 'fake_api_key', 'Fake AWS access key monitored via CloudTrail-style DNS', '{"key_prefix":"AKIA","monitored_via":"dns_beacon","cloud_provider":"aws"}', ARRAY['honeytoken','aws','credential'], TRUE)
ON CONFLICT DO NOTHING;

-- Sensors
CREATE TABLE IF NOT EXISTS sensors (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  token_hash VARCHAR(255) NOT NULL UNIQUE,
  os VARCHAR(100),
  arch VARCHAR(50),
  version VARCHAR(50),
  status VARCHAR(50) DEFAULT 'offline' CHECK (status IN ('online','offline','error')),
  last_heartbeat_at TIMESTAMPTZ,
  ip_address INET,
  hostname VARCHAR(255),
  metadata JSONB DEFAULT '{}',
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alert Rules
CREATE TABLE IF NOT EXISTS alert_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  name VARCHAR(255) NOT NULL,
  description TEXT,
  type VARCHAR(50) NOT NULL CHECK (type IN ('simple','threshold','sequence','correlation')),
  config JSONB NOT NULL DEFAULT '{}',
  severity VARCHAR(20) NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  enabled BOOLEAN DEFAULT TRUE,
  trigger_count BIGINT DEFAULT 0,
  last_triggered_at TIMESTAMPTZ,
  notification_channel_ids UUID[] DEFAULT ARRAY[]::UUID[],
  suppression_minutes INTEGER DEFAULT 5,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Insert default built-in alert rules
INSERT INTO alert_rules (tenant_id, name, type, config, severity, enabled) VALUES
('00000000-0000-0000-0000-000000000001', 'Any SSH Interaction', 'simple', '{"match":{"protocol":"SSH"}}', 'high', TRUE),
('00000000-0000-0000-0000-000000000001', 'SSH Brute Force', 'threshold', '{"protocol":"SSH","threshold":5,"window_seconds":60,"group_by":"source_ip"}', 'critical', TRUE),
('00000000-0000-0000-0000-000000000001', 'Any RDP Interaction', 'simple', '{"match":{"protocol":"RDP"}}', 'high', TRUE),
('00000000-0000-0000-0000-000000000001', 'Multi-Decoy Attacker', 'correlation', '{"min_decoys":3,"window_seconds":300,"group_by":"source_ip"}', 'critical', TRUE),
('00000000-0000-0000-0000-000000000001', 'SMB Hash Capture', 'simple', '{"match":{"protocol":"SMB","event_type":"ntlm_hash_captured"}}', 'critical', TRUE),
('00000000-0000-0000-0000-000000000001', 'DNS Honeytoken Callback', 'simple', '{"match":{"protocol":"DNS","event_type":"honeytoken_callback"}}', 'critical', TRUE),
('00000000-0000-0000-0000-000000000001', 'Kubernetes API Probe', 'simple', '{"match":{"protocol":"K8S_API"}}', 'high', TRUE),
('00000000-0000-0000-0000-000000000001', 'AWS Metadata Access', 'simple', '{"match":{"protocol":"AWS_METADATA"}}', 'critical', TRUE)
ON CONFLICT DO NOTHING;

-- Alerts
CREATE TABLE IF NOT EXISTS alerts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  rule_id UUID REFERENCES alert_rules(id),
  decoy_ids UUID[] DEFAULT ARRAY[]::UUID[],
  severity VARCHAR(20) NOT NULL,
  status VARCHAR(50) DEFAULT 'new' CHECK (status IN ('new','investigating','resolved','suppressed')),
  title VARCHAR(500) NOT NULL,
  summary TEXT,
  source_ip INET,
  source_country VARCHAR(100),
  source_asn VARCHAR(200),
  source_city VARCHAR(200),
  source_lat DOUBLE PRECISION,
  source_lon DOUBLE PRECISION,
  is_tor BOOLEAN DEFAULT FALSE,
  is_vpn BOOLEAN DEFAULT FALSE,
  mitre_technique_ids TEXT[] DEFAULT ARRAY[]::TEXT[],
  event_count INTEGER DEFAULT 1,
  analyst_notes TEXT,
  assigned_to UUID REFERENCES users(id),
  first_seen_at TIMESTAMPTZ DEFAULT NOW(),
  last_seen_at TIMESTAMPTZ DEFAULT NOW(),
  resolved_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_alerts_tenant ON alerts(tenant_id);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_source_ip ON alerts(source_ip);
CREATE INDEX IF NOT EXISTS idx_alerts_first_seen ON alerts(first_seen_at DESC);

-- Events (TimescaleDB hypertable)
CREATE TABLE IF NOT EXISTS events (
  id UUID NOT NULL DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL,
  decoy_id UUID,
  alert_id UUID,
  session_id UUID,
  source_ip INET,
  source_port INTEGER,
  destination_ip INET,
  destination_port INTEGER,
  protocol VARCHAR(50),
  event_type VARCHAR(100),
  severity VARCHAR(20) DEFAULT 'medium',
  raw_data JSONB NOT NULL DEFAULT '{}',
  enrichment JSONB DEFAULT '{}',
  mitre_technique_ids TEXT[] DEFAULT ARRAY[]::TEXT[],
  tags TEXT[] DEFAULT ARRAY[]::TEXT[],
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
SELECT create_hypertable('events', 'created_at', if_not_exists => TRUE);
SELECT add_retention_policy('events', INTERVAL '90 days', if_not_exists => TRUE);
CREATE INDEX IF NOT EXISTS idx_events_tenant_time ON events(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_ip ON events(source_ip, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_decoy ON events(decoy_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_protocol ON events(protocol, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_raw_data ON events USING GIN(raw_data);

-- Integrations
CREATE TABLE IF NOT EXISTS integrations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  type VARCHAR(100) NOT NULL,
  name VARCHAR(255) NOT NULL,
  config JSONB NOT NULL DEFAULT '{}',
  enabled BOOLEAN DEFAULT TRUE,
  last_used_at TIMESTAMPTZ,
  test_status VARCHAR(50),
  last_test_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Audit Log (append-only — never UPDATE or DELETE)
CREATE TABLE IF NOT EXISTS audit_log (
  id BIGSERIAL PRIMARY KEY,
  tenant_id UUID,
  user_id UUID,
  action VARCHAR(255) NOT NULL,
  resource_type VARCHAR(100),
  resource_id UUID,
  details JSONB DEFAULT '{}',
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_tenant ON audit_log(tenant_id, created_at DESC);
