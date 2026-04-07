CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS timescaledb;

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

CREATE TABLE IF NOT EXISTS users (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
 email VARCHAR(255) UNIQUE NOT NULL,
 password_hash VARCHAR(255) NOT NULL,
 role VARCHAR(50) NOT NULL CHECK (role IN ('super_admin','tenant_admin','analyst','readonly')),
 mfa_secret VARCHAR(100),
 mfa_enabled BOOLEAN DEFAULT FALSE,
 display_name VARCHAR(255),
 avatar_url VARCHAR(500),
 last_login_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ DEFAULT NOW(),
 deactivated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS sessions (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 user_id UUID REFERENCES users(id) ON DELETE CASCADE,
 refresh_token_hash VARCHAR(255) NOT NULL,
 expires_at TIMESTAMPTZ NOT NULL,
 ip INET,
 user_agent TEXT,
 created_at TIMESTAMPTZ DEFAULT NOW(),
 revoked_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS api_keys (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
 user_id UUID REFERENCES users(id) ON DELETE CASCADE,
 name VARCHAR(255) NOT NULL,
 key_hash VARCHAR(255) NOT NULL,
 permissions TEXT[] DEFAULT ARRAY['read','write'],
 expires_at TIMESTAMPTZ,
 last_used_at TIMESTAMPTZ,
 created_at TIMESTAMPTZ DEFAULT NOW()
);

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

DO $$
BEGIN
 IF NOT EXISTS (SELECT 1 FROM timescaledb_information.hypertables WHERE hypertable_name='events') THEN
   PERFORM create_hypertable('events','created_at', if_not_exists => TRUE);
 END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_events_tenant_created ON events (tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_created ON events (source_ip, created_at DESC);
