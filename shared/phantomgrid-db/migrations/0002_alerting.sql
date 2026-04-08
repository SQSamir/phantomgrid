CREATE TABLE IF NOT EXISTS alert_rules (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
 name VARCHAR(255) NOT NULL,
 description TEXT,
 type VARCHAR(50) NOT NULL CHECK (type IN ('simple','threshold','sequence','correlation')),
 config JSONB NOT NULL,
 severity VARCHAR(20) NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
 enabled BOOLEAN DEFAULT TRUE,
 trigger_count BIGINT DEFAULT 0,
 last_triggered_at TIMESTAMPTZ,
 notification_channels JSONB DEFAULT '[]',
 suppression_minutes INTEGER DEFAULT 5,
 created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
 id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
 tenant_id UUID REFERENCES tenants(id) ON DELETE CASCADE,
 rule_id UUID REFERENCES alert_rules(id),
 decoy_ids UUID[] DEFAULT ARRAY[]::UUID[],
 severity VARCHAR(20) NOT NULL,
 status VARCHAR(50) DEFAULT 'new' CHECK (status IN ('new','investigating','resolved','suppressed')),
 title VARCHAR(500) NOT NULL,
 summary TEXT,
 source_ip INET,
 source_country VARCHAR(100),
 source_asn VARCHAR(200),
 mitre_technique_ids TEXT[] DEFAULT ARRAY[]::TEXT[],
 event_count INTEGER DEFAULT 1,
 analyst_notes TEXT,
 assigned_to UUID REFERENCES users(id),
 first_seen_at TIMESTAMPTZ DEFAULT NOW(),
 last_seen_at TIMESTAMPTZ DEFAULT NOW(),
 resolved_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_alerts_tenant_seen ON alerts (tenant_id, last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_alerts_source ON alerts (source_ip, last_seen_at DESC);
