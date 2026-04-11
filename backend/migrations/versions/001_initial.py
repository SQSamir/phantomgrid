from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Extensions
    op.execute('CREATE EXTENSION IF NOT EXISTS "pgcrypto"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    op.execute('CREATE EXTENSION IF NOT EXISTS "timescaledb" CASCADE')

    # -------------------------------------------------------------------------
    # tenants
    # -------------------------------------------------------------------------
    op.create_table(
        "tenants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("plan", sa.String(64), server_default="enterprise"),
        sa.Column("max_decoys", sa.Integer(), server_default="1000"),
        sa.Column("max_events_per_day", sa.Integer(), server_default="10000000"),
        sa.Column("mfa_required", sa.Boolean(), server_default="false"),
        sa.Column("config", postgresql.JSONB(), server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("suspended_at", sa.DateTime(timezone=True), nullable=True),
    )

    # -------------------------------------------------------------------------
    # users
    # -------------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("email", sa.String(255), nullable=False, unique=True),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(32), server_default="tenant_admin"),
        sa.Column("mfa_secret", sa.Text(), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), server_default="false"),
        sa.Column("mfa_backup_codes", postgresql.JSONB(), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("failed_login_attempts", sa.Integer(), server_default="0"),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("deactivated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_users_tenant_id", "users", ["tenant_id"])
    op.create_index("idx_users_email", "users", ["email"])

    # -------------------------------------------------------------------------
    # alert_rules
    # -------------------------------------------------------------------------
    op.create_table(
        "alert_rules",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("type", sa.String(32), nullable=False),
        sa.Column("config", postgresql.JSONB(), server_default="{}"),
        sa.Column("severity", sa.String(16), server_default="medium"),
        sa.Column("enabled", sa.Boolean(), server_default="true"),
        sa.Column("trigger_count", sa.Integer(), server_default="0"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("suppression_minutes", sa.Integer(), server_default="5"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_alert_rules_tenant_id", "alert_rules", ["tenant_id"])

    # -------------------------------------------------------------------------
    # alerts
    # -------------------------------------------------------------------------
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("rule_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alert_rules.id", ondelete="SET NULL"), nullable=True),
        sa.Column("severity", sa.String(16), server_default="medium"),
        sa.Column("status", sa.String(32), server_default="new"),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("summary", sa.String(1024), nullable=False),
        sa.Column("source_ip", sa.String(64), nullable=True),
        sa.Column("source_country", sa.String(64), nullable=True),
        sa.Column("source_asn", sa.String(128), nullable=True),
        sa.Column("mitre_technique_ids", postgresql.ARRAY(sa.String()), server_default="{}"),
        sa.Column("event_count", sa.Integer(), server_default="1"),
        sa.Column("first_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_alerts_tenant_id", "alerts", ["tenant_id"])
    op.create_index("idx_alerts_status", "alerts", ["status"])
    op.create_index("idx_alerts_severity", "alerts", ["severity"])
    op.create_index("idx_alerts_first_seen_at", "alerts", ["first_seen_at"])
    op.create_index("idx_alerts_rule_id", "alerts", ["rule_id"])

    # -------------------------------------------------------------------------
    # decoy_networks
    # -------------------------------------------------------------------------
    op.create_table(
        "decoy_networks",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("cidr", sa.String(64), nullable=False),
        sa.Column("vlan_id", sa.Integer(), nullable=True),
        sa.Column("environment_type", sa.String(64), server_default="corporate"),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_decoy_networks_tenant_id", "decoy_networks", ["tenant_id"])

    # -------------------------------------------------------------------------
    # decoy_templates
    # -------------------------------------------------------------------------
    op.create_table(
        "decoy_templates",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("description", sa.String(255), nullable=True),
        sa.Column("default_config", postgresql.JSONB(), server_default="{}"),
        sa.Column("tags", postgresql.ARRAY(sa.String()), server_default="{}"),
    )

    # -------------------------------------------------------------------------
    # decoys
    # -------------------------------------------------------------------------
    op.create_table(
        "decoys",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("network_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("decoy_networks.id", ondelete="SET NULL"), nullable=True),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),
        sa.Column("config", postgresql.JSONB(), server_default="{}"),
        sa.Column("status", sa.String(32), server_default="draft"),
        sa.Column("ip_address", sa.String(64), nullable=True),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("tags", postgresql.ARRAY(sa.String()), server_default="{}"),
        sa.Column("interaction_count", sa.Integer(), server_default="0"),
        sa.Column("last_interaction_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deployed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_decoys_tenant_id", "decoys", ["tenant_id"])
    op.create_index("idx_decoys_status", "decoys", ["status"])
    op.create_index("idx_decoys_network_id", "decoys", ["network_id"])
    op.execute("CREATE INDEX idx_decoys_config ON decoys USING GIN (config)")

    # -------------------------------------------------------------------------
    # integrations
    # -------------------------------------------------------------------------
    op.create_table(
        "integrations",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("type", sa.String(64), nullable=False),  # webhook, slack, pagerduty, email
        sa.Column("config", postgresql.JSONB(), server_default="{}"),
        sa.Column("enabled", sa.Boolean(), server_default="true"),
        sa.Column("last_triggered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("now()")),
    )
    op.create_index("idx_integrations_tenant_id", "integrations", ["tenant_id"])

    # -------------------------------------------------------------------------
    # events (TimescaleDB hypertable)
    # -------------------------------------------------------------------------
    op.create_table(
        "events",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text("gen_random_uuid()")),
        sa.Column("tenant_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("tenants.id", ondelete="CASCADE"), nullable=False),
        sa.Column("decoy_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("source_ip", postgresql.INET(), nullable=False),
        sa.Column("source_port", sa.Integer(), nullable=True),
        sa.Column("destination_ip", postgresql.INET(), nullable=True),
        sa.Column("destination_port", sa.Integer(), nullable=True),
        sa.Column("protocol", sa.String(32), nullable=False),
        sa.Column("event_type", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("raw_data", postgresql.JSONB(), server_default="{}"),
        sa.Column("enrichment", postgresql.JSONB(), server_default="{}"),
        sa.Column("mitre_technique_ids", postgresql.ARRAY(sa.String()), server_default="{}"),
        sa.Column("tags", postgresql.ARRAY(sa.String()), server_default="{}"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )
    op.create_index("idx_events_tenant_id", "events", ["tenant_id"])
    op.create_index("idx_events_decoy_id", "events", ["decoy_id"])
    op.create_index("idx_events_source_ip", "events", ["source_ip"])
    op.create_index("idx_events_protocol", "events", ["protocol"])
    op.create_index("idx_events_severity", "events", ["severity"])
    op.execute("CREATE INDEX idx_events_raw_data ON events USING GIN (raw_data)")
    op.execute("CREATE INDEX idx_events_enrichment ON events USING GIN (enrichment)")
    op.execute("CREATE INDEX idx_events_tags ON events USING GIN (tags)")
    op.execute("CREATE INDEX idx_events_mitre ON events USING GIN (mitre_technique_ids)")

    # Convert events to TimescaleDB hypertable (1-day chunks)
    op.execute("SELECT create_hypertable('events', 'created_at', chunk_time_interval => INTERVAL '1 day')")
    # Compress chunks older than 7 days
    op.execute("ALTER TABLE events SET (timescaledb.compress, timescaledb.compress_segmentby = 'tenant_id,protocol')")
    op.execute("SELECT add_compression_policy('events', INTERVAL '7 days')")
    # Retain 90 days by default
    op.execute("SELECT add_retention_policy('events', INTERVAL '90 days')")

    # -------------------------------------------------------------------------
    # Row-Level Security
    # -------------------------------------------------------------------------
    for table in ("events", "alerts", "alert_rules", "decoys", "decoy_networks", "integrations"):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"""
            CREATE POLICY tenant_isolation ON {table}
            USING (tenant_id = current_setting('app.current_tenant_id', true)::uuid)
        """)
        # Allow superuser/service role to bypass RLS
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")

    # -------------------------------------------------------------------------
    # Seed decoy templates
    # -------------------------------------------------------------------------
    op.execute("""
        INSERT INTO decoy_templates (name, type, description, default_config, tags) VALUES
        ('SSH Linux Server', 'ssh_honeypot', 'Ubuntu 22.04 OpenSSH server', '{"port":22,"banner":"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"}', '{"linux","ssh"}'),
        ('Windows SMB Share', 'smb_honeypot', 'Windows file share with NTLM capture', '{"port":445,"workgroup":"CORP"}', '{"windows","smb"}'),
        ('MySQL Database', 'mysql_honeypot', 'MySQL 8.0 database server', '{"port":3306,"version":"8.0.35"}', '{"database","mysql"}'),
        ('AWS EC2 Metadata', 'aws_metadata_honeypot', 'EC2 IMDS v1/v2 endpoint', '{"port":80,"role":"EC2InstanceRole-WebServer"}', '{"aws","cloud"}'),
        ('Docker API', 'docker_api_honeypot', 'Exposed Docker daemon API', '{"port":2375}', '{"docker","container"}'),
        ('Kubernetes API', 'k8s_api_honeypot', 'Kubernetes API server', '{"port":6443}', '{"kubernetes","container"}'),
        ('HTTP Web Server', 'http_honeypot', 'Apache2 Ubuntu default page', '{"port":80}', '{"http","web"}'),
        ('Redis Cache', 'redis_honeypot', 'Redis in-memory cache', '{"port":6379}', '{"redis","cache"}'),
        ('PostgreSQL Database', 'postgresql_honeypot', 'PostgreSQL 16 database', '{"port":5432}', '{"database","postgresql"}'),
        ('FTP Server', 'ftp_honeypot', 'ProFTPD server', '{"port":21}', '{"ftp","file"}'),
        ('SMTP Mail Server', 'smtp_honeypot', 'Postfix mail server', '{"port":25}', '{"smtp","mail"}'),
        ('Telnet Device', 'telnet_honeypot', 'BusyBox IoT device', '{"port":23}', '{"iot","telnet"}'),
        ('VNC Server', 'vnc_honeypot', 'VNC remote desktop', '{"port":5900}', '{"vnc","remote"}'),
        ('SNMP Agent', 'snmp_honeypot', 'SNMP network device', '{"port":161}', '{"snmp","network"}'),
        ('DNS Server', 'dns_honeypot', 'DNS resolver', '{"port":53}', '{"dns","network"}')
    """)


def downgrade() -> None:
    for table in ("events", "alerts", "alert_rules", "decoys", "decoy_networks", "integrations"):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation ON {table}")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY")

    op.drop_table("events")
    op.drop_table("integrations")
    op.drop_table("decoys")
    op.drop_table("decoy_templates")
    op.drop_table("decoy_networks")
    op.drop_table("alerts")
    op.drop_table("alert_rules")
    op.drop_table("users")
    op.drop_table("tenants")
