#![deny(warnings)]

pub mod metrics;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRole {
    SuperAdmin,
    TenantAdmin,
    Analyst,
    Readonly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    pub sub: Uuid,
    pub tenant_id: Uuid,
    pub role: UserRole,
    pub exp: usize,
    pub iat: usize,
    pub jti: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterRequest {
    pub tenant_id: Uuid,
    pub email: String,
    pub password: String,
    pub role: UserRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub service: &'static str,
    pub timestamp: DateTime<Utc>,
}

pub mod event {
    use super::{Protocol, Severity};
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct RawEvent {
        pub event_id: Uuid,
        pub timestamp: DateTime<Utc>,
        pub tenant_id: Uuid,
        pub decoy_id: Option<Uuid>,
        pub session_id: Option<Uuid>,
        pub source_ip: String,
        pub source_port: Option<u16>,
        pub destination_ip: Option<String>,
        pub destination_port: Option<u16>,
        pub protocol: Protocol,
        pub event_type: String,
        pub severity: Severity,
        pub raw_data: serde_json::Value,
        pub tags: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EnrichedEvent {
        #[serde(flatten)]
        pub raw: RawEvent,
        pub enrichment: Enrichment,
        pub mitre_technique_ids: Vec<String>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, Default)]
    pub struct Enrichment {
        pub country: Option<String>,
        pub city: Option<String>,
        pub asn: Option<String>,
        pub isp: Option<String>,
        pub lat: Option<f64>,
        pub lon: Option<f64>,
        pub is_tor: bool,
        pub is_vpn: bool,
        pub abuse_score: Option<u8>,
    }
}

pub mod alert {
    use super::Severity;
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Alert {
        pub id: Uuid,
        pub tenant_id: Uuid,
        pub rule_id: Option<Uuid>,
        pub severity: Severity,
        pub title: String,
        pub summary: Option<String>,
        pub source_ip: String,
        pub mitre_technique_ids: Vec<String>,
        pub event_count: u32,
        pub first_seen_at: DateTime<Utc>,
        pub last_seen_at: DateTime<Utc>,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Protocol {
    Ssh,
    Http,
    Https,
    Telnet,
    Ftp,
    Rdp,
    Smb,
    Ldap,
    Dns,
    Vnc,
    Mysql,
    Postgresql,
    Redis,
    Mongodb,
    Elasticsearch,
    Mssql,
    K8sApi,
    AwsMetadata,
    Unknown(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

pub use event::{EnrichedEvent, Enrichment, RawEvent};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Decoy {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub network_id: Option<Uuid>,
    pub name: String,
    pub decoy_type: String,
    pub config: serde_json::Value,
    pub status: String,
    pub ip_address: Option<String>,
    pub port: Option<i32>,
    pub tags: Vec<String>,
}

pub mod kafka_topics {
    pub const EVENTS_RAW: &str = "events.raw";
    pub const EVENTS_ENRICHED: &str = "events.enriched";
    pub const ALERTS_TRIGGERED: &str = "alerts.triggered";
    pub const DECOY_COMMANDS: &str = "decoy.commands";
    pub const NOTIFICATIONS_PENDING: &str = "notifications.pending";
}

#[cfg(test)]
mod tests;
