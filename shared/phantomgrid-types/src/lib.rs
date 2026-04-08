#![deny(warnings)]
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub tenant_id: Uuid,
    pub decoy_id: Uuid,
    pub decoy_type: String,
    pub source_ip: String,
    pub source_port: u16,
    pub destination_ip: String,
    pub destination_port: u16,
    pub protocol: String,
    pub session_id: Uuid,
    pub raw_data: serde_json::Value,
    pub severity: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEvent {
    #[serde(flatten)]
    pub raw: RawEvent,
    pub country: Option<String>,
    pub asn: Option<String>,
    pub rdns: Option<String>,
    pub threat_score: Option<i32>,
}

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

#[cfg(test)]
mod tests;
