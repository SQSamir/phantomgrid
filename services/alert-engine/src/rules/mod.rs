pub mod correlation;
pub mod simple;
pub mod threshold;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct RuleRecord {
    pub id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    pub name: String,
    pub rule_type: String,
    pub config: serde_json::Value,
    pub severity: String,
    pub suppression_minutes: i32,
}
