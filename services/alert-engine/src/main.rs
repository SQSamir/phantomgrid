use chrono::Utc;
use phantomgrid_kafka::{consumer, parse_json, producer, publish_json};
use phantomgrid_types::EnrichedEvent;
use serde_json::json;
use std::env;
use uuid::Uuid;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let c = consumer("phantomgrid-alert-engine", &brokers, &["events.enriched"])?;
    let p = producer(&brokers)?;

    loop {
        let msg = c.recv().await?;
        let Ok(ev) = parse_json::<EnrichedEvent>(&msg) else { continue; };
        if ev.raw.severity.eq_ignore_ascii_case("high") || ev.threat_score.unwrap_or(0) >= 75 {
            let alert = json!({
                "id": Uuid::new_v4(),
                "tenant_id": ev.raw.tenant_id,
                "source_ip": ev.raw.source_ip,
                "severity": "high",
                "title": format!("{} interaction on {}", ev.raw.protocol, ev.raw.decoy_type),
                "summary": "Rule: simple high severity event",
                "created_at": Utc::now(),
                "event_id": ev.raw.event_id
            });
            let _ = publish_json(&p, "alerts.triggered", &ev.raw.event_id.to_string(), &alert).await;
        }
    }
}
