use anyhow::Context;
use phantomgrid_db::{connect, migrate};
use phantomgrid_kafka::{consumer, parse_json, producer, publish_json};
use phantomgrid_types::{EnrichedEvent, RawEvent};
use rdkafka::consumer::Consumer;
use std::env;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let db = connect(&env::var("DATABASE_URL").context("DATABASE_URL missing")?).await?;
    migrate(&db).await?;

    let c = consumer("phantomgrid-event-processor", &brokers, &["events.raw"])?;
    let p = producer(&brokers)?;

    loop {
        let msg = c.recv().await?;
        let Ok(raw) = parse_json::<RawEvent>(&msg) else { continue; };

        let enriched = EnrichedEvent {
            raw: raw.clone(),
            country: Some("Unknown".into()),
            asn: None,
            rdns: None,
            threat_score: Some(if raw.severity.eq_ignore_ascii_case("high") { 80 } else { 40 }),
        };

        let _ = sqlx::query(
            "INSERT INTO events (id,tenant_id,decoy_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,event_type,severity,raw_data,enrichment,tags,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)"
        )
        .bind(raw.event_id)
        .bind(raw.tenant_id)
        .bind(raw.decoy_id)
        .bind(raw.session_id)
        .bind(raw.source_ip.parse::<std::net::IpAddr>().ok())
        .bind(raw.source_port as i32)
        .bind(raw.destination_ip.parse::<std::net::IpAddr>().ok())
        .bind(raw.destination_port as i32)
        .bind(raw.protocol)
        .bind(raw.decoy_type)
        .bind(raw.severity)
        .bind(raw.raw_data)
        .bind(serde_json::to_value(&enriched).unwrap_or_else(|_| serde_json::json!({})))
        .bind(raw.tags)
        .bind(raw.timestamp)
        .execute(&db)
        .await;

        let _ = publish_json(&p, "events.enriched", &enriched.raw.event_id.to_string(), &enriched).await;
    }
}
