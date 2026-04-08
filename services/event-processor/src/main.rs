use anyhow::Context;
use phantomgrid_db::{connect, migrate};
use phantomgrid_kafka::{consumer, parse_json, producer, publish_json};
use phantomgrid_types::{EnrichedEvent, RawEvent};
use rdkafka::consumer::Consumer;
use redis::AsyncCommands;
use sqlx::PgPool;
use std::{env, net::IpAddr, str::FromStr};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let db = connect(&env::var("DATABASE_URL").context("DATABASE_URL missing")?).await?;
    migrate(&db).await?;

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".into());
    let rcli = redis::Client::open(redis_url)?;

    let c = consumer("phantomgrid-event-processor", &brokers, &["events.raw"])?;
    let p = producer(&brokers)?;

    loop {
        let msg = c.recv().await?;
        let Ok(raw) = parse_json::<RawEvent>(&msg) else {
            continue;
        };

        if is_duplicate(&rcli, &raw).await.unwrap_or(false) {
            continue;
        }

        let (country, asn, rdns) = enrich_ip(&raw.source_ip).await;
        let threat_score = score_event(&raw, country.as_deref(), asn.as_deref());

        let enriched = EnrichedEvent {
            raw: raw.clone(),
            country,
            asn,
            rdns,
            threat_score: Some(threat_score),
        };

        persist_event(&db, &raw, &enriched).await;
        let _ = publish_json(&p, "events.enriched", &enriched.raw.event_id.to_string(), &enriched).await;
    }
}

async fn is_duplicate(redis_client: &redis::Client, raw: &RawEvent) -> anyhow::Result<bool> {
    let mut con = redis_client.get_multiplexed_tokio_connection().await?;
    let key = format!(
        "pg:dedup:{}:{}:{}:{}",
        raw.tenant_id, raw.source_ip, raw.decoy_id, raw.protocol
    );
    let exists: bool = con.exists(&key).await?;
    if exists {
        return Ok(true);
    }
    let _: () = con.set_ex(&key, raw.event_id.to_string(), 15).await?;
    Ok(false)
}

async fn enrich_ip(ip: &str) -> (Option<String>, Option<String>, Option<String>) {
    if IpAddr::from_str(ip).map(|v| v.is_private()).unwrap_or(true) {
        return (Some("Private".into()), Some("N/A".into()), None);
    }

    let rdns = tokio::net::lookup_host((ip, 0))
        .await
        .ok()
        .and_then(|mut it| it.next())
        .map(|sa| sa.ip().to_string());

    // lightweight placeholder enrichment hook; can be replaced with MaxMind/API providers
    let country = Some("Unknown".into());
    let asn = Some("AS-UNKNOWN".into());

    (country, asn, rdns)
}

fn score_event(raw: &RawEvent, country: Option<&str>, asn: Option<&str>) -> i32 {
    let mut score = if raw.severity.eq_ignore_ascii_case("high") { 75 } else { 40 };
    let proto = raw.protocol.to_ascii_uppercase();
    if proto == "SSH" || proto == "TELNET" {
        score += 10;
    }
    if raw.tags.iter().any(|t| t.contains("credential") || t.contains("brute")) {
        score += 10;
    }
    if country == Some("Private") {
        score -= 15;
    }
    if asn == Some("AS-UNKNOWN") {
        score += 5;
    }
    score.clamp(0, 100)
}

async fn persist_event(db: &PgPool, raw: &RawEvent, enriched: &EnrichedEvent) {
    let _ = sqlx::query(
        "INSERT INTO events (id,tenant_id,decoy_id,session_id,source_ip,source_port,destination_ip,destination_port,protocol,event_type,severity,raw_data,enrichment,tags,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)",
    )
    .bind(raw.event_id)
    .bind(raw.tenant_id)
    .bind(raw.decoy_id)
    .bind(raw.session_id)
    .bind(raw.source_ip.parse::<IpAddr>().ok())
    .bind(raw.source_port as i32)
    .bind(raw.destination_ip.parse::<IpAddr>().ok())
    .bind(raw.destination_port as i32)
    .bind(&raw.protocol)
    .bind(&raw.decoy_type)
    .bind(&raw.severity)
    .bind(&raw.raw_data)
    .bind(serde_json::to_value(enriched).unwrap_or_else(|_| serde_json::json!({})))
    .bind(&raw.tags)
    .bind(raw.timestamp)
    .execute(db)
    .await;
}
