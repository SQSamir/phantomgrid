use axum::{routing::get, Json, Router};
use chrono::{Duration, Utc};
use phantomgrid_db::{connect, migrate};
use phantomgrid_kafka::{consumer, parse_json, producer, publish_json};
use phantomgrid_types::EnrichedEvent;
use serde_json::json;
use sqlx::PgPool;
use std::env;
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let db = connect(&env::var("DATABASE_URL")?).await?;
    migrate(&db).await?;

    let app = Router::new().route("/health", get(|| async { Json(json!({"status":"ok","service":"alert-engine"})) }));
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:8083").await.expect("bind alert-engine");
        axum::serve(listener, app).await.expect("serve alert-engine");
    });

    run_loop(db, &brokers).await
}

async fn run_loop(db: PgPool, brokers: &str) -> anyhow::Result<()> {
    let c = consumer("phantomgrid-alert-engine", brokers, &["events.enriched"])?;
    let p = producer(brokers)?;

    loop {
        let msg = c.recv().await?;
        let Ok(ev) = parse_json::<EnrichedEvent>(&msg) else { continue; };

        // Rule 1: simple high severity event
        let simple_hit = ev.raw.severity.eq_ignore_ascii_case("high") || ev.threat_score.unwrap_or(0) >= 75;

        // Rule 2: threshold - 10 events from same IP in 60s
        let threshold_count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM events WHERE tenant_id=$1 AND source_ip=$2::inet AND created_at > NOW() - INTERVAL '60 seconds'"
        )
        .bind(ev.raw.tenant_id)
        .bind(&ev.raw.source_ip)
        .fetch_one(&db)
        .await
        .unwrap_or(0);
        let threshold_hit = threshold_count >= 10;

        if !(simple_hit || threshold_hit) {
            continue;
        }

        let severity = if threshold_hit { "critical" } else { "high" };
        let rule_name = if threshold_hit { "threshold_10_in_60s" } else { "simple_high_event" };

        let alert_id = Uuid::new_v4();
        let title = if threshold_hit {
            format!("Brute-force pattern from {}", ev.raw.source_ip)
        } else {
            format!("{} interaction on {}", ev.raw.protocol, ev.raw.decoy_type)
        };

        let _ = sqlx::query(
            "INSERT INTO alerts (id,tenant_id,severity,title,summary,source_ip,mitre_technique_ids,event_count,first_seen_at,last_seen_at) VALUES ($1,$2,$3,$4,$5,$6::inet,$7,$8,NOW(),NOW())"
        )
        .bind(alert_id)
        .bind(ev.raw.tenant_id)
        .bind(severity)
        .bind(&title)
        .bind(format!("Rule: {}", rule_name))
        .bind(&ev.raw.source_ip)
        .bind(Vec::<String>::new())
        .bind(if threshold_hit { threshold_count as i32 } else { 1 })
        .execute(&db)
        .await;

        let alert = json!({
            "id": alert_id,
            "tenant_id": ev.raw.tenant_id,
            "source_ip": ev.raw.source_ip,
            "severity": severity,
            "title": title,
            "summary": format!("Rule fired: {}", rule_name),
            "created_at": Utc::now(),
            "event_id": ev.raw.event_id,
            "window_seconds": 60,
            "count": threshold_count.max(1),
            "suppression_until": (Utc::now() + Duration::minutes(5))
        });

        let _ = publish_json(&p, "alerts.triggered", &ev.raw.event_id.to_string(), &alert).await;
    }
}
