use axum::{routing::get, Json, Router};
use chrono::{Duration, Utc};
use phantomgrid_db::{connect, migrate};
use phantomgrid_kafka::{consumer, parse_json, producer, publish_json};
use phantomgrid_types::event::EnrichedEvent;
use serde_json::json;
use sqlx::PgPool;
use std::{env, sync::Arc};
use tokio::sync::RwLock;
use uuid::Uuid;

mod rules;

#[cfg(test)]
mod tests;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let db = connect(&env::var("DATABASE_URL")?).await?;
    migrate(&db).await?;

    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://redis:6379".into());
    let redis_client = redis::Client::open(redis_url)?;

    let app = Router::new()
        .route("/health", get(|| async { Json(json!({"status":"ok","service":"alert-engine"})) }))
        .route("/metrics", get(|| async { "# TYPE service_up gauge\nservice_up{service=\"alert-engine\"} 1\n" }));
    tokio::spawn(async move {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:8083").await.expect("bind alert-engine");
        axum::serve(listener, app).await.expect("serve alert-engine");
    });

    run_loop(db, redis_client, &brokers).await
}

async fn run_loop(db: PgPool, redis_client: redis::Client, brokers: &str) -> anyhow::Result<()> {
    let c = consumer("phantomgrid-alert-engine", brokers, &["events.enriched"])?;
    let p = producer(brokers)?;

    let rules_cache = Arc::new(RwLock::new(load_rules(&db).await));

    {
        let db = db.clone();
        let rules_cache = rules_cache.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                let refreshed = load_rules(&db).await;
                let mut w = rules_cache.write().await;
                *w = refreshed;
            }
        });
    }

    loop {
        let msg = c.recv().await?;
        let Ok(ev) = parse_json::<EnrichedEvent>(&msg) else { continue; };

        let rule_list = { rules_cache.read().await.clone() };
        for rule in rule_list {
            if rule.tenant_id != ev.raw.tenant_id {
                continue;
            }

            let matched = match rule.rule_type.as_str() {
                "simple" => rules::simple::matches(&ev, &rule.config),
                "threshold" => rules::threshold::matches(&redis_client, rule.id, &ev, &rule.config).await,
                "correlation" => rules::correlation::matches(&redis_client, &ev, &rule.config).await,
                _ => false,
            };

            if !matched {
                continue;
            }

            let suppression_key = format!("suppress:{}:{}", rule.id, ev.raw.source_ip);
            let mut con = match redis_client.get_multiplexed_async_connection().await {
                Ok(v) => v,
                Err(_) => continue,
            };

            let suppress_exists = redis::cmd("EXISTS")
                .arg(&suppression_key)
                .query_async::<_, i64>(&mut con)
                .await
                .unwrap_or(0)
                > 0;

            if suppress_exists {
                continue;
            }

            let alert_id = Uuid::new_v4();
            let title = format!("{} triggered", rule.name);
            let summary = format!("Rule {} matched for source {}", rule.name, ev.raw.source_ip);

            let _ = sqlx::query(
                "INSERT INTO alerts (id, tenant_id, rule_id, severity, status, title, summary, source_ip, mitre_technique_ids, event_count, first_seen_at, last_seen_at)
                 VALUES ($1, $2, $3, $4, 'new', $5, $6, $7::inet, $8, $9, NOW(), NOW())"
            )
            .bind(alert_id)
            .bind(ev.raw.tenant_id)
            .bind(rule.id)
            .bind(rule.severity.clone())
            .bind(title.clone())
            .bind(summary.clone())
            .bind(ev.raw.source_ip.clone())
            .bind(ev.mitre_technique_ids.clone())
            .bind(1_i32)
            .execute(&db)
            .await;

            let ttl = (rule.suppression_minutes.max(1) * 60) as usize;
            let _ = redis::cmd("SETEX")
                .arg(&suppression_key)
                .arg(ttl)
                .arg("1")
                .query_async::<_, ()>(&mut con)
                .await;

            let alert_payload = json!({
                "id": alert_id,
                "tenant_id": ev.raw.tenant_id,
                "rule_id": rule.id,
                "severity": rule.severity,
                "title": title,
                "summary": summary,
                "source_ip": ev.raw.source_ip,
                "mitre_technique_ids": ev.mitre_technique_ids,
                "event_count": 1,
                "first_seen_at": Utc::now(),
                "last_seen_at": Utc::now(),
            });

            let _ = publish_json(&p, "alerts.triggered", &alert_id.to_string(), &alert_payload).await;
            let _ = publish_json(&p, "notifications.pending", &alert_id.to_string(), &alert_payload).await;
        }
    }
}

async fn load_rules(db: &PgPool) -> Vec<rules::RuleRecord> {
    let rows = sqlx::query_as::<_, (Uuid, Uuid, String, String, serde_json::Value, String, i32)>(
        "SELECT id, tenant_id, name, type, config, severity, suppression_minutes
         FROM alert_rules
         WHERE enabled = TRUE"
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();

    rows.into_iter()
        .map(|r| rules::RuleRecord {
            id: r.0,
            tenant_id: r.1,
            name: r.2,
            rule_type: r.3,
            config: r.4,
            severity: r.5,
            suppression_minutes: r.6,
        })
        .collect()
}
