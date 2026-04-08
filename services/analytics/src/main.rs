use axum::{extract::{Path, Query, State}, routing::get, Json, Router};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use sqlx::PgPool;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

#[derive(Deserialize)]
struct BaseQ {
    tenant_id: String,
    from: Option<String>,
    to: Option<String>,
}

#[derive(Deserialize)]
struct LimitQ {
    tenant_id: String,
    from: Option<String>,
    to: Option<String>,
    limit: Option<u32>,
}

#[derive(Deserialize)]
struct TimelineQ {
    tenant_id: String,
    from: Option<String>,
    to: Option<String>,
    granularity: Option<String>,
}

fn range_or_default(from: Option<String>, to: Option<String>) -> (String, String) {
    (
        from.unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string()),
        to.unwrap_or_else(|| "2100-01-01T00:00:00Z".to_string()),
    )
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let db_url = std::env::var("DATABASE_URL")?;
    let pool = sqlx::postgres::PgPoolOptions::new().max_connections(10).connect(&db_url).await?;

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/analytics/overview", get(overview))
        .route("/api/v1/analytics/timeline", get(timeline))
        .route("/api/v1/analytics/top-attackers", get(top_attackers))
        .route("/api/v1/analytics/attack-heatmap", get(attack_heatmap))
        .route("/api/v1/analytics/protocol-breakdown", get(protocol_breakdown))
        .route("/api/v1/analytics/geographic", get(geographic))
        .route("/api/v1/analytics/attacker-profile/:ip", get(attacker_profile))
        .route("/api/v1/analytics/mitre-coverage", get(mitre_coverage))
        .route("/api/v1/analytics/campaign-detection", get(campaign_detection))
        .with_state(AppState { pool });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8086").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn overview(State(st): State<AppState>, Query(q): Query<BaseQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);

    let events_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM events WHERE tenant_id::text = $1 AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz")
        .bind(&q.tenant_id).bind(&from).bind(&to).fetch_one(&st.pool).await.unwrap_or(0);

    let active_alerts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM alerts WHERE tenant_id::text = $1 AND status IN ('new','investigating')")
        .bind(&q.tenant_id).fetch_one(&st.pool).await.unwrap_or(0);

    let active_decoys: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM decoys WHERE tenant_id::text = $1 AND status = 'active'")
        .bind(&q.tenant_id).fetch_one(&st.pool).await.unwrap_or(0);

    let attackers_tracked: i64 = sqlx::query_scalar("SELECT COUNT(DISTINCT source_ip) FROM events WHERE tenant_id::text = $1 AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz")
        .bind(&q.tenant_id).bind(&from).bind(&to).fetch_one(&st.pool).await.unwrap_or(0);

    let spark: Vec<(DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT date_bin('1 hour', created_at, TIMESTAMP '1970-01-01') AS ts, COUNT(*)
         FROM events WHERE tenant_id::text = $1 AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz
         GROUP BY ts ORDER BY ts"
    )
    .bind(&q.tenant_id).bind(&from).bind(&to).fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({
        "active_decoys": active_decoys,
        "events_today": events_total,
        "active_alerts": active_alerts,
        "attackers_tracked": attackers_tracked,
        "sparklines": spark.into_iter().map(|(ts, count)| serde_json::json!({"ts": ts, "count": count})).collect::<Vec<_>>()
    }))
}

async fn timeline(State(st): State<AppState>, Query(q): Query<TimelineQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);
    let bucket = match q.granularity.as_deref() {
        Some("hour") => "1 hour",
        Some("minute") => "1 minute",
        _ => "5 minutes",
    };

    let rows: Vec<(DateTime<Utc>, i64)> = sqlx::query_as(
        "SELECT date_bin($1::interval, created_at, TIMESTAMP '1970-01-01') AS ts, COUNT(*)
         FROM events
         WHERE tenant_id::text = $2
           AND created_at >= $3::timestamptz
           AND created_at <= $4::timestamptz
         GROUP BY ts
         ORDER BY ts"
    )
    .bind(bucket).bind(&q.tenant_id).bind(&from).bind(&to)
    .fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({"items": rows.into_iter().map(|(ts, count)| serde_json::json!({"ts": ts, "count": count})).collect::<Vec<_>>()}))
}

async fn top_attackers(State(st): State<AppState>, Query(q): Query<LimitQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);
    let limit = q.limit.unwrap_or(10).clamp(1, 100) as i64;

    let rows: Vec<(String, i64, Option<String>, Option<String>, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT source_ip::text, COUNT(*) AS cnt,
                MAX(enrichment->'geo'->>'country') AS country,
                MAX(enrichment->'geo'->>'city') AS city,
                MAX(created_at) AS last_seen
         FROM events
         WHERE tenant_id::text = $1 AND source_ip IS NOT NULL
           AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz
         GROUP BY source_ip
         ORDER BY cnt DESC
         LIMIT $4"
    )
    .bind(&q.tenant_id).bind(&from).bind(&to).bind(limit)
    .fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({"limit": limit, "items": rows.into_iter().map(|(ip,country_count,country,city,last_seen)| serde_json::json!({"source_ip": ip, "event_count": country_count, "country": country, "city": city, "last_seen": last_seen})).collect::<Vec<_>>() }))
}

async fn attack_heatmap(State(st): State<AppState>, Query(q): Query<BaseQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);
    let rows: Vec<(i32, i32, i64)> = sqlx::query_as(
        "SELECT EXTRACT(DOW FROM created_at)::int AS day_of_week,
                EXTRACT(HOUR FROM created_at)::int AS hour_of_day,
                COUNT(*)
         FROM events
         WHERE tenant_id::text = $1 AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz
         GROUP BY day_of_week, hour_of_day
         ORDER BY day_of_week, hour_of_day"
    )
    .bind(&q.tenant_id).bind(&from).bind(&to)
    .fetch_all(&st.pool).await.unwrap_or_default();
    Json(serde_json::json!({"items": rows.into_iter().map(|(d,h,c)| serde_json::json!({"day": d, "hour": h, "count": c})).collect::<Vec<_>>() }))
}

async fn protocol_breakdown(State(st): State<AppState>, Query(q): Query<BaseQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE(protocol, 'unknown') AS protocol, COUNT(*) AS cnt
         FROM events
         WHERE tenant_id::text = $1 AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz
         GROUP BY protocol
         ORDER BY cnt DESC"
    )
    .bind(&q.tenant_id).bind(&from).bind(&to).fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({"items": rows.into_iter().map(|(p,c)| serde_json::json!({"protocol": p, "count": c})).collect::<Vec<_>>() }))
}

async fn geographic(State(st): State<AppState>, Query(q): Query<BaseQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE(enrichment->'geo'->>'country', 'Unknown') AS country, COUNT(*) AS cnt
         FROM events
         WHERE tenant_id::text = $1 AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz
         GROUP BY country
         ORDER BY cnt DESC"
    )
    .bind(&q.tenant_id).bind(&from).bind(&to).fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({"items": rows.into_iter().map(|(country,count)| serde_json::json!({"country": country, "count": count})).collect::<Vec<_>>() }))
}

async fn attacker_profile(State(st): State<AppState>, Path(ip): Path<String>, Query(q): Query<BaseQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events WHERE tenant_id::text = $1 AND source_ip::text = $2 AND created_at >= $3::timestamptz AND created_at <= $4::timestamptz"
    ).bind(&q.tenant_id).bind(&ip).bind(&from).bind(&to).fetch_one(&st.pool).await.unwrap_or(0);

    let first_seen: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MIN(created_at) FROM events WHERE tenant_id::text = $1 AND source_ip::text = $2 AND created_at >= $3::timestamptz AND created_at <= $4::timestamptz"
    ).bind(&q.tenant_id).bind(&ip).bind(&from).bind(&to).fetch_one(&st.pool).await.ok().flatten();

    let last_seen: Option<DateTime<Utc>> = sqlx::query_scalar(
        "SELECT MAX(created_at) FROM events WHERE tenant_id::text = $1 AND source_ip::text = $2 AND created_at >= $3::timestamptz AND created_at <= $4::timestamptz"
    ).bind(&q.tenant_id).bind(&ip).bind(&from).bind(&to).fetch_one(&st.pool).await.ok().flatten();

    let protocols: Vec<(String, i64)> = sqlx::query_as(
        "SELECT COALESCE(protocol, 'unknown'), COUNT(*) FROM events
         WHERE tenant_id::text = $1 AND source_ip::text = $2 AND created_at >= $3::timestamptz AND created_at <= $4::timestamptz
         GROUP BY protocol ORDER BY count(*) DESC"
    ).bind(&q.tenant_id).bind(&ip).bind(&from).bind(&to).fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({
        "source_ip": ip,
        "event_count": total,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "protocols": protocols.into_iter().map(|(p,c)| serde_json::json!({"protocol": p, "count": c})).collect::<Vec<_>>()
    }))
}

async fn mitre_coverage(State(st): State<AppState>, Query(q): Query<BaseQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT technique, COUNT(*) FROM (
            SELECT UNNEST(mitre_technique_ids) AS technique
            FROM events
            WHERE tenant_id::text = $1 AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz
         ) t
         GROUP BY technique
         ORDER BY count(*) DESC"
    )
    .bind(&q.tenant_id).bind(&from).bind(&to).fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({"items": rows.into_iter().map(|(id, count)| serde_json::json!({"technique_id": id, "count": count})).collect::<Vec<_>>() }))
}

async fn campaign_detection(State(st): State<AppState>, Query(q): Query<BaseQ>) -> Json<serde_json::Value> {
    let (from, to) = range_or_default(q.from, q.to);
    let rows: Vec<(String, i64, i64, Option<DateTime<Utc>>)> = sqlx::query_as(
        "SELECT source_ip::text,
                COUNT(*) AS event_count,
                COUNT(DISTINCT decoy_id) AS decoy_count,
                MAX(created_at) AS last_seen
         FROM events
         WHERE tenant_id::text = $1 AND source_ip IS NOT NULL
           AND created_at >= $2::timestamptz AND created_at <= $3::timestamptz
         GROUP BY source_ip
         HAVING COUNT(DISTINCT decoy_id) >= 2
         ORDER BY event_count DESC
         LIMIT 100"
    )
    .bind(&q.tenant_id).bind(&from).bind(&to).fetch_all(&st.pool).await.unwrap_or_default();

    Json(serde_json::json!({"items": rows.into_iter().map(|(ip, events, decoys, last_seen)| serde_json::json!({"source_ip": ip, "event_count": events, "decoy_count": decoys, "last_seen": last_seen})).collect::<Vec<_>>() }))
}
