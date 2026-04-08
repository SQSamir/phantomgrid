use axum::{extract::{Query, State}, routing::get, Json, Router};
use serde::Deserialize;
use sqlx::PgPool;

#[derive(Clone)]
struct AppState {
    pool: PgPool,
}

#[derive(Deserialize)]
struct Lim {
    limit: Option<u32>,
    tenant_id: Option<String>,
}

#[derive(Deserialize)]
struct TimelineQ {
    from: Option<String>,
    to: Option<String>,
    granularity: Option<String>,
    tenant_id: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let db_url = std::env::var("DATABASE_URL")?;
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .connect(&db_url)
        .await?;

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/analytics/overview", get(overview))
        .route("/api/v1/analytics/timeline", get(timeline))
        .route("/api/v1/analytics/top-attackers", get(top_attackers))
        .route("/api/v1/analytics/protocol-breakdown", get(protocol_breakdown))
        .route("/api/v1/analytics/geographic", get(geographic))
        .with_state(AppState { pool });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8086").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn overview(State(st): State<AppState>, Query(q): Query<Lim>) -> Json<serde_json::Value> {
    let tenant = q.tenant_id.unwrap_or_default();

    let events_today: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM events WHERE ($1 = '' OR tenant_id::text = $1) AND created_at >= date_trunc('day', NOW())",
    )
    .bind(&tenant)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);

    let active_alerts: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE ($1 = '' OR tenant_id::text = $1) AND status IN ('new','investigating')",
    )
    .bind(&tenant)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);

    let active_decoys: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM decoys WHERE ($1 = '' OR tenant_id::text = $1) AND status = 'active'",
    )
    .bind(&tenant)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);

    let attackers_tracked: i64 = sqlx::query_scalar(
        "SELECT COUNT(DISTINCT source_ip) FROM events WHERE ($1 = '' OR tenant_id::text = $1)",
    )
    .bind(&tenant)
    .fetch_one(&st.pool)
    .await
    .unwrap_or(0);

    Json(serde_json::json!({
        "active_decoys": active_decoys,
        "events_today": events_today,
        "active_alerts": active_alerts,
        "attackers_tracked": attackers_tracked
    }))
}

async fn timeline(State(st): State<AppState>, Query(q): Query<TimelineQ>) -> Json<serde_json::Value> {
    let tenant = q.tenant_id.unwrap_or_default();
    let bucket = match q.granularity.as_deref() {
        Some("hour") => "1 hour",
        Some("minute") => "1 minute",
        _ => "5 minutes",
    };

    let from = q.from.unwrap_or_else(|| "1970-01-01T00:00:00Z".into());
    let to = q.to.unwrap_or_else(|| "2100-01-01T00:00:00Z".into());

    let rows = sqlx::query_as::<_, (chrono::DateTime<chrono::Utc>, i64)>(
        "SELECT date_bin($1::interval, created_at, TIMESTAMP '1970-01-01') AS ts, COUNT(*)\n         FROM events\n         WHERE ($2 = '' OR tenant_id::text = $2)\n           AND created_at >= $3::timestamptz\n           AND created_at <= $4::timestamptz\n         GROUP BY ts\n         ORDER BY ts"
    )
    .bind(bucket)
    .bind(&tenant)
    .bind(from)
    .bind(to)
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();

    let items: Vec<_> = rows
        .into_iter()
        .map(|(ts, count)| serde_json::json!({"ts": ts, "count": count}))
        .collect();

    Json(serde_json::json!({"items": items}))
}

async fn top_attackers(State(st): State<AppState>, Query(q): Query<Lim>) -> Json<serde_json::Value> {
    let limit = q.limit.unwrap_or(10).clamp(1, 100) as i64;
    let tenant = q.tenant_id.unwrap_or_default();

    let rows = sqlx::query_as::<_, (String, i64, Option<chrono::DateTime<chrono::Utc>>)>(
        "SELECT source_ip::text, COUNT(*) AS cnt, MAX(created_at) AS last_seen\n         FROM events\n         WHERE source_ip IS NOT NULL\n           AND ($1 = '' OR tenant_id::text = $1)\n         GROUP BY source_ip\n         ORDER BY cnt DESC\n         LIMIT $2"
    )
    .bind(&tenant)
    .bind(limit)
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();

    let items: Vec<_> = rows
        .into_iter()
        .map(|(ip, count, last_seen)| {
            serde_json::json!({
                "source_ip": ip,
                "event_count": count,
                "last_seen": last_seen
            })
        })
        .collect();

    Json(serde_json::json!({"limit": limit, "items": items}))
}

async fn protocol_breakdown(State(st): State<AppState>, Query(q): Query<Lim>) -> Json<serde_json::Value> {
    let tenant = q.tenant_id.unwrap_or_default();

    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(protocol, 'unknown') AS protocol, COUNT(*) AS cnt\n         FROM events\n         WHERE ($1 = '' OR tenant_id::text = $1)\n         GROUP BY protocol\n         ORDER BY cnt DESC"
    )
    .bind(&tenant)
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();

    let items: Vec<_> = rows
        .into_iter()
        .map(|(protocol, count)| serde_json::json!({"protocol": protocol, "count": count}))
        .collect();

    Json(serde_json::json!({"items": items}))
}

async fn geographic(State(st): State<AppState>, Query(q): Query<Lim>) -> Json<serde_json::Value> {
    let tenant = q.tenant_id.unwrap_or_default();

    let rows = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(enrichment->>'country', 'Unknown') AS country, COUNT(*) AS cnt\n         FROM events\n         WHERE ($1 = '' OR tenant_id::text = $1)\n         GROUP BY country\n         ORDER BY cnt DESC"
    )
    .bind(&tenant)
    .fetch_all(&st.pool)
    .await
    .unwrap_or_default();

    let items: Vec<_> = rows
        .into_iter()
        .map(|(country, count)| serde_json::json!({"country": country, "count": count}))
        .collect();

    Json(serde_json::json!({"items": items}))
}
