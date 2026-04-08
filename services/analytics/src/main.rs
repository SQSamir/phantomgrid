use axum::{extract::Query, routing::get, Json, Router};
use serde::Deserialize;

#[derive(Deserialize)]
struct Lim { limit: Option<u32> }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/api/v1/analytics/overview", get(overview))
        .route("/api/v1/analytics/top-attackers", get(top_attackers))
        .route("/api/v1/analytics/protocol-breakdown", get(protocol_breakdown))
        .route("/api/v1/analytics/geographic", get(geographic));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8086").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn overview() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "active_decoys": 0,
        "events_today": 0,
        "active_alerts": 0,
        "attackers_tracked": 0
    }))
}

async fn top_attackers(Query(q): Query<Lim>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"limit": q.limit.unwrap_or(10), "items": []}))
}

async fn protocol_breakdown() -> Json<serde_json::Value> { Json(serde_json::json!({"items": []})) }
async fn geographic() -> Json<serde_json::Value> { Json(serde_json::json!({"items": []})) }
