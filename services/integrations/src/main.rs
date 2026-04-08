use axum::{routing::{get, post}, Json, Router};
use serde::Deserialize;

#[derive(Deserialize)]
struct GenericWebhook { url: String, method: String, headers: Option<serde_json::Value>, payload: serde_json::Value }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/metrics", get(|| async { "# TYPE service_up gauge\nservice_up{service=\"integrations\"} 1\n" }))
        .route("/api/v1/integrations/webhook/test", post(test_webhook));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8089").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn test_webhook(Json(req): Json<GenericWebhook>) -> Json<serde_json::Value> {
    Json(serde_json::json!({"ok": true, "url": req.url, "method": req.method, "headers": req.headers, "payload": req.payload}))
}
