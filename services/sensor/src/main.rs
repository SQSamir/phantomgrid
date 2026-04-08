use axum::{routing::get, Router};
use serde::Serialize;

#[derive(Serialize)]
struct Heartbeat<'a> { name: &'a str, os: &'a str, version: &'a str }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let endpoint = std::env::var("SENSOR_GATEWAY_URL").unwrap_or_else(|_| "http://api-gateway:8080/api/v1/sensors/heartbeat".into());
    let name = std::env::var("SENSOR_NAME").unwrap_or_else(|_| "sensor-local".into());

    tokio::spawn(async move {
        let app = Router::new().route("/metrics", get(|| async { "# TYPE service_up gauge\nservice_up{service=\"sensor\"} 1\n" }));
        if let Ok(listener) = tokio::net::TcpListener::bind("0.0.0.0:9100").await {
            let _ = axum::serve(listener, app).await;
        }
    });

    let client = reqwest::Client::new();
    loop {
        let hb = Heartbeat { name: &name, os: std::env::consts::OS, version: env!("CARGO_PKG_VERSION") };
        let _ = client.post(&endpoint).json(&hb).send().await;
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
    }
}
