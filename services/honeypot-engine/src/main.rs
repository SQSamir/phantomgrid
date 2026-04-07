use axum::{routing::get, Router};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();
    let app = Router::new().route("/health", get(|| async { "ok" }));
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
