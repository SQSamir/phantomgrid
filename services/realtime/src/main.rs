use axum::{extract::{ws::{Message, WebSocket, WebSocketUpgrade}, Query, State}, response::IntoResponse, routing::get, Router};
use futures_util::StreamExt;
use rdkafka::message::Message;
use std::{collections::HashMap, env, sync::Arc};
use tokio::sync::broadcast;

#[derive(Clone)]
struct AppState { tx: broadcast::Sender<String> }

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let (tx, _rx) = broadcast::channel::<String>(4096);
    let st = AppState { tx: tx.clone() };

    tokio::spawn(async move {
        let c = match phantomgrid_kafka::consumer("phantomgrid-realtime", &brokers, &["events.enriched", "alerts.triggered"]) {
            Ok(v) => v,
            Err(_) => return,
        };
        loop {
            if let Ok(msg) = c.recv().await {
                if let Some(p) = msg.payload() {
                    let _ = tx.send(String::from_utf8_lossy(p).to_string());
                }
            }
        }
    });

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/ws/events", get(ws_handler))
        .route("/ws/alerts", get(ws_handler))
        .with_state(Arc::new(st));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8085").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn ws_handler(
    ws: WebSocketUpgrade,
    State(st): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let tenant = params.get("tenant_id").cloned().unwrap_or_default();
    ws.on_upgrade(move |sock| client(sock, st.tx.subscribe(), tenant))
}

async fn client(mut socket: WebSocket, mut rx: broadcast::Receiver<String>, tenant_id: String) {
    loop {
        tokio::select! {
            Ok(msg) = rx.recv() => {
                if !tenant_id.is_empty() && !msg.contains(&tenant_id) { continue; }
                if socket.send(Message::Text(msg.into())).await.is_err() { break; }
            }
            Some(Ok(in_msg)) = socket.next() => {
                if matches!(in_msg, Message::Ping(_)) {
                    let _ = socket.send(Message::Pong(Vec::new().into())).await;
                }
            }
            else => break,
        }
    }
}
