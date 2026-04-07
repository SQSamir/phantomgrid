use axum::{extract::State, http::HeaderMap, routing::get, Router};
use chrono::Utc;
use phantomgrid_kafka::publish_json;
use phantomgrid_types::RawEvent;
use std::{env, sync::Arc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[derive(Clone)]
struct AppState {
    producer: rdkafka::producer::FutureProducer,
    tenant_id: Uuid,
    decoy_id_http: Uuid,
    decoy_id_ssh: Uuid,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let producer = phantomgrid_kafka::producer(&brokers)?;
    let tenant_id = env::var("DEFAULT_TENANT_ID").ok().and_then(|s| Uuid::parse_str(&s).ok()).unwrap_or_else(Uuid::new_v4);

    let st = Arc::new(AppState {
        producer,
        tenant_id,
        decoy_id_http: Uuid::new_v4(),
        decoy_id_ssh: Uuid::new_v4(),
    });

    let http_state = st.clone();
    tokio::spawn(async move {
        let app = Router::new().route("/", get(http_root)).with_state(http_state);
        let listener = tokio::net::TcpListener::bind("0.0.0.0:18080").await.expect("bind http");
        axum::serve(listener, app).await.expect("serve http");
    });

    let ssh_state = st.clone();
    tokio::spawn(async move { run_fake_ssh(ssh_state).await; });

    tokio::signal::ctrl_c().await?;
    Ok(())
}

async fn http_root(State(st): State<Arc<AppState>>, headers: HeaderMap) -> String {
    let src_ip = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()).unwrap_or("0.0.0.0").to_string();
    let ev = RawEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        tenant_id: st.tenant_id,
        decoy_id: st.decoy_id_http,
        decoy_type: "http_honeypot".into(),
        source_ip: src_ip,
        source_port: 0,
        destination_ip: "0.0.0.0".into(),
        destination_port: 18080,
        protocol: "HTTP".into(),
        session_id: Uuid::new_v4(),
        raw_data: serde_json::json!({"headers": headers.iter().map(|(k,v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<Vec<_>>() }),
        severity: "medium".into(),
        tags: vec!["http_probe".into()],
    };
    let _ = publish_json(&st.producer, "events.raw", &ev.event_id.to_string(), &ev).await;
    "It works. Apache/2.4.41 (Ubuntu)".into()
}

async fn run_fake_ssh(st: Arc<AppState>) {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:10022").await.expect("bind ssh");
    loop {
        let Ok((mut socket, peer)) = listener.accept().await else { continue; };
        let stc = st.clone();
        tokio::spawn(async move {
            let _ = socket.write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n").await;
            let mut buf = [0u8; 512];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let banner = String::from_utf8_lossy(&buf[..n]).to_string();

            let ev = RawEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                tenant_id: stc.tenant_id,
                decoy_id: stc.decoy_id_ssh,
                decoy_type: "ssh_honeypot".into(),
                source_ip: peer.ip().to_string(),
                source_port: peer.port(),
                destination_ip: "0.0.0.0".into(),
                destination_port: 10022,
                protocol: "SSH".into(),
                session_id: Uuid::new_v4(),
                raw_data: serde_json::json!({"client_banner": banner}),
                severity: "high".into(),
                tags: vec!["ssh_probe".into()],
            };
            let _ = publish_json(&stc.producer, "events.raw", &ev.event_id.to_string(), &ev).await;
        });
    }
}
