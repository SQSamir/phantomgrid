use chrono::Utc;
use phantomgrid_kafka::send_event;
use phantomgrid_types::{event::RawEvent, Protocol, Severity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{DecoyConfig, EngineContext};

pub async fn run(ctx: EngineContext, cfg: DecoyConfig) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&cfg.bind_addr).await?;
    loop {
        if ctx.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }

        let Ok((mut socket, peer)) = listener.accept().await else {
            continue;
        };
        let producer = ctx.producer.clone();
        let tenant_id = ctx.tenant_id;
        let decoy_id = cfg.decoy_id;

        tokio::spawn(async move {
            let mut buf = [0_u8; 4096];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_uppercase();

            let (resp, event_type, severity, tag) = if req.contains("PING") {
                ("+PONG\r\n", "ping", Severity::Info, "redis_probe")
            } else if req.contains("CONFIG SET") {
                ("+OK\r\n", "config_set", Severity::High, "T1505.003")
            } else if req.contains("SLAVEOF") || req.contains("REPLICAOF") {
                ("+OK\r\n", "replication_attack", Severity::High, "T1505.003")
            } else if req.contains("FLUSHALL") || req.contains("FLUSHDB") {
                ("+OK\r\n", "data_destruction", Severity::Critical, "T1485")
            } else if req.contains("EVAL") {
                ("-ERR not allowed\r\n", "rce_attempt", Severity::High, "T1059")
            } else if req.contains("INFO") {
                ("$50\r\n# Server\r\nredis_version:7.0.11\r\nrole:master\r\n\r\n", "info", Severity::Info, "redis_probe")
            } else if req.contains("AUTH") {
                ("+OK\r\n", "auth_attempt", Severity::High, "credential_capture")
            } else if req.contains("SET") || req.contains("GET") || req.contains("KEYS") {
                ("+OK\r\n", "kv_access", Severity::Medium, "redis_probe")
            } else {
                ("-ERR unknown command\r\n", "unknown", Severity::Low, "redis_probe")
            };

            let _ = socket.write_all(resp.as_bytes()).await;

            let ev = RawEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                tenant_id,
                decoy_id: Some(decoy_id),
                session_id: Some(Uuid::new_v4()),
                source_ip: peer.ip().to_string(),
                source_port: Some(peer.port()),
                destination_ip: None,
                destination_port: Some(16379),
                protocol: Protocol::Redis,
                event_type: event_type.into(),
                severity,
                raw_data: serde_json::json!({"resp": String::from_utf8_lossy(&buf[..n]).to_string()}),
                tags: vec![tag.into()],
            };
            send_event(&producer, "events.raw", &ev.event_id.to_string(), &ev).await;
        });
    }
    Ok(())
}
