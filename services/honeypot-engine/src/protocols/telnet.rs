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
            let _ = socket
                .write_all(b"\xff\xfb\x01\xff\xfb\x03BusyBox v1.35.0 (2023-01-01) login: ")
                .await;
            let username = read_line(&mut socket).await;
            let _ = socket.write_all(b"Password: ").await;
            let password = read_line(&mut socket).await;
            let _ = socket.write_all(b"\n/ # ").await;
            let cmd = read_line(&mut socket).await;

            let mut tags = vec!["telnet_probe".to_string(), "credential_capture".to_string()];
            if cmd.contains("enable") || cmd.contains("/bin/sh") || cmd.contains("busybox") {
                tags.push("iot_malware".to_string());
                tags.push("T1498".to_string());
            }

            let ev = RawEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                tenant_id,
                decoy_id: Some(decoy_id),
                session_id: Some(Uuid::new_v4()),
                source_ip: peer.ip().to_string(),
                source_port: Some(peer.port()),
                destination_ip: None,
                destination_port: Some(10023),
                protocol: Protocol::Telnet,
                event_type: "telnet_session".into(),
                severity: Severity::High,
                raw_data: serde_json::json!({
                    "username": username,
                    "password": password,
                    "command": cmd
                }),
                tags,
            };
            send_event(&producer, "events.raw", &ev.event_id.to_string(), &ev).await;

            let _ = socket.write_all(b"command not found\n/ # ").await;
        });
    }

    Ok(())
}

async fn read_line(socket: &mut tokio::net::TcpStream) -> String {
    let mut out = vec![];
    let mut b = [0_u8; 1];
    loop {
        match socket.read(&mut b).await {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                if b[0] == b'\n' || b[0] == b'\r' {
                    break;
                }
                out.push(b[0]);
                if out.len() >= 1024 {
                    break;
                }
            }
        }
    }
    String::from_utf8_lossy(&out).to_string()
}
