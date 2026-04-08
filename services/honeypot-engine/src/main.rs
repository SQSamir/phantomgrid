use axum::{extract::State, http::HeaderMap, routing::get, Router};
use chrono::Utc;
use dashmap::DashMap;
use phantomgrid_kafka::publish_json;
use phantomgrid_types::RawEvent;
use std::{
    env,
    net::IpAddr,
    sync::{
        atomic::{AtomicBool, AtomicU32, Ordering},
        Arc,
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[cfg(test)]
mod tests;

#[derive(Clone)]
struct AppState {
    producer: rdkafka::producer::FutureProducer,
    tenant_id: Uuid,
    decoy_id_http: Uuid,
    decoy_id_ssh: Uuid,
    decoy_id_telnet: Uuid,
    decoy_id_redis: Uuid,
    decoy_id_dns: Uuid,
    per_ip: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
    shutting_down: Arc<AtomicBool>,
}

struct ConnectionGuard {
    ip: IpAddr,
    per_ip: Arc<DashMap<IpAddr, Arc<AtomicU32>>>,
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(counter) = self.per_ip.get(&self.ip) {
            let old = counter.fetch_sub(1, Ordering::SeqCst);
            if old <= 1 {
                self.per_ip.remove(&self.ip);
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let producer = phantomgrid_kafka::producer(&brokers)?;
    let tenant_id = env::var("DEFAULT_TENANT_ID")
        .ok()
        .and_then(|s| Uuid::parse_str(&s).ok())
        .unwrap_or_else(Uuid::new_v4);

    let st = Arc::new(AppState {
        producer,
        tenant_id,
        decoy_id_http: Uuid::new_v4(),
        decoy_id_ssh: Uuid::new_v4(),
        decoy_id_telnet: Uuid::new_v4(),
        decoy_id_redis: Uuid::new_v4(),
        decoy_id_dns: Uuid::new_v4(),
        per_ip: Arc::new(DashMap::new()),
        shutting_down: Arc::new(AtomicBool::new(false)),
    });

    let http_state = st.clone();
    tokio::spawn(async move {
        if let Err(e) = run_http(http_state).await {
            tracing::error!(error=%e, "http handler stopped");
        }
    });

    let ssh_state = st.clone();
    tokio::spawn(async move {
        if let Err(e) = run_fake_ssh(ssh_state).await {
            tracing::error!(error=%e, "ssh handler stopped");
        }
    });

    let telnet_state = st.clone();
    tokio::spawn(async move {
        if let Err(e) = run_telnet(telnet_state).await {
            tracing::error!(error=%e, "telnet handler stopped");
        }
    });

    let redis_state = st.clone();
    tokio::spawn(async move {
        if let Err(e) = run_redis(redis_state).await {
            tracing::error!(error=%e, "redis handler stopped");
        }
    });

    let dns_state = st.clone();
    tokio::spawn(async move {
        if let Err(e) = run_dns(dns_state).await {
            tracing::error!(error=%e, "dns handler stopped");
        }
    });

    tokio::spawn(async move {
        let app = Router::new().route("/metrics", get(|| async { "# TYPE service_up gauge\nservice_up{service=\"honeypot-engine\"} 1\n" }));
        if let Ok(listener) = tokio::net::TcpListener::bind("0.0.0.0:9100").await {
            let _ = axum::serve(listener, app).await;
        }
    });

    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }

    st.shutting_down.store(true, Ordering::SeqCst);
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    Ok(())
}

fn try_acquire(st: &Arc<AppState>, ip: IpAddr) -> Option<ConnectionGuard> {
    let counter = st
        .per_ip
        .entry(ip)
        .or_insert_with(|| Arc::new(AtomicU32::new(0)))
        .clone();
    let current = counter.fetch_add(1, Ordering::SeqCst) + 1;
    if current > 50 {
        let _ = counter.fetch_sub(1, Ordering::SeqCst);
        return None;
    }
    Some(ConnectionGuard {
        ip,
        per_ip: st.per_ip.clone(),
    })
}

fn sanitize_bytes(input: &[u8]) -> String {
    let mut out = String::new();
    for b in input.iter().take(4096) {
        if b.is_ascii_graphic() || *b == b' ' {
            out.push(*b as char);
        } else {
            out.push_str(&format!("\\x{:02x}", b));
        }
    }
    out
}

async fn run_http(st: Arc<AppState>) -> anyhow::Result<()> {
    let app = Router::new().route("/", get(http_root)).with_state(st);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:18080").await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn http_root(State(st): State<Arc<AppState>>, headers: HeaderMap) -> String {
    let src_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0.0.0.0")
        .to_string();
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
        raw_data: serde_json::json!({
            "headers": headers.iter().map(|(k, v)| (k.as_str(), v.to_str().unwrap_or(""))).collect::<Vec<_>>()
        }),
        severity: "medium".into(),
        tags: vec!["http_probe".into()],
    };
    let _ = publish_json(&st.producer, "events.raw", &ev.event_id.to_string(), &ev).await;
    "It works. Apache/2.4.41 (Ubuntu)".into()
}

async fn run_fake_ssh(st: Arc<AppState>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:10022").await?;
    loop {
        if st.shutting_down.load(Ordering::SeqCst) {
            break;
        }
        let Ok((mut socket, peer)) = listener.accept().await else {
            continue;
        };

        let Some(_guard) = try_acquire(&st, peer.ip()) else {
            let _ = socket.shutdown().await;
            continue;
        };

        let stc = st.clone();
        tokio::spawn(async move {
            let _ = socket
                .write_all(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")
                .await;
            let mut buf = [0u8; 512];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let banner = sanitize_bytes(&buf[..n]);

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
    Ok(())
}

async fn run_telnet(st: Arc<AppState>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:10023").await?;
    loop {
        if st.shutting_down.load(Ordering::SeqCst) {
            break;
        }
        let Ok((mut socket, peer)) = listener.accept().await else {
            continue;
        };

        let Some(_guard) = try_acquire(&st, peer.ip()) else {
            let _ = socket.shutdown().await;
            continue;
        };

        let stc = st.clone();
        tokio::spawn(async move {
            let session_id = Uuid::new_v4();
            let _ = socket.write_all(b"Debian GNU/Linux 12\nlogin: ").await;

            let username = read_line(&mut socket).await;
            let _ = socket.write_all(b"Password: ").await;
            let password = read_line(&mut socket).await;

            let _ = socket.write_all(b"\nLast login: Tue Apr  8 12:00:00 UTC 2026 from 10.0.0.5\n$ ").await;
            let command = read_line(&mut socket).await;

            let severity = if command.contains("wget") || command.contains("curl") || command.contains("busybox") {
                "high"
            } else {
                "medium"
            };

            let ev = RawEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                tenant_id: stc.tenant_id,
                decoy_id: stc.decoy_id_telnet,
                decoy_type: "telnet_honeypot".into(),
                source_ip: peer.ip().to_string(),
                source_port: peer.port(),
                destination_ip: "0.0.0.0".into(),
                destination_port: 10023,
                protocol: "TELNET".into(),
                session_id,
                raw_data: serde_json::json!({
                    "username": sanitize_bytes(username.as_bytes()),
                    "password": sanitize_bytes(password.as_bytes()),
                    "command": sanitize_bytes(command.as_bytes())
                }),
                severity: severity.into(),
                tags: vec!["telnet_probe".into(), "credential_capture".into()],
            };
            let _ = publish_json(&stc.producer, "events.raw", &ev.event_id.to_string(), &ev).await;
        });
    }
    Ok(())
}

async fn run_redis(st: Arc<AppState>) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind("0.0.0.0:16379").await?;
    loop {
        if st.shutting_down.load(Ordering::SeqCst) {
            break;
        }
        let Ok((mut socket, peer)) = listener.accept().await else {
            continue;
        };

        let Some(_guard) = try_acquire(&st, peer.ip()) else {
            let _ = socket.shutdown().await;
            continue;
        };

        let stc = st.clone();
        tokio::spawn(async move {
            let session_id = Uuid::new_v4();
            let mut buf = vec![0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let payload_sanitized = sanitize_bytes(&buf[..n]);

            let command = parse_redis_first_command(&payload_sanitized);
            let severity = if command.contains("CONFIG") || command.contains("SLAVEOF") {
                "high"
            } else {
                "medium"
            };

            let response = if command.eq_ignore_ascii_case("PING") {
                "+PONG\r\n"
            } else {
                "+OK\r\n"
            };
            let _ = socket.write_all(response.as_bytes()).await;

            let ev = RawEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                tenant_id: stc.tenant_id,
                decoy_id: stc.decoy_id_redis,
                decoy_type: "redis_honeypot".into(),
                source_ip: peer.ip().to_string(),
                source_port: peer.port(),
                destination_ip: "0.0.0.0".into(),
                destination_port: 16379,
                protocol: "REDIS".into(),
                session_id,
                raw_data: serde_json::json!({
                    "resp": payload_sanitized,
                    "command": command
                }),
                severity: severity.into(),
                tags: vec!["redis_probe".into()],
            };
            let _ = publish_json(&stc.producer, "events.raw", &ev.event_id.to_string(), &ev).await;
        });
    }
    Ok(())
}

async fn run_dns(st: Arc<AppState>) -> anyhow::Result<()> {
    let sock = tokio::net::UdpSocket::bind("0.0.0.0:5353").await?;
    let mut buf = [0u8; 512];

    loop {
        if st.shutting_down.load(Ordering::SeqCst) {
            break;
        }

        let Ok((n, peer)) = sock.recv_from(&mut buf).await else {
            continue;
        };

        let packet = &buf[..n];
        if packet.len() < 12 {
            continue;
        }

        let refused = dns_recursion_requested(packet);
        let resp = if refused {
            build_dns_refused(packet)
        } else {
            build_dns_nxdomain(packet)
        };
        let _ = sock.send_to(&resp, peer).await;

        let event_type = if refused { "dns_recursive_refused" } else { "dns_query" };
        let ev = RawEvent {
            event_id: Uuid::new_v4(),
            timestamp: Utc::now(),
            tenant_id: st.tenant_id,
            decoy_id: st.decoy_id_dns,
            decoy_type: "dns_honeypot".into(),
            source_ip: peer.ip().to_string(),
            source_port: peer.port(),
            destination_ip: "0.0.0.0".into(),
            destination_port: 5353,
            protocol: "DNS".into(),
            session_id: Uuid::new_v4(),
            raw_data: serde_json::json!({"payload": sanitize_bytes(packet), "event_type": event_type}),
            severity: if refused { "high".into() } else { "medium".into() },
            tags: if refused { vec!["dns_recursion_guard".into()] } else { vec!["dns_probe".into()] },
        };
        let _ = publish_json(&st.producer, "events.raw", &ev.event_id.to_string(), &ev).await;
    }

    Ok(())
}

fn dns_recursion_requested(packet: &[u8]) -> bool {
    if packet.len() < 4 {
        return false;
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    (flags & 0x0100) != 0
}

fn build_dns_refused(query: &[u8]) -> Vec<u8> {
    let mut out = query.to_vec();
    if out.len() >= 4 {
        // set QR=1, RA=0, RCODE=5 REFUSED
        out[2] = (out[2] | 0x80) & !0x80; // keep minimal; qr set below
        out[2] |= 0x80;
        out[3] = (out[3] & 0xF0) | 0x05;
    }
    if out.len() >= 12 {
        out[6] = 0;
        out[7] = 0;
        out[8] = 0;
        out[9] = 0;
        out[10] = 0;
        out[11] = 0;
    }
    out
}

fn build_dns_nxdomain(query: &[u8]) -> Vec<u8> {
    let mut out = query.to_vec();
    if out.len() >= 4 {
        out[2] |= 0x80;
        out[3] = (out[3] & 0xF0) | 0x03;
    }
    if out.len() >= 12 {
        out[6] = 0;
        out[7] = 0;
        out[8] = 0;
        out[9] = 0;
        out[10] = 0;
        out[11] = 0;
    }
    out
}

async fn read_line(socket: &mut tokio::net::TcpStream) -> String {
    let mut out = Vec::with_capacity(128);
    let mut b = [0u8; 1];
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
    sanitize_bytes(&out)
}

fn parse_redis_first_command(payload: &str) -> String {
    for token in payload
        .split(|c: char| c == '\r' || c == '\n' || c == ' ' || c == '*')
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if token.chars().all(|c| c.is_ascii_alphabetic()) {
            return token.to_ascii_uppercase();
        }
    }
    "UNKNOWN".into()
}
