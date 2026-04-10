use chrono::Utc;
use phantomgrid_kafka::send_event;
use phantomgrid_types::{event::RawEvent, Protocol, Severity};
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{DecoyConfig, EngineContext};

#[derive(serde::Deserialize)]
pub struct HttpConfig {
    pub server_header: String,
    pub template: String,
    pub bind_addr: String,
    pub capture_forms: bool,
}

pub async fn run(ctx: EngineContext, cfg: DecoyConfig) -> anyhow::Result<()> {
    let mut hc: HttpConfig = serde_json::from_value(cfg.config).unwrap_or(HttpConfig {
        server_header: "Apache/2.4.54 (Ubuntu)".into(),
        template: "apache_default".into(),
        bind_addr: cfg.bind_addr.clone(),
        capture_forms: true,
    });
    hc.bind_addr = cfg.bind_addr;

    let listener = tokio::net::TcpListener::bind(&hc.bind_addr).await?;
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
        let hc = hc.template.clone();

        tokio::spawn(async move {
            let mut buf = vec![0_u8; 8192];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let line = req.lines().next().unwrap_or("");
            let parts: Vec<&str> = line.split_whitespace().collect();
            let method = parts.first().copied().unwrap_or("GET");
            let uri = parts.get(1).copied().unwrap_or("/");

            let mut tags = vec![];
            if Regex::new(r"/\.\./|/etc/passwd|/proc/").ok().is_some_and(|r| r.is_match(uri)) {
                tags.push("path_traversal".to_string());
                tags.push("T1083".to_string());
            }
            if Regex::new(r"UNION SELECT|' OR|1=1").ok().is_some_and(|r| r.is_match(&req)) {
                tags.push("sqli_attempt".to_string());
                tags.push("T1190".to_string());
            }
            if Regex::new(r";id|\$\(|`").ok().is_some_and(|r| r.is_match(&req)) {
                tags.push("command_injection".to_string());
                tags.push("T1059".to_string());
            }
            if Regex::new(r"sqlmap|nikto|nmap").ok().is_some_and(|r| r.is_match(&req.to_lowercase())) {
                tags.push("scanner_detected".to_string());
                tags.push("T1595.002".to_string());
            }
            if method == "POST" && (uri == "/login" || uri == "/admin" || uri == "/wp-login.php") {
                tags.push("credential_capture".to_string());
                tags.push("T1110".to_string());
            }

            let body = match hc.as_str() {
                "wordpress" => "<html><body><h1>WordPress</h1><form action='/wp-login.php' method='post'><input name='log'/><input name='pwd' type='password'/></form></body></html>",
                "nginx" => "<html><body><h1>Welcome to nginx!</h1></body></html>",
                _ => "<html><body><h1>Apache2 Ubuntu Default Page</h1></body></html>",
            };

            let resp = format!(
                "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (Ubuntu)\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
                body.len(), body
            );
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
                destination_port: Some(18080),
                protocol: Protocol::Http,
                event_type: "http_request".into(),
                severity: if tags.iter().any(|t| t == "credential_capture") { Severity::High } else { Severity::Medium },
                raw_data: serde_json::json!({
                    "method": method,
                    "uri": uri,
                    "body_preview": req.chars().take(500).collect::<String>(),
                }),
                tags,
            };
            send_event(&producer, "events.raw", &ev.event_id.to_string(), &ev).await;
        });
    }
    Ok(())
}
