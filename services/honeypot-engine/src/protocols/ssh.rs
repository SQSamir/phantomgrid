use std::sync::Arc;

use chrono::Utc;
use phantomgrid_kafka::send_event;
use phantomgrid_types::{event::RawEvent, Protocol, Severity};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

use crate::{DecoyConfig, EngineContext};

#[derive(serde::Deserialize)]
pub struct SshConfig {
    pub banner: String,
    pub fake_hostname: String,
    pub motd: String,
    pub bind_addr: String,
}

pub async fn run(ctx: EngineContext, cfg: DecoyConfig) -> anyhow::Result<()> {
    let mut sc: SshConfig = serde_json::from_value(cfg.config).unwrap_or(SshConfig {
        banner: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6".into(),
        fake_hostname: "web-prod-01".into(),
        motd: "Welcome".into(),
        bind_addr: cfg.bind_addr.clone(),
    });
    sc.bind_addr = cfg.bind_addr;

    let listener = tokio::net::TcpListener::bind(&sc.bind_addr).await?;
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
        let sc = Arc::new(sc.clone());

        tokio::spawn(async move {
            let _ = socket.write_all(format!("{}\r\n", sc.banner).as_bytes()).await;
            let _ = socket
                .write_all(format!("{}\n{}\n$ ", sc.fake_hostname, sc.motd).as_bytes())
                .await;

            let mut buf = [0u8; 2048];
            let n = socket.read(&mut buf).await.unwrap_or(0);
            let cmd = String::from_utf8_lossy(&buf[..n]).trim().to_string();

            let out = match cmd.as_str() {
                "ls" | "ls -la" => "total 16\ndrwxr-xr-x  2 root root 4096 Apr 10 10:00 .\n-rw-r--r--  1 root root  220 .bash_logout\n",
                "whoami" => "root\n",
                "id" => "uid=0(root) gid=0(root) groups=0(root)\n",
                "pwd" => "/root\n",
                "uname -a" => "Linux web-prod-01 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n",
                "cat /etc/passwd" => "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n",
                "ifconfig" | "ip a" => "eth0: inet 10.10.10.20/24\n",
                "ps aux" => "root 1 0.0 0.1 /sbin/init\n",
                "history" => "1 ls\n2 whoami\n3 cat /etc/passwd\n",
                "exit" | "quit" => "logout\n",
                _ => "bash: command not found\n",
            };
            let _ = socket.write_all(out.as_bytes()).await;

            let ev = RawEvent {
                event_id: Uuid::new_v4(),
                timestamp: Utc::now(),
                tenant_id,
                decoy_id: Some(decoy_id),
                session_id: Some(Uuid::new_v4()),
                source_ip: peer.ip().to_string(),
                source_port: Some(peer.port()),
                destination_ip: None,
                destination_port: Some(10022),
                protocol: Protocol::Ssh,
                event_type: "command_executed".into(),
                severity: Severity::High,
                raw_data: serde_json::json!({"command": cmd, "output": out}),
                tags: vec!["credential_capture".into(), "T1059".into()],
            };
            send_event(&producer, "events.raw", &ev.event_id.to_string(), &ev).await;
        });
    }

    Ok(())
}
