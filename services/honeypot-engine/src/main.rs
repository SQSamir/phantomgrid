use std::{collections::HashMap, env, net::IpAddr, sync::Arc};

use dashmap::DashMap;
use once_cell::sync::Lazy;
use phantomgrid_kafka::create_producer;
use rdkafka::producer::FutureProducer;
use tokio::signal;
use uuid::Uuid;

mod protocols;

pub static CONN_LIMIT: Lazy<DashMap<IpAddr, std::sync::atomic::AtomicU32>> = Lazy::new(DashMap::new);
pub const MAX_CONNS_PER_IP: u32 = 50;

#[derive(Clone)]
pub struct EngineContext {
    pub producer: Arc<FutureProducer>,
    pub tenant_id: Uuid,
    pub decoys: Arc<DashMap<Uuid, DecoyConfig>>,
    pub shutting_down: Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct DecoyConfig {
    pub decoy_id: Uuid,
    pub kind: String,
    pub bind_addr: String,
    pub config: serde_json::Value,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let producer = Arc::new(create_producer(&brokers).await);

    let tenant_id = env::var("DEFAULT_TENANT_ID")
        .ok()
        .and_then(|v| Uuid::parse_str(&v).ok())
        .unwrap_or_else(Uuid::new_v4);

    let decoys = load_active_decoys_from_redis().await;

    let ctx = EngineContext {
        producer,
        tenant_id,
        decoys: Arc::new(DashMap::from_iter(decoys.into_iter())),
        shutting_down: Arc::new(std::sync::atomic::AtomicBool::new(false)),
    };

    let mut handles = vec![];
    for d in ctx.decoys.iter() {
        let c = ctx.clone();
        let cfg = d.value().clone();
        let h = tokio::spawn(async move {
            match cfg.kind.as_str() {
                "ssh" => protocols::ssh::run(c, cfg).await,
                "http" => protocols::http::run(c, cfg).await,
                "redis" => protocols::redis_hp::run(c, cfg).await,
                "telnet" => protocols::telnet::run(c, cfg).await,
                _ => Ok(()),
            }
        });
        handles.push(h);
    }

    wait_for_shutdown_signal().await;
    ctx.shutting_down
        .store(true, std::sync::atomic::Ordering::SeqCst);
    ctx.producer.flush(std::time::Duration::from_secs(5));

    for h in handles {
        let _ = h.await;
    }

    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = signal::unix::signal(signal::unix::SignalKind::terminate()).ok();
        tokio::select! {
            _ = signal::ctrl_c() => {}
            _ = async {
                if let Some(t) = term.as_mut() { let _ = t.recv().await; }
            } => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = signal::ctrl_c().await;
    }
}

async fn load_active_decoys_from_redis() -> Vec<DecoyConfig> {
    // Dev fallback: statik default decoy seti
    vec![
        DecoyConfig {
            decoy_id: Uuid::new_v4(),
            kind: "ssh".into(),
            bind_addr: "0.0.0.0:10022".into(),
            config: serde_json::json!({
                "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
                "fake_hostname": "web-prod-01",
                "motd": "Welcome to Ubuntu 22.04 LTS"
            }),
        },
        DecoyConfig {
            decoy_id: Uuid::new_v4(),
            kind: "http".into(),
            bind_addr: "0.0.0.0:18080".into(),
            config: serde_json::json!({
                "server_header": "Apache/2.4.54 (Ubuntu)",
                "template": "apache_default",
                "capture_forms": true
            }),
        },
        DecoyConfig {
            decoy_id: Uuid::new_v4(),
            kind: "redis".into(),
            bind_addr: "0.0.0.0:16379".into(),
            config: serde_json::json!({}),
        },
        DecoyConfig {
            decoy_id: Uuid::new_v4(),
            kind: "telnet".into(),
            bind_addr: "0.0.0.0:10023".into(),
            config: serde_json::json!({}),
        },
    ]
}
