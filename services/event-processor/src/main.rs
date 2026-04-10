use anyhow::Context;
use maxminddb::{geoip2, Reader};
use phantomgrid_db::{connect, migrate};
use phantomgrid_kafka::{consumer, parse_json, producer, publish_json};
use phantomgrid_types::event::{EnrichedEvent, Enrichment, RawEvent};
use std::{env, net::{IpAddr, Ipv4Addr}};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().json().init();

    let brokers = env::var("KAFKA_BROKERS").unwrap_or_else(|_| "kafka:9092".into());
    let db = connect(&env::var("DATABASE_URL").context("DATABASE_URL missing")?).await?;
    migrate(&db).await?;

    let geoip_reader = match env::var("GEOIP_DB_PATH") {
        Ok(path) => match Reader::open_readfile(path) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error = %e, "cannot open GEOIP DB, enrichment disabled");
                None
            }
        },
        Err(_) => {
            tracing::warn!("GEOIP_DB_PATH not set, enrichment disabled");
            None
        }
    };

    let c = consumer("phantomgrid-event-processor", &brokers, &["events.raw"])?;
    let p = producer(&brokers)?;

    loop {
        let msg = c.recv().await?;
        let Ok(raw) = parse_json::<RawEvent>(&msg) else {
            continue;
        };

        let enrichment = enrich_ip(raw.source_ip.as_str(), geoip_reader.as_ref());

        let enriched = EnrichedEvent {
            mitre_technique_ids: raw
                .tags
                .iter()
                .filter(|t| t.starts_with('T'))
                .cloned()
                .collect(),
            raw: raw.clone(),
            enrichment,
        };

        persist_event(&db, &enriched).await;
        update_decoy_interaction(&db, &raw).await;

        let _ = publish_json(
            &p,
            "events.enriched",
            &enriched.raw.event_id.to_string(),
            &enriched,
        )
        .await;
    }
}

fn enrich_ip(ip: &str, reader: Option<&Reader<Vec<u8>>>) -> Enrichment {
    let mut out = Enrichment::default();
    let Ok(parsed_ip) = ip.parse::<IpAddr>() else {
        return out;
    };

    if is_private_ip(parsed_ip) {
        return out;
    }

    let Some(reader) = reader else {
        return out;
    };

    let city = reader.lookup::<geoip2::City<'_>>(parsed_ip).ok();
    if let Some(city_data) = city {
        out.country = city_data
            .country
            .and_then(|c| c.iso_code)
            .map(|s| s.to_string());
        out.city = city_data
            .city
            .and_then(|c| c.names)
            .and_then(|names| names.get("en").map(|v| v.to_string()));
        out.lat = city_data.location.and_then(|l| l.latitude);
        out.lon = city_data.location.and_then(|l| l.longitude);
    }

    if let Ok(asn_data) = reader.lookup::<geoip2::Asn<'_>>(parsed_ip) {
        out.asn = asn_data.autonomous_system_number.map(|n| n.to_string());
        out.isp = asn_data
            .autonomous_system_organization
            .map(|s| s.to_string());
    }

    out
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private() ||
            v4.is_loopback() ||
            v4.is_link_local() ||
            v4 == Ipv4Addr::new(0, 0, 0, 0)
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unspecified(),
    }
}

async fn persist_event(db: &sqlx::PgPool, event: &EnrichedEvent) {
    let _ = sqlx::query(
        "INSERT INTO events (id, tenant_id, decoy_id, session_id, source_ip, source_port, protocol, event_type, severity, raw_data, enrichment, mitre_technique_ids, tags, destination_ip, destination_port, created_at)
         VALUES ($1, $2, $3, $4, $5::inet, $6, $7, $8, $9, $10, $11, $12, $13, $14::inet, $15, $16)"
    )
    .bind(event.raw.event_id)
    .bind(event.raw.tenant_id)
    .bind(event.raw.decoy_id)
    .bind(event.raw.session_id)
    .bind(Some(event.raw.source_ip.clone()))
    .bind(event.raw.source_port.map(i32::from))
    .bind(format!("{:?}", event.raw.protocol).to_uppercase())
    .bind(event.raw.event_type.clone())
    .bind(format!("{:?}", event.raw.severity).to_lowercase())
    .bind(event.raw.raw_data.clone())
    .bind(serde_json::to_value(&event.enrichment).unwrap_or_else(|_| serde_json::json!({})))
    .bind(event.mitre_technique_ids.clone())
    .bind(event.raw.tags.clone())
    .bind(event.raw.destination_ip.clone())
    .bind(event.raw.destination_port.map(i32::from))
    .bind(event.raw.timestamp)
    .execute(db)
    .await;
}

async fn update_decoy_interaction(db: &sqlx::PgPool, raw: &RawEvent) {
    if let Some(decoy_id) = raw.decoy_id {
        let _ = sqlx::query(
            "UPDATE decoys SET interaction_count = interaction_count + 1, last_interaction_at = NOW() WHERE id = $1"
        )
        .bind(decoy_id)
        .execute(db)
        .await;
    }
}
