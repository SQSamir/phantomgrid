use phantomgrid_types::event::EnrichedEvent;

pub async fn matches(
    redis_client: &redis::Client,
    event: &EnrichedEvent,
    config: &serde_json::Value,
) -> bool {
    let min_decoys = config.get("min_decoys").and_then(|v| v.as_i64()).unwrap_or(3);
    let window_seconds = config
        .get("window_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(300);

    let Some(decoy_id) = event.raw.decoy_id else {
        return false;
    };

    let key = format!("decoys:{}", event.raw.source_ip);
    let mut con = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return false,
    };

    let _ = redis::cmd("SADD")
        .arg(&key)
        .arg(decoy_id.to_string())
        .query_async::<()>(&mut con)
        .await;

    let _ = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(window_seconds.max(60))
        .query_async::<()>(&mut con)
        .await;

    let cardinality = redis::cmd("SCARD")
        .arg(&key)
        .query_async::<i64>(&mut con)
        .await
        .unwrap_or(0);

    cardinality >= min_decoys
}
