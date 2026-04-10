use phantomgrid_types::event::EnrichedEvent;
use redis::AsyncCommands;

pub async fn matches(
    redis_client: &redis::Client,
    rule_id: uuid::Uuid,
    event: &EnrichedEvent,
    config: &serde_json::Value,
) -> bool {
    let threshold = config.get("threshold").and_then(|v| v.as_i64()).unwrap_or(5);
    let window_seconds = config
        .get("window_seconds")
        .and_then(|v| v.as_i64())
        .unwrap_or(60);
    let group_by = config
        .get("group_by")
        .and_then(|v| v.as_str())
        .unwrap_or("source_ip");

    let group_value = if group_by == "source_ip" {
        event.raw.source_ip.clone()
    } else {
        event.raw.source_ip.clone()
    };

    let key = format!("rl:{}:{}", rule_id, group_value);
    let now = chrono::Utc::now().timestamp();
    let min_score = now - window_seconds;

    let mut con = match redis_client.get_multiplexed_async_connection().await {
        Ok(c) => c,
        Err(_) => return false,
    };

    let _ = redis::cmd("ZADD")
        .arg(&key)
        .arg(now)
        .arg(event.raw.event_id.to_string())
        .query_async::<_, ()>(&mut con)
        .await;

    let _ = redis::cmd("ZREMRANGEBYSCORE")
        .arg(&key)
        .arg(0)
        .arg(min_score)
        .query_async::<_, ()>(&mut con)
        .await;

    let _ = redis::cmd("EXPIRE")
        .arg(&key)
        .arg(window_seconds.max(30))
        .query_async::<_, ()>(&mut con)
        .await;

    let count = redis::cmd("ZCARD")
        .arg(&key)
        .query_async::<_, i64>(&mut con)
        .await
        .unwrap_or(0);

    count >= threshold
}
