use phantomgrid_types::event::EnrichedEvent;

pub fn matches(event: &EnrichedEvent, config: &serde_json::Value) -> bool {
    let expected_protocol = config
        .get("match")
        .and_then(|m| m.get("protocol"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_uppercase();

    if expected_protocol.is_empty() {
        return false;
    }

    format!("{:?}", event.raw.protocol).to_uppercase() == expected_protocol
}
