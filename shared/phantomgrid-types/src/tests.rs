use super::*;

#[test]
fn test_event_serialization_roundtrip() {
    let e = RawEvent {
        event_id: Uuid::new_v4(),
        timestamp: chrono::Utc::now(),
        tenant_id: Uuid::new_v4(),
        decoy_id: Uuid::new_v4(),
        decoy_type: "ssh_honeypot".into(),
        source_ip: "1.2.3.4".into(),
        source_port: 12345,
        destination_ip: "10.0.0.1".into(),
        destination_port: 22,
        protocol: "SSH".into(),
        session_id: Uuid::new_v4(),
        raw_data: serde_json::json!({"k":"v"}),
        severity: "high".into(),
        tags: vec!["probe".into()],
    };

    let s = serde_json::to_string(&e).expect("serialize");
    let back: RawEvent = serde_json::from_str(&s).expect("deserialize");
    assert_eq!(back.protocol, "SSH");
}

#[test]
fn test_alert_severity_ordering() {
    fn rank(s: &str) -> i32 {
        match s {
            "critical" => 4,
            "high" => 3,
            "medium" => 2,
            "low" => 1,
            _ => 0,
        }
    }

    assert!(rank("critical") > rank("high"));
    assert!(rank("high") > rank("medium"));
}
