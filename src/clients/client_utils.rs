use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

pub(super) fn parse_alert_value(raw: &str) -> Value {
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        return value;
    }

    if let Some(candidate) = extract_json_object(raw)
        && let Ok(value) = serde_json::from_str::<Value>(candidate)
    {
        return value;
    }

    json!({ "output": raw })
}

pub(super) fn with_metadata(
    mut alert: Value,
    labels: Map<String, Value>,
    ts: DateTime<Utc>,
) -> Value {
    if let Some(obj) = alert.as_object_mut() {
        obj.insert("_labels".to_string(), Value::Object(labels));
        obj.insert("_timestamp".to_string(), Value::String(ts.to_rfc3339()));
    }
    alert
}

pub(super) fn from_loki_timestamp_ns(nanos_str: &str) -> DateTime<Utc> {
    let timestamp_ns = nanos_str.parse::<i64>().unwrap_or(0);
    DateTime::<Utc>::from_timestamp_micros(timestamp_ns / 1_000).unwrap_or_else(Utc::now)
}

pub(super) fn from_rfc3339_or_now(value: Option<&str>) -> DateTime<Utc> {
    value
        .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
        .map(|d| d.with_timezone(&Utc))
        .unwrap_or_else(Utc::now)
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (start < end).then_some(&raw[start..=end])
}
