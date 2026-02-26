use super::{AnalyzerError, Result};
use chrono::Duration;
use serde_json::{Map, Value};
use std::collections::HashMap;

pub fn parse_last(last: &str) -> Result<Duration> {
    if last.len() < 2 {
        return Err(AnalyzerError::InvalidArgument(
            "last must look like 15m, 1h, 7d".to_string(),
        ));
    }

    let (num, unit) = last.split_at(last.len() - 1);
    let value = num
        .parse::<i64>()
        .map_err(|_| AnalyzerError::InvalidArgument(format!("invalid duration value: {num}")))?;

    if value <= 0 {
        return Err(AnalyzerError::InvalidArgument(
            "duration value must be greater than zero".to_string(),
        ));
    }

    match unit {
        "m" => Ok(Duration::minutes(value)),
        "h" => Ok(Duration::hours(value)),
        "d" => Ok(Duration::days(value)),
        _ => Err(AnalyzerError::InvalidArgument(format!(
            "invalid duration unit '{unit}', use m/h/d"
        ))),
    }
}

pub(super) fn value_to_string_map(obj: Option<&Map<String, Value>>) -> HashMap<String, String> {
    obj.map(|m| {
        m.iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str()
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| v.to_string()),
                )
            })
            .collect::<HashMap<_, _>>()
    })
    .unwrap_or_default()
}

pub(super) fn value_to_string_map_optional(v: Option<&Value>) -> Option<HashMap<String, String>> {
    v.and_then(Value::as_object).map(|m| {
        m.iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    v.as_str()
                        .map(ToOwned::to_owned)
                        .unwrap_or_else(|| v.to_string()),
                )
            })
            .collect::<HashMap<_, _>>()
    })
}
