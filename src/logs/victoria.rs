use super::http::BlockingHttp;
use super::normalize::{from_rfc3339_or_now, parse_alert_value, with_metadata};
use super::{LogClient, Result};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use std::collections::HashMap;
use tracing::{debug, info, warn, instrument};

pub struct VictoriaLogsClient {
    http: BlockingHttp,
}

impl VictoriaLogsClient {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: BlockingHttp::new(url)?,
        })
    }
}

impl LogClient for VictoriaLogsClient {
    #[instrument(skip(self), fields(query = %query, limit = %limit))]
    fn query_range(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Value>> {
        debug!("Querying VictoriaLogs");
        let body = self.http.get_bytes(
            "/select/logsql/query",
            &[
                ("query", query.to_string()),
                ("start", start.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                ("end", end.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                ("limit", limit.to_string()),
            ],
        )?;

        let mut alerts = Vec::new();
        let mut parse_errors = 0;

        for line in body.split(|&b| b == b'\n') {
            if line.is_empty() {
                continue;
            }

            let Ok(entry) = serde_json::from_slice::<Value>(line) else {
                parse_errors += 1;
                continue;
            };

            let msg = entry
                .get("_msg")
                .and_then(Value::as_str)
                .unwrap_or_default();

            let mut labels = Map::new();
            if let Some(obj) = entry.as_object() {
                for (k, v) in obj {
                    if !k.starts_with('_') {
                        labels.insert(k.clone(), v.clone());
                    }
                }
            }

            let ts = from_rfc3339_or_now(entry.get("_time").and_then(Value::as_str));
            let alert = parse_alert_value(msg);
            alerts.push(with_metadata(alert, labels, ts));
        }

        if parse_errors > 0 {
            warn!(parse_errors, "Failed to parse some log lines");
        }

        info!(count = alerts.len(), "VictoriaLogs query complete");
        Ok(alerts)
    }

    #[instrument(skip(self, labels, log_line))]
    fn push(
        &self,
        labels: &HashMap<String, String>,
        log_line: &str,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<()> {
        debug!("Pushing to VictoriaLogs");
        let mut entry = Map::new();
        entry.insert("_msg".to_string(), Value::String(log_line.to_string()));
        entry.insert(
            "_time".to_string(),
            Value::String(timestamp.unwrap_or_else(Utc::now).to_rfc3339()),
        );
        for (k, v) in labels {
            entry.insert(k.clone(), Value::String(v.clone()));
        }

        let result = self.http
            .post_ndjson_unit("/insert/jsonline", &format!("{}\n", Value::Object(entry)));

        if result.is_ok() {
            debug!("Successfully pushed to VictoriaLogs");
        }
        result
    }
}
