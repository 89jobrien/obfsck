use crate::analyzer::AnalyzerError;
use chrono::{DateTime, Utc};
use reqwest::blocking::Client;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::time::Duration as StdDuration;

type Result<T> = std::result::Result<T, AnalyzerError>;

pub trait LogClient {
    fn query_range(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Value>>;

    fn push(
        &self,
        labels: &HashMap<String, String>,
        log_line: &str,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<()>;
}

pub struct LokiClient {
    url: String,
    client: Client,
}

impl LokiClient {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(60))
            .build()?;
        Ok(Self {
            url: url.into().trim_end_matches('/').to_string(),
            client,
        })
    }
}

impl LogClient for LokiClient {
    fn query_range(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let response = self
            .client
            .get(format!("{}/loki/api/v1/query_range", self.url))
            .query(&[
                ("query", query.to_string()),
                (
                    "start",
                    (start.timestamp_nanos_opt().unwrap_or(0)).to_string(),
                ),
                ("end", (end.timestamp_nanos_opt().unwrap_or(0)).to_string()),
                ("limit", limit.to_string()),
            ])
            .send()?
            .error_for_status()?;

        let data: Value = response.json()?;
        let mut alerts = Vec::new();

        for stream in data
            .get("data")
            .and_then(|d| d.get("result"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
        {
            let labels = stream
                .get("stream")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();

            for value in stream
                .get("values")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
            {
                let pair = value.as_array().cloned().unwrap_or_default();
                if pair.len() != 2 {
                    continue;
                }

                let timestamp_ns = pair[0].as_str().unwrap_or("0").parse::<i64>().unwrap_or(0);
                let log_line = pair[1].as_str().unwrap_or_default();

                let mut alert = serde_json::from_str::<Value>(log_line)
                    .unwrap_or_else(|_| json!({ "output": log_line }));

                if let Some(obj) = alert.as_object_mut() {
                    obj.insert("_labels".to_string(), Value::Object(labels.clone()));
                    let ts = DateTime::<Utc>::from_timestamp_micros(timestamp_ns / 1_000)
                        .unwrap_or_else(Utc::now)
                        .to_rfc3339();
                    obj.insert("_timestamp".to_string(), Value::String(ts));
                }

                alerts.push(alert);
            }
        }

        Ok(alerts)
    }

    fn push(
        &self,
        labels: &HashMap<String, String>,
        log_line: &str,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let ts_ns = timestamp
            .unwrap_or_else(Utc::now)
            .timestamp_nanos_opt()
            .unwrap_or(0)
            .to_string();

        let payload = json!({
            "streams": [{
                "stream": labels,
                "values": [[ts_ns, log_line]]
            }]
        });

        self.client
            .post(format!("{}/loki/api/v1/push", self.url))
            .json(&payload)
            .send()?
            .error_for_status()?;

        Ok(())
    }
}

pub struct VictoriaLogsClient {
    url: String,
    client: Client,
}

impl VictoriaLogsClient {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(StdDuration::from_secs(5))
            .timeout(StdDuration::from_secs(60))
            .build()?;
        Ok(Self {
            url: url.into().trim_end_matches('/').to_string(),
            client,
        })
    }
}

impl LogClient for VictoriaLogsClient {
    fn query_range(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Value>> {
        let response = self
            .client
            .get(format!("{}/select/logsql/query", self.url))
            .query(&[
                ("query", query.to_string()),
                ("start", start.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                ("end", end.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                ("limit", limit.to_string()),
            ])
            .send()?
            .error_for_status()?;

        let body = response.text()?;
        let mut alerts = Vec::new();

        for line in body.lines() {
            if line.trim().is_empty() {
                continue;
            }

            let Ok(entry) = serde_json::from_str::<Value>(line) else {
                continue;
            };

            let msg = entry
                .get("_msg")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let mut alert =
                serde_json::from_str::<Value>(msg).unwrap_or_else(|_| json!({ "output": msg }));

            let mut labels = Map::new();
            if let Some(obj) = entry.as_object() {
                for (k, v) in obj {
                    if !k.starts_with('_') {
                        labels.insert(k.clone(), v.clone());
                    }
                }
            }

            let ts = entry
                .get("_time")
                .and_then(Value::as_str)
                .and_then(|s| {
                    DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|d| d.with_timezone(&Utc))
                })
                .unwrap_or_else(Utc::now);

            if let Some(obj) = alert.as_object_mut() {
                obj.insert("_labels".to_string(), Value::Object(labels));
                obj.insert("_timestamp".to_string(), Value::String(ts.to_rfc3339()));
            }

            alerts.push(alert);
        }

        Ok(alerts)
    }

    fn push(
        &self,
        labels: &HashMap<String, String>,
        log_line: &str,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let mut entry = Map::new();
        entry.insert("_msg".to_string(), Value::String(log_line.to_string()));
        entry.insert(
            "_time".to_string(),
            Value::String(timestamp.unwrap_or_else(Utc::now).to_rfc3339()),
        );
        for (k, v) in labels {
            entry.insert(k.clone(), Value::String(v.clone()));
        }

        self.client
            .post(format!("{}/insert/jsonline", self.url))
            .header("Content-Type", "application/stream+x-ndjson")
            .body(format!("{}\n", Value::Object(entry)))
            .send()?
            .error_for_status()?;

        Ok(())
    }
}
