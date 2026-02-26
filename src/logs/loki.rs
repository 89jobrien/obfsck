use super::http::BlockingHttp;
use super::normalize::{from_loki_timestamp_ns, parse_alert_value, with_metadata};
use super::{LogClient, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use tracing::{debug, info, instrument};

pub struct LokiClient {
    http: BlockingHttp,
}

#[derive(Debug, Deserialize)]
struct LokiQueryResponse {
    #[serde(default)]
    data: LokiQueryData,
}

#[derive(Debug, Default, Deserialize)]
struct LokiQueryData {
    #[serde(default)]
    result: Vec<LokiStreamResult>,
}

#[derive(Debug, Default, Deserialize)]
struct LokiStreamResult {
    #[serde(default)]
    stream: Map<String, Value>,
    #[serde(default)]
    values: Vec<Vec<String>>,
}

impl LokiClient {
    pub fn new(url: impl Into<String>) -> Result<Self> {
        Ok(Self {
            http: BlockingHttp::new(url)?,
        })
    }
}

impl LogClient for LokiClient {
    #[instrument(skip(self), fields(query = %query, limit = %limit))]
    fn query_range(
        &self,
        query: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        limit: usize,
    ) -> Result<Vec<Value>> {
        debug!("Querying Loki");
        let data: LokiQueryResponse = self.http.get_json(
            "/loki/api/v1/query_range",
            &[
                ("query", query.to_string()),
                (
                    "start",
                    start.timestamp_nanos_opt().unwrap_or(0).to_string(),
                ),
                ("end", end.timestamp_nanos_opt().unwrap_or(0).to_string()),
                ("limit", limit.to_string()),
            ],
        )?;

        let mut alerts = Vec::new();
        for stream in data.data.result {
            for pair in stream.values {
                if pair.len() != 2 {
                    continue;
                }

                let log_line = &pair[1];
                let alert = parse_alert_value(log_line);
                let ts = from_loki_timestamp_ns(&pair[0]);
                alerts.push(with_metadata(alert, stream.stream.clone(), ts));
            }
        }

        info!(count = alerts.len(), "Loki query complete");
        Ok(alerts)
    }

    #[instrument(skip(self, labels, log_line))]
    fn push(
        &self,
        labels: &HashMap<String, String>,
        log_line: &str,
        timestamp: Option<DateTime<Utc>>,
    ) -> Result<()> {
        debug!("Pushing to Loki");
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

        let result = self.http.post_json_unit("/loki/api/v1/push", &payload);
        if result.is_ok() {
            debug!("Successfully pushed to Loki");
        }
        result
    }
}
