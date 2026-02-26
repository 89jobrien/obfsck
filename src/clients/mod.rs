use crate::analyzer::AnalyzerError;
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::collections::HashMap;

mod client_utils;
mod http;
mod loki;
mod victoria;

pub use loki::LokiClient;
pub use victoria::VictoriaLogsClient;

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
