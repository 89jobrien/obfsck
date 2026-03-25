use super::Result;
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration as StdDuration;
use tracing::{error, instrument};

const CONNECT_TIMEOUT_SECS: u64 = 5;
const REQUEST_TIMEOUT_SECS: u64 = 60;

pub(super) struct BlockingHttp {
    base_url: String,
    client: Client,
}

impl BlockingHttp {
    pub(super) fn new(url: impl Into<String>) -> Result<Self> {
        let client = Client::builder()
            .connect_timeout(StdDuration::from_secs(CONNECT_TIMEOUT_SECS))
            .timeout(StdDuration::from_secs(REQUEST_TIMEOUT_SECS))
            .build()?;
        Ok(Self {
            base_url: url.into().trim_end_matches('/').to_string(),
            client,
        })
    }

    #[instrument(skip(self), fields(url = %format!("{}{}", self.base_url, path)))]
    pub(super) fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(&url)
            .query(query)
            .send()
            .map_err(|e| {
                error!(error = %e, "HTTP request failed");
                e
            })?
            .error_for_status()
            .inspect_err(|e| {
                error!(status = ?e.status(), "HTTP error status");
            })?;

        response.json().map_err(|e| {
            error!(error = %e, "JSON deserialization failed");
            e.into()
        })
    }

    #[instrument(skip(self), fields(url = %format!("{}{}", self.base_url, path)))]
    pub(super) fn get_bytes(&self, path: &str, query: &[(&str, String)]) -> Result<Vec<u8>> {
        let url = format!("{}{}", self.base_url, path);
        let response = self
            .client
            .get(&url)
            .query(query)
            .send()
            .map_err(|e| {
                error!(error = %e, "HTTP request failed");
                e
            })?
            .error_for_status()
            .inspect_err(|e| {
                error!(status = ?e.status(), "HTTP error status");
            })?;

        Ok(response.bytes()?.to_vec())
    }

    #[instrument(skip(self, payload), fields(url = %format!("{}{}", self.base_url, path)))]
    pub(super) fn post_json_unit(&self, path: &str, payload: &Value) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .json(payload)
            .send()
            .map_err(|e| {
                error!(error = %e, "HTTP request failed");
                e
            })?
            .error_for_status()
            .inspect_err(|e| {
                error!(status = ?e.status(), "HTTP error status");
            })?;
        Ok(())
    }

    #[instrument(skip(self, body), fields(url = %format!("{}{}", self.base_url, path), body_len = body.len()))]
    pub(super) fn post_ndjson_unit(&self, path: &str, body: &str) -> Result<()> {
        let url = format!("{}{}", self.base_url, path);
        self.client
            .post(&url)
            .header("Content-Type", "application/stream+x-ndjson")
            .body(body.to_string())
            .send()
            .map_err(|e| {
                error!(error = %e, "HTTP request failed");
                e
            })?
            .error_for_status()
            .inspect_err(|e| {
                error!(status = ?e.status(), "HTTP error status");
            })?;
        Ok(())
    }
}
