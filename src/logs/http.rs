use super::Result;
use reqwest::blocking::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::time::Duration as StdDuration;

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

    pub(super) fn get_json<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<T> {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .query(query)
            .send()?
            .error_for_status()?;
        Ok(response.json()?)
    }

    pub(super) fn get_bytes(&self, path: &str, query: &[(&str, String)]) -> Result<Vec<u8>> {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .query(query)
            .send()?
            .error_for_status()?;
        Ok(response.bytes()?.to_vec())
    }

    pub(super) fn post_json_unit(&self, path: &str, payload: &Value) -> Result<()> {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .json(payload)
            .send()?
            .error_for_status()?;
        Ok(())
    }

    pub(super) fn post_ndjson_unit(&self, path: &str, body: &str) -> Result<()> {
        self.client
            .post(format!("{}{}", self.base_url, path))
            .header("Content-Type", "application/stream+x-ndjson")
            .body(body.to_string())
            .send()?
            .error_for_status()?;
        Ok(())
    }
}
