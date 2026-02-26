use super::{AnalyzerError, Result};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::time::Duration as StdDuration;
use tracing::{error, info, instrument};

pub(super) trait LlmProvider {
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<String>;
}

pub(super) struct OllamaProvider {
    url: String,
    model: String,
    client: Client,
}

impl OllamaProvider {
    pub(super) fn new(url: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Ok(Self {
            url: url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            client: Client::builder()
                .timeout(StdDuration::from_secs(120))
                .build()?,
        })
    }
}

impl LlmProvider for OllamaProvider {
    #[instrument(skip(self, system_prompt, user_prompt), fields(
        provider = "ollama",
        model = %self.model,
        prompt_len = user_prompt.len()
    ))]
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let start = std::time::Instant::now();
        let response = self
            .client
            .post(format!("{}/api/chat", self.url))
            .json(&json!({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "stream": false,
                "format": "json"
            }))
            .send()
            .map_err(|e| {
                error!(error = %e, "LLM request failed");
                e
            })?
            .error_for_status()?;

        let value: Value = response.json()?;
        let content = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                error!("Ollama response missing message.content");
                AnalyzerError::ResponseParse(
                    "ollama response missing message.content string".to_string(),
                )
            })?;

        let duration = start.elapsed();
        info!(duration_ms = duration.as_millis(), "LLM request completed");

        Ok(content.to_string())
    }
}

pub(super) struct OpenAiProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl OpenAiProvider {
    pub(super) fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Ok(Self {
            api_key: api_key.into(),
            model: model.into(),
            client: Client::builder()
                .timeout(StdDuration::from_secs(60))
                .build()?,
        })
    }
}

impl LlmProvider for OpenAiProvider {
    #[instrument(skip(self, system_prompt, user_prompt), fields(
        provider = "openai",
        model = %self.model,
        prompt_len = user_prompt.len()
    ))]
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let start = std::time::Instant::now();
        let response = self
            .client
            .post("https://api.openai.com/v1/chat/completions")
            .bearer_auth(&self.api_key)
            .json(&json!({
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "response_format": {"type": "json_object"}
            }))
            .send()
            .map_err(|e| {
                error!(error = %e, "LLM request failed");
                e
            })?
            .error_for_status()?;

        let value: Value = response.json()?;
        let content = value
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                error!("OpenAI response missing choices[0].message.content");
                AnalyzerError::ResponseParse(
                    "openai response missing choices[0].message.content string".to_string(),
                )
            })?;

        let duration = start.elapsed();
        info!(duration_ms = duration.as_millis(), "LLM request completed");

        Ok(content.to_string())
    }
}

pub(super) struct AnthropicProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl AnthropicProvider {
    pub(super) fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Ok(Self {
            api_key: api_key.into(),
            model: model.into(),
            client: Client::builder()
                .timeout(StdDuration::from_secs(60))
                .build()?,
        })
    }
}

impl LlmProvider for AnthropicProvider {
    #[instrument(skip(self, system_prompt, user_prompt), fields(
        provider = "anthropic",
        model = %self.model,
        prompt_len = user_prompt.len()
    ))]
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
        let start = std::time::Instant::now();
        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", "2023-06-01")
            .json(&json!({
                "model": self.model,
                "max_tokens": 4096,
                "system": system_prompt,
                "messages": [{"role": "user", "content": user_prompt}]
            }))
            .send()
            .map_err(|e| {
                error!(error = %e, "LLM request failed");
                e
            })?
            .error_for_status()?;

        let value: Value = response.json()?;
        let content = value
            .get("content")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|c| c.get("text"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                error!("Anthropic response missing content[0].text");
                AnalyzerError::ResponseParse(
                    "anthropic response missing content[0].text string".to_string(),
                )
            })?;

        let duration = start.elapsed();
        info!(duration_ms = duration.as_millis(), "LLM request completed");

        Ok(content.to_string())
    }
}
