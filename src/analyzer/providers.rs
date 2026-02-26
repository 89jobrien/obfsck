use super::{AnalyzerError, Result};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::time::Duration as StdDuration;

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
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
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
            .send()?
            .error_for_status()?;

        let value: Value = response.json()?;
        let content = value
            .get("message")
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AnalyzerError::ResponseParse(
                    "ollama response missing message.content string".to_string(),
                )
            })?;

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
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
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
            .send()?
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
                AnalyzerError::ResponseParse(
                    "openai response missing choices[0].message.content string".to_string(),
                )
            })?;

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
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<String> {
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
            .send()?
            .error_for_status()?;

        let value: Value = response.json()?;
        let content = value
            .get("content")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .and_then(|c| c.get("text"))
            .and_then(Value::as_str)
            .ok_or_else(|| {
                AnalyzerError::ResponseParse(
                    "anthropic response missing content[0].text string".to_string(),
                )
            })?;

        Ok(content.to_string())
    }
}
