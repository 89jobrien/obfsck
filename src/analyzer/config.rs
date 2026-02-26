use super::{AnalyzerError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use std::fs;
use std::path::Path;
use tracing::{debug, warn, instrument};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_obfuscation_level")]
    pub obfuscation_level: String,
    #[serde(default = "default_provider")]
    pub provider: String,
    #[serde(default)]
    pub ollama: OllamaConfig,
    #[serde(default)]
    pub openai: OpenAiConfig,
    #[serde(default)]
    pub anthropic: AnthropicConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default = "default_backend")]
    pub backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LokiConfig {
    #[serde(default = "default_loki_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VictoriaLogsConfig {
    #[serde(default = "default_vm_url")]
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OllamaConfig {
    #[serde(default = "default_ollama_url")]
    pub url: String,
    #[serde(default = "default_ollama_model")]
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OpenAiConfig {
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_openai_model")]
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnthropicConfig {
    #[serde(default)]
    pub api_key: String,
    #[serde(default = "default_anthropic_model")]
    pub model: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AnalyzerConfig {
    #[serde(default)]
    pub analysis: AnalysisConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub loki: LokiConfig,
    #[serde(default)]
    pub victorialogs: VictoriaLogsConfig,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            obfuscation_level: default_obfuscation_level(),
            provider: default_provider(),
            ollama: OllamaConfig::default(),
            openai: OpenAiConfig::default(),
            anthropic: AnthropicConfig::default(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            backend: default_backend(),
        }
    }
}

impl Default for LokiConfig {
    fn default() -> Self {
        Self {
            url: default_loki_url(),
        }
    }
}

impl Default for VictoriaLogsConfig {
    fn default() -> Self {
        Self {
            url: default_vm_url(),
        }
    }
}

impl Default for OllamaConfig {
    fn default() -> Self {
        Self {
            url: default_ollama_url(),
            model: default_ollama_model(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_provider() -> String {
    "ollama".to_string()
}

fn default_obfuscation_level() -> String {
    "standard".to_string()
}

fn default_backend() -> String {
    env::var("STACK").unwrap_or_else(|_| "loki".to_string())
}

fn default_loki_url() -> String {
    "http://localhost:3100".to_string()
}

fn default_vm_url() -> String {
    "http://localhost:9428".to_string()
}

fn default_ollama_url() -> String {
    "http://localhost:11434".to_string()
}

fn default_ollama_model() -> String {
    "llama3.1:8b".to_string()
}

fn default_openai_model() -> String {
    "gpt-4o-mini".to_string()
}

fn default_anthropic_model() -> String {
    "claude-3-haiku-20240307".to_string()
}

#[instrument(fields(config_path = ?config_path))]
pub fn load_config(config_path: Option<&str>) -> Result<AnalyzerConfig> {
    let mut raw = None;

    if let Some(path) = config_path {
        if Path::new(path).exists() {
            debug!(path = %path, "Loading config from specified path");
            raw = Some(fs::read_to_string(path)?);
        } else {
            warn!(path = %path, "Config file not found");
            return Err(AnalyzerError::InvalidArgument(format!(
                "config file not found: {path}"
            )));
        }
    } else {
        let default_paths = [
            "config.yaml".to_string(),
            format!(
                "{}/.config/sib/analysis.yaml",
                env::var("HOME").unwrap_or_default()
            ),
            "/etc/sib/analysis.yaml".to_string(),
        ];

        for path in default_paths {
            if Path::new(&path).exists() {
                debug!(path = %path, "Found config at default path");
                raw = Some(fs::read_to_string(path)?);
                break;
            }
        }
    }

    let mut cfg = if let Some(text) = raw {
        let mut value: Value = serde_yaml::from_str::<Value>(&text)?;
        expand_env_in_value(&mut value);
        serde_json::from_value::<AnalyzerConfig>(value)?
    } else {
        AnalyzerConfig::default()
    };

    cfg.storage.backend = expand_env_string(&cfg.storage.backend);
    cfg.analysis.openai.api_key = expand_env_string(&cfg.analysis.openai.api_key);
    cfg.analysis.anthropic.api_key = expand_env_string(&cfg.analysis.anthropic.api_key);

    Ok(cfg)
}

fn read_secret(env_var: &str) -> Option<String> {
    let file_var = format!("{env_var}_FILE");
    if let Ok(file_path) = env::var(&file_var) {
        if let Ok(meta) = fs::metadata(&file_path)
            && meta.len() > 65_536
        {
            warn!(path = %file_path, size = meta.len(), "Secret file too large (>64KB), skipping");
            return None;
        }
        if let Ok(content) = fs::read_to_string(&file_path) {
            return Some(content.trim().to_string());
        } else {
            warn!(path = %file_path, "Failed to read secret file");
        }
    }

    env::var(env_var).ok()
}

pub(super) fn expand_env_string(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;

    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];

        if let Some(end_rel) = after_start.find('}') {
            let token = &after_start[..end_rel];
            let (var, default) = if let Some(idx) = token.find(":-") {
                (&token[..idx], &token[idx + 2..])
            } else {
                (token, "")
            };

            let value = match var {
                "ANTHROPIC_API_KEY"
                | "OPENAI_API_KEY"
                | "OLLAMA_API_KEY"
                | "GRAFANA_ADMIN_PASSWORD" => {
                    read_secret(var).unwrap_or_else(|| default.to_string())
                }
                _ => env::var(var).unwrap_or_else(|_| default.to_string()),
            };
            out.push_str(&value);
            rest = &after_start[end_rel + 1..];
        } else {
            out.push_str("${");
            out.push_str(after_start);
            rest = "";
        }
    }

    out.push_str(rest);
    out
}

fn expand_env_in_value(v: &mut Value) {
    match v {
        Value::Object(map) => {
            for value in map.values_mut() {
                expand_env_in_value(value);
            }
        }
        Value::Array(arr) => {
            for value in arr {
                expand_env_in_value(value);
            }
        }
        Value::String(s) => {
            *s = expand_env_string(s);
        }
        _ => {}
    }
}
