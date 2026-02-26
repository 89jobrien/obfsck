use crate::log_agents::{LogClient, LokiClient, VictoriaLogsClient};
use crate::{ObfuscationLevel, obfuscate_alert};
use chrono::{DateTime, Duration, Utc};
use clap::Parser;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::time::Duration as StdDuration;
use thiserror::Error;

pub const SYSTEM_PROMPT: &str = r#"You are a senior security analyst and incident responder with deep expertise in:
- Container security and Kubernetes
- Linux system internals and syscalls
- MITRE ATT&CK framework
- Threat hunting and forensics
- Defensive security and hardening

You are analyzing security alerts from Falco, a runtime security tool that monitors system calls and container activity. Your role is to help security teams understand and respond to potential threats.

IMPORTANT CONTEXT:
- All personally identifiable information has been obfuscated (IPs, hostnames, usernames, etc.)
- Tokens like [USER-1], [HOST-1], [IP-EXTERNAL-1], [IP-INTERNAL-1] represent redacted values
- Focus on BEHAVIOR and PATTERNS, not specific redacted values
- Alerts are from production systems and should be treated seriously

For each alert, provide:
1) ATTACK VECTOR: What the attacker is likely trying to accomplish.
2) MITRE ATT&CK MAPPING: Tactic + technique ID/name + sub-technique when applicable.
3) RISK ASSESSMENT: Severity (Critical/High/Medium/Low), confidence (High/Medium/Low), and impact.
4) INDICATORS TO INVESTIGATE: Related activity, logs, artifacts, and validation checks.
5) MITIGATION STRATEGIES: Immediate containment, short-term prevention, long-term hardening.
6) FALSE POSITIVE ASSESSMENT: Common benign causes and distinguishing factors.

Respond in strict JSON with these exact keys and shape:
{
  "attack_vector": "string",
  "mitre_attack": {
    "tactic": "string",
    "technique_id": "string",
    "technique_name": "string",
    "sub_technique": "string or null"
  },
  "risk": {
    "severity": "Critical|High|Medium|Low",
    "confidence": "High|Medium|Low",
    "impact": "string"
  },
  "investigate": ["string"],
  "mitigations": {
    "immediate": ["string"],
    "short_term": ["string"],
    "long_term": ["string"]
  },
  "false_positive": {
    "likelihood": "High|Medium|Low",
    "common_causes": ["string"],
    "distinguishing_factors": ["string"]
  },
  "summary": "string"
}

Do not include markdown, commentary, or prose outside JSON. Be concise but actionable."#;

pub const USER_PROMPT_TEMPLATE: &str = r#"Analyze this security alert.

Rule: {rule_name}
Priority: {priority}
Timestamp: {timestamp}
Source: {source}

Alert details:
{obfuscated_output}

Additional context:
- container_image: {container_image}
- syscall: {syscall}
- process: {process}
- parent_process: {parent_process}

Return only strict JSON matching the required schema."#;

pub fn mitre_mapping() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        (
            "Read sensitive file untrusted",
            "Credential Access / T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow",
        ),
        (
            "Write below etc",
            "Persistence / T1543 Create or Modify System Process",
        ),
        (
            "Terminal shell in container",
            "Execution / T1059.004 Command and Scripting Interpreter: Unix Shell",
        ),
        (
            "Write below binary dir",
            "Persistence / T1543 Create or Modify System Process",
        ),
        (
            "Container Running as Root",
            "Privilege Escalation / T1611 Escape to Host",
        ),
        (
            "Outbound Connection to Suspicious Port",
            "Command and Control / T1571 Non-Standard Port",
        ),
        (
            "Outbound connection",
            "Command and Control / T1071 Application Layer Protocol",
        ),
        (
            "Reverse Shell Spawned",
            "Execution / T1059.004 Command and Scripting Interpreter: Unix Shell",
        ),
        (
            "Crypto Mining Activity",
            "Impact / T1496 Resource Hijacking",
        ),
        (
            "Package management process launched",
            "Execution / T1072 Software Deployment Tools",
        ),
        (
            "Clear log activities",
            "Defense Evasion / T1070.002 Indicator Removal: Clear Linux or Mac System Logs",
        ),
        (
            "Data Exfiltration via Curl",
            "Exfiltration / T1048 Exfiltration Over Alternative Protocol",
        ),
    ])
}

#[derive(Debug, Error)]
pub enum AnalyzerError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("yaml error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("response parse error: {0}")]
    ResponseParse(String),
}

type Result<T> = std::result::Result<T, AnalyzerError>;

pub trait LlmProvider {
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<Value>;
}

pub struct OllamaProvider {
    url: String,
    model: String,
    client: Client,
}

impl OllamaProvider {
    pub fn new(url: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Ok(Self {
            url: url.into().trim_end_matches('/').to_string(),
            model: model.into(),
            client: Client::builder().timeout(StdDuration::from_secs(120)).build()?,
        })
    }
}

impl LlmProvider for OllamaProvider {
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<Value> {
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

        serde_json::from_str(content).map_err(AnalyzerError::from)
    }
}

pub struct OpenAiProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl OpenAiProvider {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Ok(Self {
            api_key: api_key.into(),
            model: model.into(),
            client: Client::builder().timeout(StdDuration::from_secs(60)).build()?,
        })
    }
}

impl LlmProvider for OpenAiProvider {
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<Value> {
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

        serde_json::from_str(content).map_err(AnalyzerError::from)
    }
}

pub struct AnthropicProvider {
    api_key: String,
    model: String,
    client: Client,
}

impl AnthropicProvider {
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Result<Self> {
        Ok(Self {
            api_key: api_key.into(),
            model: model.into(),
            client: Client::builder().timeout(StdDuration::from_secs(60)).build()?,
        })
    }
}

impl LlmProvider for AnthropicProvider {
    fn analyze(&self, system_prompt: &str, user_prompt: &str) -> Result<Value> {
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

        if let Ok(json_obj) = serde_json::from_str::<Value>(content) {
            return Ok(json_obj);
        }

        if let Some(start) = content.find('{')
            && let Some(end) = content.rfind('}')
        {
            let maybe_json = &content[start..=end];
            if let Ok(json_obj) = serde_json::from_str::<Value>(maybe_json) {
                return Ok(json_obj);
            }
        }

        Err(AnalyzerError::ResponseParse(
            "anthropic response did not contain valid JSON".to_string(),
        ))
    }
}

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

pub struct AlertAnalyzer {
    backend: String,
    log_client: Box<dyn LogClient>,
    obfuscation_level: ObfuscationLevel,
    provider: Box<dyn LlmProvider>,
}

impl AlertAnalyzer {
    pub fn from_config(config: &AnalyzerConfig) -> Result<Self> {
        let backend_raw = config.storage.backend.to_ascii_lowercase();
        let (backend, log_client): (String, Box<dyn LogClient>) = match backend_raw.as_str() {
            "victorialogs" | "vm" => (
                "victorialogs".to_string(),
                Box::new(VictoriaLogsClient::new(config.victorialogs.url.clone())?),
            ),
            _ => (
                "loki".to_string(),
                Box::new(LokiClient::new(config.loki.url.clone())?),
            ),
        };

        let obfuscation_level =
            ObfuscationLevel::parse(&config.analysis.obfuscation_level).ok_or_else(|| {
                AnalyzerError::InvalidConfig(format!(
                    "unknown obfuscation level: {}",
                    config.analysis.obfuscation_level
                ))
            })?;

        let provider: Box<dyn LlmProvider> = match config.analysis.provider.as_str() {
            "ollama" => Box::new(OllamaProvider::new(
                config.analysis.ollama.url.clone(),
                config.analysis.ollama.model.clone(),
            )?),
            "openai" => {
                let key = expand_env_string(&config.analysis.openai.api_key);
                Box::new(OpenAiProvider::new(key, config.analysis.openai.model.clone())?)
            }
            "anthropic" => {
                let key = expand_env_string(&config.analysis.anthropic.api_key);
                Box::new(AnthropicProvider::new(
                    key,
                    config.analysis.anthropic.model.clone(),
                )?)
            }
            other => {
                return Err(AnalyzerError::InvalidConfig(format!(
                    "unknown provider: {other}"
                )));
            }
        };

        Ok(Self {
            backend,
            log_client,
            obfuscation_level,
            provider,
        })
    }

    pub fn fetch_alerts(&self, priority: Option<&str>, last: &str, limit: usize) -> Result<Vec<Value>> {
        let delta = parse_last(last)?;
        let end = Utc::now();
        let start = end - delta;

        let query = if self.backend == "victorialogs" {
            if let Some(p) = priority {
                format!("source:syscall AND priority:{p}")
            } else {
                "source:syscall".to_string()
            }
        } else if let Some(p) = priority {
            format!("{{source=\"syscall\", priority=\"{p}\"}}")
        } else {
            "{source=\"syscall\"}".to_string()
        };

        self.log_client.query_range(&query, start, end, limit)
    }

    pub fn analyze_alert(&self, alert: &Value, dry_run: bool) -> Value {
        let labels = value_to_string_map(alert.get("_labels").and_then(Value::as_object));
        let output = alert.get("output").and_then(Value::as_str);
        let output_fields = value_to_string_map_optional(alert.get("output_fields"));

        let (obf_output, obf_fields, mapping) =
            obfuscate_alert(output, output_fields.as_ref(), self.obfuscation_level);

        let obf_alert = json!({
            "output": obf_output,
            "output_fields": obf_fields,
        });

        let user_prompt = USER_PROMPT_TEMPLATE
            .replace("{rule_name}", labels.get("rule").map(String::as_str).unwrap_or("Unknown"))
            .replace("{priority}", labels.get("priority").map(String::as_str).unwrap_or("Unknown"))
            .replace(
                "{timestamp}",
                alert
                    .get("_timestamp")
                    .and_then(Value::as_str)
                    .unwrap_or("Unknown"),
            )
            .replace("{source}", labels.get("source").map(String::as_str).unwrap_or("syscall"))
            .replace(
                "{obfuscated_output}",
                obf_output.as_deref().unwrap_or_default(),
            )
            .replace(
                "{container_image}",
                obf_fields
                    .as_ref()
                    .and_then(|m| m.get("container.image.repository"))
                    .map(String::as_str)
                    .unwrap_or("N/A"),
            )
            .replace(
                "{syscall}",
                obf_fields
                    .as_ref()
                    .and_then(|m| m.get("syscall.type"))
                    .map(String::as_str)
                    .unwrap_or("N/A"),
            )
            .replace(
                "{process}",
                obf_fields
                    .as_ref()
                    .and_then(|m| m.get("proc.name"))
                    .map(String::as_str)
                    .unwrap_or("N/A"),
            )
            .replace(
                "{parent_process}",
                obf_fields
                    .as_ref()
                    .and_then(|m| m.get("proc.pname"))
                    .map(String::as_str)
                    .unwrap_or("N/A"),
            );

        if dry_run {
            return json!({
                "obfuscated_prompt": user_prompt,
                "obfuscation_mapping": {
                    "ips": mapping.ips,
                    "hostnames": mapping.hostnames,
                    "users": mapping.users,
                    "containers": mapping.containers,
                    "paths": mapping.paths,
                    "emails": mapping.emails,
                    "secrets_count": mapping.secrets_count,
                },
                "note": "Dry run - no LLM call made"
            });
        }

        let quick_mitre = labels
            .get("rule")
            .and_then(|r| mitre_mapping().get(r.as_str()).copied());

        let analysis = self
            .provider
            .analyze(SYSTEM_PROMPT, &user_prompt)
            .unwrap_or_else(|e| {
                json!({
                    "error": e.to_string(),
                    "fallback_mitre": quick_mitre
                })
            });

        json!({
            "original_alert": alert,
            "obfuscated_alert": obf_alert,
            "obfuscation_mapping": {
                "ips": mapping.ips,
                "hostnames": mapping.hostnames,
                "users": mapping.users,
                "containers": mapping.containers,
                "paths": mapping.paths,
                "emails": mapping.emails,
                "secrets_count": mapping.secrets_count,
            },
            "analysis": analysis
        })
    }

    pub fn store_analysis(&self, result: &Value) -> Result<()> {
        let analysis = result
            .get("analysis")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let original = result
            .get("original_alert")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let labels = original
            .get("_labels")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let mitre = analysis
            .get("mitre_attack")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let risk = analysis
            .get("risk")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let fp = analysis
            .get("false_positive")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();

        let mut enriched_labels = HashMap::new();
        enriched_labels.insert("source".to_string(), "analysis".to_string());
        enriched_labels.insert("type".to_string(), "enriched".to_string());
        enriched_labels.insert(
            "original_rule".to_string(),
            labels
                .get("rule")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
        );
        enriched_labels.insert(
            "original_priority".to_string(),
            labels
                .get("priority")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
        );
        enriched_labels.insert(
            "hostname".to_string(),
            labels
                .get("hostname")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
        );
        enriched_labels.insert(
            "severity".to_string(),
            risk.get("severity")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_ascii_lowercase(),
        );
        enriched_labels.insert(
            "mitre_tactic".to_string(),
            mitre
                .get("tactic")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .replace(' ', "_"),
        );
        enriched_labels.insert(
            "mitre_technique".to_string(),
            mitre
                .get("technique_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string(),
        );
        enriched_labels.insert(
            "false_positive".to_string(),
            fp.get("likelihood")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_ascii_lowercase(),
        );

        let timestamp = original
            .get("_timestamp")
            .and_then(Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|d| d.with_timezone(&Utc));

        let enriched_entry = json!({
            "timestamp": original.get("_timestamp").cloned().unwrap_or(Value::String(String::new())),
            "obfuscated_output": result
                .get("obfuscated_alert")
                .and_then(|a| a.get("output"))
                .cloned()
                .unwrap_or(Value::String(String::new())),
            "rule": labels.get("rule").cloned().unwrap_or(Value::String(String::new())),
            "priority": labels.get("priority").cloned().unwrap_or(Value::String(String::new())),
            "hostname": labels.get("hostname").cloned().unwrap_or(Value::String(String::new())),
            "attack_vector": analysis.get("attack_vector").cloned().unwrap_or(Value::String(String::new())),
            "mitre_attack": Value::Object(mitre),
            "risk": Value::Object(risk),
            "mitigations": analysis.get("mitigations").cloned().unwrap_or_else(|| json!({})),
            "false_positive": analysis.get("false_positive").cloned().unwrap_or_else(|| json!({})),
            "summary": analysis.get("summary").cloned().unwrap_or(Value::String(String::new())),
            "investigate": analysis.get("investigate").cloned().unwrap_or_else(|| json!([])),
        });

        self.log_client
            .push(&enriched_labels, &enriched_entry.to_string(), timestamp)
    }

    pub fn analyze_batch(&self, alerts: &[Value], dry_run: bool, store: bool) -> Vec<Value> {
        let mut results = Vec::new();
        for alert in alerts {
            let result = self.analyze_alert(alert, dry_run);
            if store
                && !dry_run
                && result
                    .get("analysis")
                    .and_then(|a| a.get("error"))
                    .is_none()
            {
                let _ = self.store_analysis(&result);
            }
            results.push(result);
        }
        results
    }
}

#[derive(Debug, Parser, Clone)]
#[command(name = "alert-analyzer")]
#[command(about = "Alert Analyzer - LLM-powered security alert analysis")]
pub struct CliArgs {
    #[arg(short = 'c', long = "config")]
    pub config: Option<String>,
    #[arg(short = 'p', long = "priority")]
    pub priority: Option<String>,
    #[arg(short = 'l', long = "last", default_value = "1h")]
    pub last: String,
    #[arg(short = 'n', long = "limit", default_value_t = 5)]
    pub limit: usize,
    #[arg(short = 'd', long = "dry-run", default_value_t = false)]
    pub dry_run: bool,
    #[arg(short = 's', long = "store", default_value_t = false)]
    pub store: bool,
    #[arg(short = 'v', long = "verbose", default_value_t = false)]
    pub verbose: bool,
    #[arg(short = 'j', long = "json", default_value_t = false)]
    pub json: bool,
    #[arg(long = "loki-url")]
    pub loki_url: Option<String>,
    #[arg(long = "victorialogs-url")]
    pub victorialogs_url: Option<String>,
    #[arg(short = 'b', long = "backend")]
    pub backend: Option<String>,
}

pub fn run_from_args(args: CliArgs) -> Result<i32> {
    let mut config = load_config(args.config.as_deref())?;

    if let Some(backend) = args.backend {
        config.storage.backend = backend;
    }
    if let Some(url) = args.loki_url {
        config.loki.url = url;
        config.storage.backend = "loki".to_string();
    }
    if let Some(url) = args.victorialogs_url {
        config.victorialogs.url = url;
        config.storage.backend = "victorialogs".to_string();
    }

    if !config.analysis.enabled {
        eprintln!("analysis is disabled in config. set analysis.enabled=true to enable");
        return Ok(1);
    }

    let analyzer = AlertAnalyzer::from_config(&config)?;
    eprintln!("fetching alerts from last {}...", args.last);
    let alerts = analyzer.fetch_alerts(args.priority.as_deref(), &args.last, args.limit)?;

    if alerts.is_empty() {
        println!("no alerts found matching criteria");
        return Ok(0);
    }

    eprintln!("found {} alerts. analyzing...", alerts.len());
    let results = analyzer.analyze_batch(&alerts, args.dry_run, args.store);

    if args.json {
        println!("{}", serde_json::to_string_pretty(&results)?);
    } else {
        for result in &results {
            print_analysis(result, args.verbose);
        }
    }

    Ok(0)
}

fn print_analysis(result: &Value, verbose: bool) {
    let analysis = result
        .get("analysis")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    if let Some(err) = analysis.get("error").and_then(Value::as_str) {
        println!("analysis error: {err}");
        if let Some(fallback) = analysis.get("fallback_mitre") {
            println!("fallback mitre: {fallback}");
        }
        return;
    }

    println!("======================================================================");
    println!("SECURITY ALERT ANALYSIS");
    println!("======================================================================");

    println!(
        "attack vector: {}",
        analysis
            .get("attack_vector")
            .and_then(Value::as_str)
            .unwrap_or("N/A")
    );

    let mitre = analysis
        .get("mitre_attack")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    println!(
        "mitre tactic: {}",
        mitre.get("tactic").and_then(Value::as_str).unwrap_or("N/A")
    );
    println!(
        "mitre technique: {} - {}",
        mitre
            .get("technique_id")
            .and_then(Value::as_str)
            .unwrap_or("N/A"),
        mitre
            .get("technique_name")
            .and_then(Value::as_str)
            .unwrap_or("N/A")
    );

    let risk = analysis
        .get("risk")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    println!(
        "risk severity: {}",
        risk.get("severity").and_then(Value::as_str).unwrap_or("N/A")
    );
    println!(
        "risk confidence: {}",
        risk.get("confidence").and_then(Value::as_str).unwrap_or("N/A")
    );
    println!(
        "risk impact: {}",
        risk.get("impact").and_then(Value::as_str).unwrap_or("N/A")
    );

    let summary = analysis
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or("N/A");
    println!("summary: {summary}");

    if verbose {
        println!("obfuscation mapping:");
        if let Some(mapping) = result.get("obfuscation_mapping") {
            println!(
                "{}",
                serde_json::to_string_pretty(mapping).unwrap_or_else(|_| "{}".to_string())
            );
        }
    }

    println!("======================================================================");
}

pub fn load_config(config_path: Option<&str>) -> Result<AnalyzerConfig> {
    let mut raw = None;

    if let Some(path) = config_path {
        if Path::new(path).exists() {
            raw = Some(fs::read_to_string(path)?);
        } else {
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

fn parse_last(last: &str) -> Result<Duration> {
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

fn value_to_string_map(obj: Option<&Map<String, Value>>) -> HashMap<String, String> {
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

fn value_to_string_map_optional(v: Option<&Value>) -> Option<HashMap<String, String>> {
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

fn read_secret(env_var: &str) -> Option<String> {
    let file_var = format!("{env_var}_FILE");
    if let Ok(file_path) = env::var(file_var) {
        if let Ok(meta) = fs::metadata(&file_path)
            && meta.len() > 65_536
        {
            return None;
        }
        if let Ok(content) = fs::read_to_string(file_path) {
            return Some(content.trim().to_string());
        }
    }

    env::var(env_var).ok()
}

fn expand_env_string(input: &str) -> String {
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
                "ANTHROPIC_API_KEY" | "OPENAI_API_KEY" | "OLLAMA_API_KEY"
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

#[cfg(test)]
mod tests {
    use super::{expand_env_string, parse_last};

    #[test]
    fn parses_last_durations() {
        assert!(parse_last("15m").is_ok());
        assert!(parse_last("1h").is_ok());
        assert!(parse_last("7d").is_ok());
        assert!(parse_last("10x").is_err());
        assert!(parse_last("0h").is_err());
        assert!(parse_last("-1h").is_err());
    }

    #[test]
    fn expands_env_var_with_default() {
        let value = expand_env_string("${DOES_NOT_EXIST:-fallback}");
        assert_eq!(value, "fallback");
    }

    #[test]
    fn expand_env_preserves_unicode() {
        let value = expand_env_string("préfix-${DOES_NOT_EXIST:-défaut}-suffixe");
        assert_eq!(value, "préfix-défaut-suffixe");
    }
}
