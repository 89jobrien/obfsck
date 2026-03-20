use crate::clients::{LogClient, LokiClient, VictoriaLogsClient};
use crate::schema::AnalysisOutput;
use crate::{ObfuscationLevel, obfuscate_alert};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use simplify_baml::{BamlSchema, FieldType, IR, parse_llm_response_with_ir};
use std::collections::HashMap;
use thiserror::Error;
use tracing::{debug, error, info, instrument, warn};

mod cli;
mod config;
mod parsing;
mod prompts;
mod providers;

pub use cli::{CliArgs, run_from_args};
pub use config::{
    AnalysisConfig, AnalyzerConfig, AnthropicConfig, LokiConfig, OllamaConfig, OpenAiConfig,
    StorageConfig, VictoriaLogsConfig, expand_env_string, load_config,
};
pub use parsing::parse_last;
use parsing::{value_to_string_map, value_to_string_map_optional};
pub use prompts::{SYSTEM_PROMPT, USER_PROMPT_TEMPLATE, mitre_mapping};
use providers::{AnthropicProvider, LlmProvider, OllamaProvider, OpenAiProvider};

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

pub struct AlertAnalyzer {
    backend: String,
    log_client: Box<dyn LogClient>,
    obfuscation_level: ObfuscationLevel,
    provider: Box<dyn LlmProvider>,
    analysis_ir: IR,
    analysis_output_type: FieldType,
}

impl AlertAnalyzer {
    #[instrument(skip(config), fields(
        backend = %config.storage.backend,
        provider = %config.analysis.provider,
        obfuscation = %config.analysis.obfuscation_level
    ))]
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

        let obfuscation_level = ObfuscationLevel::parse(&config.analysis.obfuscation_level)
            .ok_or_else(|| {
                error!(level = %config.analysis.obfuscation_level, "Invalid obfuscation level");
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
                Box::new(OpenAiProvider::new(
                    key,
                    config.analysis.openai.model.clone(),
                )?)
            }
            "anthropic" => {
                let key = expand_env_string(&config.analysis.anthropic.api_key);
                Box::new(AnthropicProvider::new(
                    key,
                    config.analysis.anthropic.model.clone(),
                )?)
            }
            other => {
                error!(provider = %other, "Unknown LLM provider");
                return Err(AnalyzerError::InvalidConfig(format!(
                    "unknown provider: {other}"
                )));
            }
        };

        let analysis_ir = crate::schema::analysis_ir();
        let analysis_output_type = FieldType::Class(AnalysisOutput::schema_name().to_string());

        Ok(Self {
            backend,
            log_client,
            obfuscation_level,
            provider,
            analysis_ir,
            analysis_output_type,
        })
    }

    fn parse_analysis_response(&self, raw_response: &str) -> Result<Value> {
        let parsed = match parse_llm_response_with_ir(
            &self.analysis_ir,
            raw_response,
            &self.analysis_output_type,
        ) {
            Ok(value) => value,
            Err(strict_err) => {
                let candidate = extract_json_object(raw_response).ok_or_else(|| {
                    AnalyzerError::ResponseParse(format!("strict parse failed: {strict_err}"))
                })?;

                match parse_llm_response_with_ir(
                    &self.analysis_ir,
                    candidate,
                    &self.analysis_output_type,
                ) {
                    Ok(value) => value,
                    Err(fallback_err) => {
                        let typed_direct = serde_json::from_str::<AnalysisOutput>(candidate)
                            .map_err(|typed_err| {
                                AnalyzerError::ResponseParse(format!(
                                    "strict parse failed: {strict_err}; fallback parse failed: {fallback_err}; direct typed parse failed: {typed_err}"
                                ))
                            })?;

                        return serde_json::to_value(typed_direct).map_err(AnalyzerError::from);
                    }
                }
            }
        };

        let as_json = serde_json::to_value(parsed)?;
        let typed: AnalysisOutput = serde_json::from_value(as_json)
            .map_err(|e| AnalyzerError::ResponseParse(format!("schema validation failed: {e}")))?;

        serde_json::to_value(typed).map_err(AnalyzerError::from)
    }

    #[instrument(skip(self), fields(
        backend = %self.backend,
        priority = ?priority,
        last = %last,
        limit = %limit
    ))]
    pub fn fetch_alerts(
        &self,
        priority: Option<&str>,
        last: &str,
        limit: usize,
    ) -> Result<Vec<Value>> {
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

        info!(query = %query, start = %start.to_rfc3339(), end = %end.to_rfc3339(), "Querying logs");
        let alerts = self.log_client.query_range(&query, start, end, limit)?;
        info!(count = alerts.len(), "Fetched alerts successfully");
        Ok(alerts)
    }

    #[instrument(skip(self, alert), fields(dry_run = %dry_run))]
    pub fn analyze_alert(&self, alert: &Value, dry_run: bool) -> Value {
        let labels = value_to_string_map(alert.get("_labels").and_then(Value::as_object));
        let output = alert.get("output").and_then(Value::as_str);
        let output_fields = value_to_string_map_optional(alert.get("output_fields"));

        let (obf_output, obf_fields, mapping) =
            obfuscate_alert(output, output_fields.as_ref(), self.obfuscation_level);

        debug!(
            ips = mapping.ips.len(),
            users = mapping.users.len(),
            secrets = mapping.secrets_count,
            "Obfuscation complete"
        );

        let obf_alert = json!({
            "output": obf_output,
            "output_fields": obf_fields,
        });

        let user_prompt = build_user_prompt(alert, &labels, &obf_output, &obf_fields);
        let mapping_json = obfuscation_mapping_value(&mapping);

        if dry_run {
            info!("Dry run - skipping LLM analysis");
            return json!({
                "obfuscated_prompt": user_prompt,
                "obfuscation_mapping": mapping_json,
                "note": "Dry run - no LLM call made"
            });
        }

        let quick_mitre = labels
            .get("rule")
            .and_then(|r| mitre_mapping().get(r.as_str()).copied());

        let analysis = self
            .provider
            .analyze(SYSTEM_PROMPT, &user_prompt)
            .and_then(|raw| self.parse_analysis_response(&raw))
            .unwrap_or_else(|e| {
                error!(error = %e, "Analysis failed, using fallback");
                json!({
                    "error": e.to_string(),
                    "fallback_mitre": quick_mitre
                })
            });

        json!({
            "original_alert": alert,
            "obfuscated_alert": obf_alert,
            "obfuscation_mapping": mapping_json,
            "analysis": analysis
        })
    }

    #[instrument(skip(self, result))]
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
            .map_err(|e| {
                error!(error = %e, "Failed to store analysis");
                e
            })
    }

    #[instrument(skip(self, alerts), fields(count = alerts.len(), dry_run = %dry_run, store = %store))]
    pub fn analyze_batch(&self, alerts: &[Value], dry_run: bool, store: bool) -> Vec<Value> {
        let mut results = Vec::new();
        let mut stored_count = 0;

        for (idx, alert) in alerts.iter().enumerate() {
            debug!(index = idx, "Analyzing alert in batch");
            let result = self.analyze_alert(alert, dry_run);
            if store
                && !dry_run
                && result
                    .get("analysis")
                    .and_then(|a| a.get("error"))
                    .is_none()
            {
                if let Err(e) = self.store_analysis(&result) {
                    warn!(index = idx, error = %e, "Failed to store analysis in batch");
                } else {
                    stored_count += 1;
                }
            }
            results.push(result);
        }

        info!(
            total = alerts.len(),
            stored = stored_count,
            "Batch analysis complete"
        );
        results
    }
}

fn build_user_prompt(
    alert: &Value,
    labels: &HashMap<String, String>,
    obf_output: &Option<String>,
    obf_fields: &Option<HashMap<String, String>>,
) -> String {
    USER_PROMPT_TEMPLATE
        .replace(
            "{rule_name}",
            labels.get("rule").map(String::as_str).unwrap_or("Unknown"),
        )
        .replace(
            "{priority}",
            labels
                .get("priority")
                .map(String::as_str)
                .unwrap_or("Unknown"),
        )
        .replace(
            "{timestamp}",
            alert
                .get("_timestamp")
                .and_then(Value::as_str)
                .unwrap_or("Unknown"),
        )
        .replace(
            "{source}",
            labels
                .get("source")
                .map(String::as_str)
                .unwrap_or("syscall"),
        )
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
        )
}

fn obfuscation_mapping_value(mapping: &crate::ObfuscationMapExport) -> Value {
    json!({
        "ips": mapping.ips,
        "hostnames": mapping.hostnames,
        "users": mapping.users,
        "containers": mapping.containers,
        "paths": mapping.paths,
        "emails": mapping.emails,
        "secrets_count": mapping.secrets_count,
    })
}

fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let end = raw.rfind('}')?;
    (end > start).then_some(&raw[start..=end])
}
