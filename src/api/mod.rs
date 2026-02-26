use crate::analyzer::{AlertAnalyzer, AnalyzerConfig, AnalyzerError, load_config};
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use std::sync::OnceLock;
use thiserror::Error;
use tower_http::cors::CorsLayer;

mod render;

use render::{html_escape, render_analysis_html};

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("analyzer error: {0}")]
    Analyzer(#[from] AnalyzerError),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("join error: {0}")]
    Join(String),
}

#[derive(Clone)]
pub struct AppState {
    config: AnalyzerConfig,
    cache_dir: PathBuf,
    cache_ttl_secs: i64,
    http_client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CacheEntry {
    cache_key: String,
    timestamp: String,
    original_output: String,
    rule: String,
    priority: String,
    hostname: String,
    analysis: Value,
    obfuscated_output: String,
    obfuscation_mapping: Value,
    dedup_count: u64,
    last_seen: String,
}

#[derive(Debug, Deserialize)]
pub struct AnalyzeRequest {
    alert: Option<String>,
    rule: Option<String>,
    priority: Option<String>,
    hostname: Option<String>,
    store: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct AnalyzeQuery {
    output: Option<String>,
    rule: Option<String>,
    priority: Option<String>,
    hostname: Option<String>,
    store: Option<String>,
    show_mapping: Option<String>,
}

#[derive(Debug, Deserialize)]
struct HistoryQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct HealthAllQuery {
    timeout: Option<f64>,
}

#[derive(Debug, Serialize)]
struct HealthResp {
    status: String,
    service: String,
}

struct AnalysisPageView<'a> {
    error: Option<String>,
    analysis: &'a Value,
    original_output: &'a str,
    obfuscated_output: &'a str,
    obfuscation_mapping: &'a Value,
    show_mapping: bool,
    cached: bool,
    timestamp: &'a str,
}

pub async fn run_server(host: String, port: u16) -> Result<(), ApiError> {
    let config = load_config(None)?;
    let cache_dir = std::env::var("ANALYSIS_CACHE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/app/cache"));
    fs::create_dir_all(&cache_dir)?;
    let cache_ttl_secs = std::env::var("ANALYSIS_CACHE_TTL")
        .ok()
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(86_400);

    let state = Arc::new(AppState {
        config,
        cache_dir,
        cache_ttl_secs,
        http_client: reqwest::Client::new(),
    });

    let app = Router::new()
        .route("/", get(index))
        .route("/health", get(health))
        .route("/api/health/all", get(health_all))
        .route("/api/analyze", post(analyze_api))
        .route("/analyze", get(analyze_page))
        .route("/history", get(history_page))
        .route("/history/{cache_key}", get(history_detail))
        .route("/api/history", get(api_history))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(format!("{host}:{port}"))
        .await
        .map_err(ApiError::Io)?;
    axum::serve(listener, app).await.map_err(ApiError::Io)
}

async fn health() -> Json<HealthResp> {
    Json(HealthResp {
        status: "healthy".to_string(),
        service: "alert-analysis-api".to_string(),
    })
}

async fn health_all(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HealthAllQuery>,
) -> impl IntoResponse {
    let timeout = query.timeout.unwrap_or(3.0).clamp(0.5, 30.0);
    let stack = std::env::var("STACK")
        .ok()
        .unwrap_or_else(|| state.config.storage.backend.clone());

    let mut checks: HashMap<&str, String> = HashMap::new();
    checks.insert(
        "falcosidekick",
        std::env::var("SIDEKICK_HEALTH_URL")
            .unwrap_or_else(|_| "http://sidekick:2801/healthz".to_string()),
    );
    checks.insert(
        "grafana",
        std::env::var("GRAFANA_HEALTH_URL")
            .unwrap_or_else(|_| "http://grafana:3000/api/health".to_string()),
    );

    if matches!(stack.as_str(), "vm" | "victorialogs") {
        checks.insert(
            "victorialogs",
            std::env::var("VICTORIALOGS_HEALTH_URL")
                .unwrap_or_else(|_| "http://victorialogs:9428/health".to_string()),
        );
        checks.insert(
            "victoriametrics",
            std::env::var("VICTORIAMETRICS_HEALTH_URL")
                .unwrap_or_else(|_| "http://victoriametrics:8428/health".to_string()),
        );
    } else {
        checks.insert(
            "loki",
            std::env::var("LOKI_HEALTH_URL")
                .unwrap_or_else(|_| "http://loki:3100/ready".to_string()),
        );
        checks.insert(
            "prometheus",
            std::env::var("PROMETHEUS_HEALTH_URL")
                .unwrap_or_else(|_| "http://prometheus:9090/-/ready".to_string()),
        );
    }

    let mut results = serde_json::Map::new();
    for (name, url) in checks {
        let item = match state
            .http_client
            .get(url)
            .timeout(std::time::Duration::from_secs_f64(timeout))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    json!({"status": "healthy", "code": resp.status().as_u16()})
                } else {
                    json!({"status": "unhealthy", "code": resp.status().as_u16()})
                }
            }
            Err(err) if err.is_timeout() => json!({"status": "timeout"}),
            Err(err) if err.is_connect() => json!({"status": "unreachable"}),
            Err(err) => json!({"status": "error", "detail": err.to_string()}),
        };
        results.insert(name.to_string(), item);
    }
    results.insert("analysis".to_string(), json!({"status": "healthy"}));

    let statuses: Vec<String> = results
        .values()
        .filter_map(|v| v.get("status").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .collect();
    let overall = if statuses.iter().all(|s| s == "healthy") {
        "healthy"
    } else if statuses.iter().any(|s| s == "healthy") {
        "degraded"
    } else {
        "unhealthy"
    };

    Json(json!({
        "status": overall,
        "stack": stack,
        "services": results,
        "checked_at": Utc::now().to_rfc3339(),
    }))
}

async fn analyze_api(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<AnalyzeRequest>,
) -> impl IntoResponse {
    let Some(alert_text) = payload.alert.clone().filter(|s| !s.is_empty()) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "Missing alert data"})),
        )
            .into_response();
    };

    let alert = build_alert(
        alert_text,
        payload.rule.unwrap_or_else(|| "Unknown".to_string()),
        payload.priority.unwrap_or_else(|| "Unknown".to_string()),
        payload.hostname.unwrap_or_else(|| "Unknown".to_string()),
    );

    match analyze_alert_with_config(state.config.clone(), alert.clone()).await {
        Ok(result) => {
            if payload.store.unwrap_or(false) {
                let _ = store_analysis_with_config(state.config.clone(), result.clone()).await;
            }
            (
                StatusCode::OK,
                Json(json!({
                    "success": true,
                    "analysis": result.get("analysis").cloned().unwrap_or_else(|| json!({})),
                    "obfuscation_mapping": result.get("obfuscation_mapping").cloned().unwrap_or_else(|| json!({})),
                })),
            )
                .into_response()
        }
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

async fn analyze_page(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AnalyzeQuery>,
) -> impl IntoResponse {
    let output = query.output.unwrap_or_default();
    let rule = query.rule.unwrap_or_else(|| "Unknown".to_string());
    let priority = query.priority.unwrap_or_else(|| "Unknown".to_string());
    let hostname = query.hostname.unwrap_or_else(|| "Unknown".to_string());
    let store = parse_boolish(query.store.as_deref(), true);
    let show_mapping = parse_boolish(query.show_mapping.as_deref(), false);

    if output.is_empty() {
        return Html(render_analysis_html(&AnalysisPageView {
            error: Some("No alert output provided. Use ?output=...".to_string()),
            analysis: &json!({}),
            original_output: "",
            obfuscated_output: "",
            obfuscation_mapping: &json!({}),
            show_mapping,
            cached: false,
            timestamp: &Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        }));
    }

    let cache_key = get_cache_key(&output, &rule);
    if let Ok(Some(cached)) = get_cached_analysis(&state, &cache_key) {
        return Html(render_analysis_html(&AnalysisPageView {
            error: None,
            analysis: &cached.analysis,
            original_output: &output,
            obfuscated_output: &cached.obfuscated_output,
            obfuscation_mapping: &cached.obfuscation_mapping,
            show_mapping,
            cached: true,
            timestamp: &cached.timestamp,
        }));
    }

    let alert = build_alert(
        output.clone(),
        rule.clone(),
        priority.clone(),
        hostname.clone(),
    );
    let result = match analyze_alert_with_config(state.config.clone(), alert).await {
        Ok(r) => r,
        Err(err) => {
            return Html(render_analysis_html(&AnalysisPageView {
                error: Some(err.to_string()),
                analysis: &json!({}),
                original_output: &output,
                obfuscated_output: "",
                obfuscation_mapping: &json!({}),
                show_mapping,
                cached: false,
                timestamp: &Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            }));
        }
    };

    if store && result.pointer("/analysis/error").is_none() {
        let _ = store_analysis_with_config(state.config.clone(), result.clone()).await;
    }

    let _ = save_to_cache(
        &state, &cache_key, &result, &output, &rule, &priority, &hostname,
    );

    let analysis = result.get("analysis").cloned().unwrap_or_else(|| json!({}));
    let obfuscated_output = result
        .pointer("/obfuscated_alert/output")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let mapping = result
        .get("obfuscation_mapping")
        .cloned()
        .unwrap_or_else(|| json!({}));

    Html(render_analysis_html(&AnalysisPageView {
        error: None,
        analysis: &analysis,
        original_output: &output,
        obfuscated_output: &obfuscated_output,
        obfuscation_mapping: &mapping,
        show_mapping,
        cached: false,
        timestamp: &Utc::now().format("%Y-%m-%d %H:%M:%S").to_string(),
    }))
}

async fn history_page(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let analyses = list_cached_analyses(&state, 100).unwrap_or_default();
    let mut rows = String::new();

    for a in analyses {
        let key = html_escape(&a.cache_key);
        let timestamp = html_escape(&a.timestamp.chars().take(19).collect::<String>());
        let rule = html_escape(&a.rule);
        let priority = html_escape(&a.priority);
        let hostname = html_escape(&a.hostname);
        let severity = html_escape(&a.severity);
        let color = match a.severity.as_str() {
            "critical" => "#f2495c",
            "high" => "#ff9830",
            "medium" => "#fade2a",
            "low" => "#73bf69",
            _ => "#8e8e8e",
        };
        rows.push_str(&format!(
            "<tr onclick=\"window.location='/history/{key}'\" style=\"cursor:pointer;\"><td>{timestamp}</td><td>{rule}</td><td>{priority}</td><td style=\"color:{color};font-weight:bold;\">{severity}</td><td>{hostname}</td><td>{}</td></tr>",
            a.dedup_count
        ));
    }

    Html(format!(
        "<!DOCTYPE html><html><head><title>Analysis History</title><style>body{{font-family:-apple-system,sans-serif;background:#111217;color:#d8d9da;padding:40px;}}h1{{color:#ff9830;}}table{{width:100%;border-collapse:collapse;margin-top:20px;}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #2c3235;}}th{{background:#1f2129;color:#73bf69;}}tr:hover{{background:#1f2129;}}a{{color:#3274d9;text-decoration:none;}}</style></head><body><div><a href='/'>← Back to API</a></div><h1>Analysis History</h1><p>{} cached analyses</p><table><tr><th>Timestamp</th><th>Rule</th><th>Priority</th><th>AI Severity</th><th>Hostname</th><th>Seen</th></tr>{rows}</table></body></html>",
        rows.matches("<tr ").count()
    ))
}

async fn history_detail(
    State(state): State<Arc<AppState>>,
    Path(cache_key): Path<String>,
) -> impl IntoResponse {
    match get_cached_analysis(&state, &cache_key) {
        Ok(Some(cached)) => Html(render_analysis_html(&AnalysisPageView {
            error: None,
            analysis: &cached.analysis,
            original_output: &cached.original_output,
            obfuscated_output: &cached.obfuscated_output,
            obfuscation_mapping: &cached.obfuscation_mapping,
            show_mapping: false,
            cached: true,
            timestamp: &cached.timestamp,
        }))
        .into_response(),
        _ => (StatusCode::NOT_FOUND, "Analysis not found").into_response(),
    }
}

async fn api_history(
    State(state): State<Arc<AppState>>,
    Query(query): Query<HistoryQuery>,
) -> impl IntoResponse {
    let limit = query.limit.unwrap_or(50).clamp(1, 500);
    match list_cached_analyses(&state, limit) {
        Ok(items) => Json(items).into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": err.to_string()})),
        )
            .into_response(),
    }
}

async fn index(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let cached_count = match fs::read_dir(&state.cache_dir) {
        Ok(iter) => iter.filter_map(Result::ok).count(),
        Err(_) => 0,
    };

    Html(format!(
        "<!DOCTYPE html><html><head><title>Analysis API</title><style>body{{font-family:-apple-system,sans-serif;background:#111217;color:#d8d9da;padding:40px;}}h1{{color:#ff9830;}}h2{{color:#73bf69;margin-top:24px;}}code{{background:#2a2d35;padding:2px 8px;border-radius:4px;}}pre{{background:#1f2129;padding:20px;border-radius:8px;overflow-x:auto;}}a{{color:#3274d9;}}.stat{{display:inline-block;background:#1f2129;padding:15px 25px;border-radius:8px;margin-right:15px;}}.stat-value{{font-size:2em;color:#73bf69;}}</style></head><body><h1>Alert Analysis API</h1><p>AI-powered security alert analysis with privacy protection.</p><div style='margin:30px 0;'><div class='stat'><div class='stat-value'>{cached_count}</div><div>Cached Analyses</div></div><a href='/history' style='background:#3274d9;color:white;padding:15px 25px;border-radius:8px;text-decoration:none;'>View History</a></div><h2>Endpoints</h2><h3>GET /analyze</h3><pre>GET /analyze?output=&lt;alert_text&gt;&amp;rule=&lt;rule_name&gt;&amp;priority=&lt;priority&gt;&amp;hostname=&lt;host&gt;</pre><h3>POST /api/analyze</h3><pre>{{\n  \"alert\": \"alert output text\",\n  \"rule\": \"rule name\",\n  \"priority\": \"Critical\",\n  \"hostname\": \"host\",\n  \"store\": true\n}}</pre><h3>GET /health</h3><p>Health check endpoint.</p><h3>GET /api/health/all</h3><p>Aggregate health check for all services.</p></body></html>"
    ))
}

fn build_alert(output: String, rule: String, priority: String, hostname: String) -> Value {
    json!({
        "output": output,
        "_labels": {
            "rule": rule,
            "priority": priority,
            "hostname": hostname,
            "source": "syscall"
        },
        "_timestamp": Utc::now().to_rfc3339(),
    })
}

fn cache_file(cache_dir: &FsPath, key: &str) -> PathBuf {
    cache_dir.join(format!("{key}.json"))
}

fn get_cached_analysis(state: &AppState, cache_key: &str) -> Result<Option<CacheEntry>, ApiError> {
    let path = cache_file(&state.cache_dir, cache_key);
    if !path.exists() {
        return Ok(None);
    }

    let text = fs::read_to_string(&path)?;
    let mut entry: CacheEntry = serde_json::from_str(&text)?;

    if let Ok(ts) = DateTime::parse_from_rfc3339(&entry.timestamp) {
        let age = Utc::now()
            .signed_duration_since(ts.with_timezone(&Utc))
            .num_seconds();
        if age > state.cache_ttl_secs {
            return Ok(None);
        }
    }

    entry.dedup_count = entry.dedup_count.saturating_add(1);
    entry.last_seen = Utc::now().to_rfc3339();
    fs::write(&path, serde_json::to_string_pretty(&entry)?)?;
    Ok(Some(entry))
}

fn save_to_cache(
    state: &AppState,
    cache_key: &str,
    result: &Value,
    original_output: &str,
    rule: &str,
    priority: &str,
    hostname: &str,
) -> Result<(), ApiError> {
    let path = cache_file(&state.cache_dir, cache_key);
    let entry = CacheEntry {
        cache_key: cache_key.to_string(),
        timestamp: Utc::now().to_rfc3339(),
        original_output: original_output.to_string(),
        rule: rule.to_string(),
        priority: priority.to_string(),
        hostname: hostname.to_string(),
        analysis: result.get("analysis").cloned().unwrap_or_else(|| json!({})),
        obfuscated_output: result
            .pointer("/obfuscated_alert/output")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
        obfuscation_mapping: result
            .get("obfuscation_mapping")
            .cloned()
            .unwrap_or_else(|| json!({})),
        dedup_count: 1,
        last_seen: Utc::now().to_rfc3339(),
    };

    fs::write(path, serde_json::to_string_pretty(&entry)?)?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct HistoryItem {
    cache_key: String,
    timestamp: String,
    rule: String,
    priority: String,
    hostname: String,
    severity: String,
    dedup_count: u64,
    last_seen: String,
}

fn list_cached_analyses(state: &AppState, limit: usize) -> Result<Vec<HistoryItem>, ApiError> {
    let mut files: Vec<_> = fs::read_dir(&state.cache_dir)?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|s| s.to_str()) == Some("json"))
        .collect();

    files.sort_by_key(|e| {
        e.metadata()
            .and_then(|m| m.modified())
            .unwrap_or(std::time::SystemTime::UNIX_EPOCH)
    });
    files.reverse();

    let mut out = Vec::new();
    for entry in files.into_iter().take(limit) {
        let text = match fs::read_to_string(entry.path()) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let parsed: CacheEntry = match serde_json::from_str(&text) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let severity = parsed
            .analysis
            .pointer("/risk/severity")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_ascii_lowercase();

        out.push(HistoryItem {
            cache_key: parsed.cache_key,
            timestamp: parsed.timestamp,
            rule: parsed.rule,
            priority: parsed.priority,
            hostname: parsed.hostname,
            severity,
            dedup_count: parsed.dedup_count,
            last_seen: parsed.last_seen,
        });
    }

    Ok(out)
}

fn parse_boolish(value: Option<&str>, default: bool) -> bool {
    match value {
        Some(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        None => default,
    }
}

fn normalize_output(output: &str) -> String {
    let mut normalized = output.split_whitespace().collect::<Vec<_>>().join(" ");

    normalized = re_iso_ts().replace_all(&normalized, "[TIME]").into_owned();
    normalized = re_unix_ts()
        .replace_all(&normalized, "[TIMESTAMP]")
        .into_owned();
    normalized = re_plain_dt()
        .replace_all(&normalized, "[TIME]")
        .into_owned();
    normalized = re_ids().replace_all(&normalized, "$1=[ID]").into_owned();
    normalized = re_container_id()
        .replace_all(&normalized, "$1=[CID]")
        .into_owned();
    normalized = re_ip_port().replace_all(&normalized, "[IP]").into_owned();

    normalized
}

fn get_cache_key(output: &str, rule: &str) -> String {
    let content = format!("{}:{}", normalize_output(output), rule);
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let digest = hasher.finalize();
    let hex = format!("{digest:x}");
    hex.chars().take(16).collect()
}

async fn analyze_alert_with_config(
    config: AnalyzerConfig,
    alert: Value,
) -> Result<Value, ApiError> {
    tokio::task::spawn_blocking(move || {
        let analyzer = AlertAnalyzer::from_config(&config)?;
        Ok::<Value, AnalyzerError>(analyzer.analyze_alert(&alert, false))
    })
    .await
    .map_err(|e| ApiError::Join(e.to_string()))?
    .map_err(ApiError::from)
}

async fn store_analysis_with_config(config: AnalyzerConfig, result: Value) -> Result<(), ApiError> {
    tokio::task::spawn_blocking(move || {
        let analyzer = AlertAnalyzer::from_config(&config)?;
        analyzer.store_analysis(&result)
    })
    .await
    .map_err(|e| ApiError::Join(e.to_string()))?
    .map_err(ApiError::from)
}

fn re_iso_ts() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{4})?")
            .expect("iso ts regex")
    })
}

fn re_unix_ts() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\b\d{10,13}(\.\d+)?\b").expect("unix ts regex"))
}

fn re_plain_dt() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}").expect("plain dt regex"))
}

fn re_ids() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(user_uid|user_loginuid|pid|ppid|gid|tid|res)=\d+").expect("ids regex")
    })
}

fn re_container_id() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(container_id)=[a-f0-9]{8,64}").expect("cid regex"))
}

fn re_ip_port() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?").expect("ip regex"))
}

#[cfg(test)]
mod tests {
    use super::{get_cache_key, normalize_output, parse_boolish};

    #[test]
    fn normalize_replaces_variable_fields() {
        let out = "2026-01-09T12:34:56Z pid=1234 user_uid=1000 container_id=abcdef1234567890 src=10.1.2.3";
        let normalized = normalize_output(out);
        assert!(normalized.contains("[TIME]"));
        assert!(normalized.contains("pid=[ID]"));
        assert!(normalized.contains("[CID]"));
        assert!(normalized.contains("[IP]"));
    }

    #[test]
    fn cache_key_is_stable() {
        let a = get_cache_key("pid=1 src=1.2.3.4", "RuleA");
        let b = get_cache_key("pid=2 src=5.6.7.8", "RuleA");
        assert_eq!(a, b);
    }

    #[test]
    fn parse_boolish_works() {
        assert!(parse_boolish(Some("true"), false));
        assert!(parse_boolish(Some("1"), false));
        assert!(!parse_boolish(Some("false"), true));
        assert!(parse_boolish(None, true));
    }
}
