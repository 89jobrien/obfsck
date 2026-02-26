use serde_json::Value;
use std::process::Command;

fn run_api_with_env(log_format: &str, rust_log: &str) -> (i32, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_api"))
        .env("LOG_FORMAT", log_format)
        .env("RUST_LOG", rust_log)
        .env("ANALYSIS_CACHE_DIR", "/dev/null/obfsck")
        .output()
        .expect("failed to run api binary");

    let status = output.status.code().unwrap_or(-1);
    let mut combined = String::new();
    combined.push_str(&String::from_utf8_lossy(&output.stdout));
    combined.push_str(&String::from_utf8_lossy(&output.stderr));
    (status, combined)
}

fn json_lines(logs: &str) -> Vec<Value> {
    logs.lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .collect()
}

#[test]
fn api_emits_json_logs_when_log_format_is_json() {
    let (status, logs) = run_api_with_env("json", "info");
    assert_eq!(status, 1, "expected fast startup failure for test env");

    let parsed = json_lines(&logs);
    assert!(!parsed.is_empty(), "expected JSON log lines, got: {logs}");

    let startup = parsed.iter().find(|entry| {
        entry
            .get("fields")
            .and_then(|f| f.get("message"))
            .and_then(Value::as_str)
            == Some("Alert Analysis API starting")
    });

    let startup = startup.expect("startup JSON log entry missing");
    assert_eq!(startup.get("level").and_then(Value::as_str), Some("INFO"));
}

#[test]
fn api_emits_pretty_logs_when_log_format_is_pretty() {
    let (status, logs) = run_api_with_env("pretty", "info");
    assert_eq!(status, 1, "expected fast startup failure for test env");

    assert!(
        logs.contains("Alert Analysis API starting"),
        "expected startup message in pretty logs, got: {logs}"
    );

    assert!(
        json_lines(&logs).is_empty(),
        "expected non-JSON pretty logs, got parsable JSON lines: {logs}"
    );
}

#[test]
fn rust_log_filter_hides_info_when_set_to_error() {
    let (status, logs) = run_api_with_env("json", "error");
    assert_eq!(status, 1, "expected fast startup failure for test env");

    let parsed = json_lines(&logs);
    let has_info_startup = parsed.iter().any(|entry| {
        entry
            .get("fields")
            .and_then(|f| f.get("message"))
            .and_then(Value::as_str)
            == Some("Alert Analysis API starting")
    });
    assert!(
        !has_info_startup,
        "startup info log should be filtered out when RUST_LOG=error: {logs}"
    );

    let has_error = parsed.iter().any(|entry| {
        entry.get("level").and_then(Value::as_str) == Some("ERROR")
            && entry
                .get("fields")
                .and_then(|f| f.get("message"))
                .and_then(Value::as_str)
                == Some("Server error")
    });
    assert!(has_error, "expected server error log entry: {logs}");
}
