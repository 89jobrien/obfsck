//! Verifies canonical CLI routing and deprecated binary compatibility warnings.

#![cfg(feature = "analyzer")]

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn deprecated_redact_binary_warns() {
    let output = Command::new(env!("CARGO_BIN_EXE_redact"))
        .stdin(Stdio::null())
        .output()
        .expect("run deprecated redact binary");

    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: 'redact' is deprecated; use 'obfsck redact' instead"),
        "missing deprecation warning: {stderr}"
    );
}

fn obfsck_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_obfsck"))
}

#[test]
fn canonical_help_lists_both_subcommands() {
    let output = obfsck_bin()
        .arg("--help")
        .output()
        .expect("run obfsck help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("redact"),
        "missing redact command: {stdout}"
    );
    assert!(
        stdout.contains("analyze"),
        "missing analyze command: {stdout}"
    );
}

#[test]
fn canonical_redact_subcommand_redacts() {
    let fixture = format!(
        "{}/tests/fixtures/inputs/secrets_sample.txt",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = obfsck_bin()
        .args(["redact", "--level", "minimal", &fixture])
        .output()
        .expect("run obfsck redact");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.contains("[REDACTED-"),
        "secret was not redacted: {stdout}"
    );
    assert!(
        !stderr.contains("deprecated"),
        "canonical command warned: {stderr}"
    );
}

#[test]
fn model_ingress_policy_uses_bundled_patterns_without_allowlists() {
    let allowlisted = ["AK", "IA", "1234567890ABCDEF"].concat();
    let input = format!("credential={allowlisted}\n");

    let home = tempfile::tempdir().expect("create isolated home");
    let config_dir = home.path().join(".config/obfsck");
    std::fs::create_dir_all(&config_dir).expect("create user config directory");
    let user_config = config_dir.join("secrets.yaml");
    std::fs::write(
        &user_config,
        "groups: {}\ncustom:\n  - name: harmless\n    label: HARMLESS\n    pattern: NEVER_MATCH_POLICY_TEST\n",
    )
    .expect("write user config");
    std::fs::write(config_dir.join("allowlist"), &allowlisted).expect("write global allowlist");

    let allowlist_file = tempfile::NamedTempFile::new().expect("create allowlist file");
    std::fs::write(allowlist_file.path(), &allowlisted).expect("write allowlist file");

    let mut child = obfsck_bin()
        .env("HOME", home.path())
        .args(["redact", "--level", "minimal", "--policy", "model-ingress"])
        .arg("--config")
        .arg(&user_config)
        .arg("--allowlist")
        .arg(&allowlisted)
        .arg("--allowlist-file")
        .arg(allowlist_file.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn model-ingress redaction");
    child
        .stdin
        .as_mut()
        .expect("model-ingress stdin")
        .write_all(input.as_bytes())
        .expect("write model-ingress input");
    let output = child
        .wait_with_output()
        .expect("run model-ingress redaction");

    assert!(
        output.status.success(),
        "model-ingress policy failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("[REDACTED-"), "secret was not redacted");
    assert!(!stdout.contains(&allowlisted), "allowlisted secret leaked");
}

#[test]
fn canonical_redact_help_uses_canonical_invocation() {
    let output = obfsck_bin()
        .args(["redact", "--help"])
        .output()
        .expect("run obfsck redact help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage: obfsck redact"),
        "help advertises the wrong invocation: {stdout}"
    );
}

#[test]
fn canonical_analyze_subcommand_has_help() {
    let output = obfsck_bin()
        .args(["analyze", "--help"])
        .output()
        .expect("run obfsck analyze help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("--last"),
        "missing analyzer options: {stdout}"
    );
}

#[test]
fn deprecated_analyzer_binary_warns() {
    let missing_config = format!(
        "{}/tests/fixtures/missing-analyzer-config.yaml",
        env!("CARGO_MANIFEST_DIR")
    );
    let output = Command::new(env!("CARGO_BIN_EXE_analyzer"))
        .args(["--config", &missing_config])
        .output()
        .expect("run deprecated analyzer binary");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("warning: 'analyzer' is deprecated; use 'obfsck analyze' instead"),
        "missing deprecation warning: {stderr}"
    );
}

#[test]
fn canonical_custom_patterns_honor_glob_allowlist() {
    use std::io::Write;

    let mut config = tempfile::NamedTempFile::new().expect("create config");
    config
        .write_all(
            br#"groups: {}
custom:
  - name: custom_token
    pattern: \bcustom-[0-9]+\b
    label: CUSTOM
"#,
        )
        .expect("write config");
    let mut input = tempfile::NamedTempFile::new().expect("create input");
    input.write_all(b"custom-123\n").expect("write input");

    let output = obfsck_bin()
        .arg("redact")
        .arg("--config")
        .arg(config.path())
        .arg("--allowlist")
        .arg("custom-*")
        .arg(input.path())
        .output()
        .expect("run obfsck redact");

    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout), "custom-123\n");
}
