#![cfg(feature = "analyzer")]

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
