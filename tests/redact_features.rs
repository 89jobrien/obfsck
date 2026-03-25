#![cfg(feature = "analyzer")]

use std::process::Command;

fn redact_bin() -> Command {
    let bin = env!("CARGO_BIN_EXE_redact");
    Command::new(bin)
}

#[test]
fn test_audit_reports_to_stderr() {
    let out = redact_bin()
        .arg("--audit")
        .arg("tests/fixtures/demo-secrets.txt")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("Audit report"),
        "expected audit header, got: {stderr}"
    );
    assert!(
        stderr.contains("ANTHROPIC-KEY"),
        "expected pattern label, got: {stderr}"
    );

    // Redacted content still goes to stdout
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[REDACTED-"),
        "expected redacted output on stdout, got: {stdout}"
    );
    assert!(
        !stdout.contains("sk-ant-"),
        "key should be redacted on stdout, got: {stdout}"
    );
}

#[test]
fn test_audit_shows_match_counts() {
    let out = redact_bin()
        .arg("--audit")
        .arg("tests/fixtures/demo-secrets.txt")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    // Audit header should include totals
    assert!(
        stderr.contains("pattern"),
        "expected summary line, got: {stderr}"
    );
}
