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

#[test]
fn test_profile_pii_enables_ssn_redaction() {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "ssn=123-45-6789").unwrap();

    // pii profile must use level >= standard (pii group has min_level: standard)
    let out = redact_bin()
        .args(["--profile", "pii", "--level", "standard"])
        .arg(f.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("[REDACTED-SSN]"),
        "SSN should be redacted with pii profile at standard level, got: {stdout}"
    );
    assert!(
        !stdout.contains("123-45-6789"),
        "raw SSN value should not appear, got: {stdout}"
    );
}

#[test]
fn test_default_profile_does_not_redact_ssn() {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "ssn=123-45-6789").unwrap();

    let out = redact_bin().arg(f.path()).output().unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("123-45-6789"),
        "SSN should pass through by default, got: {stdout}"
    );
}
