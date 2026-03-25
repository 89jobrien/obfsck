//! Integration tests for the `redact` CLI binary — file I/O paths.
#![cfg(feature = "analyzer")]

use std::io::Write;
use std::process::Command;

fn redact_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_redact"))
}

/// Write content to a named temp file; caller owns cleanup.
fn temp_file_with(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(content.as_bytes()).expect("write temp");
    f
}

#[test]
fn file_input_redacts_secret_to_stdout() {
    let input = temp_file_with("aws_key=AKIA1234567890ABCDEF\n");
    let out = redact_bin()
        .arg(input.path())
        .arg("--level")
        .arg("minimal")
        .output()
        .expect("run redact");

    assert!(out.status.success(), "exit code: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[REDACTED-AWS-KEY]"), "got: {stdout}");
    assert!(!stdout.contains("AKIA"), "key leaked: {stdout}");
}

#[test]
fn file_output_writes_redacted_content() {
    let input = temp_file_with("aws_key=AKIA1234567890ABCDEF\n");
    let out_file = tempfile::NamedTempFile::new().expect("out temp file");

    let status = redact_bin()
        .arg(input.path())
        .arg("--level")
        .arg("minimal")
        .arg("--output")
        .arg(out_file.path())
        .status()
        .expect("run redact");

    assert!(status.success(), "exit code: {status:?}");
    let content = std::fs::read_to_string(out_file.path()).expect("read output");
    assert!(content.contains("[REDACTED-AWS-KEY]"), "got: {content}");
    assert!(!content.contains("AKIA"), "key leaked: {content}");
}

#[test]
fn file_input_and_output_round_trip() {
    let secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890\n";
    let input = temp_file_with(secret);
    let out_file = tempfile::NamedTempFile::new().expect("out temp file");

    let status = redact_bin()
        .arg(input.path())
        .arg("--output")
        .arg(out_file.path())
        .status()
        .expect("run redact");

    assert!(status.success());
    let content = std::fs::read_to_string(out_file.path()).expect("read output");
    assert!(
        content.contains("[REDACTED-GITHUB-TOKEN]"),
        "got: {content}"
    );
    assert!(!content.contains("ghp_"), "token leaked: {content}");
}

#[test]
fn nonexistent_input_file_exits_nonzero() {
    let status = redact_bin()
        .arg("/tmp/obfsck-test-nonexistent-file-12345.txt")
        .status()
        .expect("run redact");
    assert!(!status.success(), "should have failed with nonzero exit");
}

// =============================================================================
// PII level-gating invariants
//
// The `pii` group in config/secrets.yaml has `min_level: standard`.
// These tests lock in the guarantee that --level minimal leaves PII untouched,
// and that --level standard (the privacy-forward default) redacts it.
// =============================================================================

/// Input containing representative PII. No real data — all synthetic test values.
const PII_INPUT: &str = "\
Report generated on 2026-03-25
author: Jane Smith
ssn: 123-45-6789
phone: (415) 555-1234
card: 4111111111111111
";

fn run_redact_stdin(input: &str, level: &str) -> String {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_redact"))
        .args(["--level", level])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn redact");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(input.as_bytes())
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "redact exited {:?}", out.status);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Core invariant: --level minimal MUST NOT redact PII.
/// Regression here means PII is being applied below its min_level gate.
#[test]
fn pii_untouched_at_minimal_level() {
    let out = run_redact_stdin(PII_INPUT, "minimal");
    assert!(
        out.contains("Jane Smith"),
        "name was redacted at minimal — invariant broken: {out}"
    );
    assert!(
        out.contains("123-45-6789"),
        "SSN was redacted at minimal — invariant broken: {out}"
    );
    assert!(
        out.contains("(415) 555-1234"),
        "phone was redacted at minimal — invariant broken: {out}"
    );
    assert!(
        out.contains("4111111111111111"),
        "credit card was redacted at minimal — invariant broken: {out}"
    );
    assert!(
        !out.contains("[REDACTED-PII"),
        "PII token appeared at minimal level: {out}"
    );
}

/// --level standard is the privacy-forward default: PII must be redacted.
#[test]
fn pii_redacted_at_standard_level() {
    let out = run_redact_stdin(PII_INPUT, "standard");
    assert!(
        !out.contains("Jane Smith"),
        "name not redacted at standard: {out}"
    );
    assert!(
        !out.contains("123-45-6789"),
        "SSN not redacted at standard: {out}"
    );
    assert!(
        !out.contains("(415) 555-1234"),
        "phone not redacted at standard: {out}"
    );
    assert!(
        !out.contains("4111111111111111"),
        "credit card not redacted at standard: {out}"
    );
}

/// paranoid level also redacts PII (superset of standard).
#[test]
fn pii_redacted_at_paranoid_level() {
    let out = run_redact_stdin(PII_INPUT, "paranoid");
    assert!(
        !out.contains("Jane Smith"),
        "name not redacted at paranoid: {out}"
    );
    assert!(
        !out.contains("123-45-6789"),
        "SSN not redacted at paranoid: {out}"
    );
}

/// paranoid_only PII patterns (IBAN, passport, drivers license) must NOT fire at standard.
#[test]
fn paranoid_only_pii_not_applied_at_standard() {
    // GB29NWBK60161331926819 — synthetic IBAN (GB format, wrong check digit)
    // A12345678 — synthetic passport number
    // A1234567 — synthetic US drivers license
    let input = "iban: GB29NWBK60161331926819\npassport: A12345678\ndl: A1234567\n";
    let out = run_redact_stdin(input, "standard");
    assert!(
        !out.contains("[REDACTED-IBAN]"),
        "IBAN was redacted at standard (paranoid_only violation): {out}"
    );
    assert!(
        !out.contains("[REDACTED-PASSPORT]"),
        "passport was redacted at standard (paranoid_only violation): {out}"
    );
    assert!(
        !out.contains("[REDACTED-DRIVERS-LICENSE]"),
        "drivers license was redacted at standard (paranoid_only violation): {out}"
    );
}

/// paranoid_only PII patterns must fire at paranoid.
#[test]
fn paranoid_only_pii_applied_at_paranoid() {
    let input = "iban: GB29NWBK60161331926819\n";
    let out = run_redact_stdin(input, "paranoid");
    assert!(
        out.contains("[REDACTED-IBAN]"),
        "IBAN not redacted at paranoid: {out}"
    );
}

/// Structural obfuscation (email, IP) also leaves PII contexts untouched at minimal.
/// Belt-and-suspenders: confirms the structural layer respects level too.
#[test]
fn structural_pii_untouched_at_minimal() {
    let input = "contact: user@example.com server: 192.168.1.100\n";
    let out = run_redact_stdin(input, "minimal");
    assert!(
        out.contains("user@example.com"),
        "email was structurally obfuscated at minimal: {out}"
    );
    assert!(
        out.contains("192.168.1.100"),
        "IP was structurally obfuscated at minimal: {out}"
    );
}
