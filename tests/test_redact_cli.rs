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
