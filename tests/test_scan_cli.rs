//! Verifies diff-scanner diagnostics identify findings without echoing secrets.

#![cfg(feature = "analyzer")]

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn scan_diagnostics_do_not_echo_secret_content() {
    let secret = [
        "xoxb",
        "123456789012",
        "123456789012",
        "abcdefghijklmnopqrstuvwx",
    ]
    .join("-");
    let diff = format!(
        "diff --git a/config.txt b/config.txt\n--- a/config.txt\n+++ b/config.txt\n@@ -0,0 +7 @@\n+token={secret}\n"
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_scan"))
        .arg("--no-gitleaks")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scan");
    child
        .stdin
        .as_mut()
        .expect("scan stdin")
        .write_all(diff.as_bytes())
        .expect("write diff");

    let output = child.wait_with_output().expect("wait for scan");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(
        !stderr.contains(&secret),
        "secret leaked in stderr: {stderr}"
    );
    assert!(
        stderr.contains("config.txt:7"),
        "missing source location: {stderr}"
    );
    assert!(
        stderr.contains("communication"),
        "missing pattern group provenance: {stderr}"
    );
    assert_eq!(
        stderr.matches("[obfsck]").count(),
        1,
        "pattern hit was counted more than once: {stderr}"
    );
}

/// Runs the scanner through `argv` and returns `(exit_code, stderr)`.
fn run_scanner(argv: &[&str], diff: &str) -> (i32, String) {
    let mut child = Command::new(argv[0])
        .args(&argv[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn scanner");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(diff.as_bytes())
        .expect("write diff");
    let output = child.wait_with_output().expect("wait");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Deliberately NOT `AKIAIOSFODNN7EXAMPLE`: the repo-local `.obfsck.toml`
/// allowlists that fixture, and integration tests inherit it by running with
/// the crate root as cwd. The inline marker keeps the key below out of the
/// pre-commit scan.
const AWS_KEY: &str = "AKIAZZZZZZZZZZZZZZZZ"; // obfsck:ignore

fn diff_with(body: &str) -> String {
    format!("diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -0,0 +1,2 @@\n{body}")
}

#[test]
fn canonical_scan_subcommand_finds_secrets() {
    let diff = diff_with(&format!("+key={AWS_KEY}\n"));
    let (code, stderr) = run_scanner(
        &[env!("CARGO_BIN_EXE_obfsck"), "scan", "--no-gitleaks"],
        &diff,
    );
    assert_eq!(code, 1, "findings must exit 1: {stderr}");
    assert!(stderr.contains("f.txt:1"), "missing location: {stderr}");
    assert!(
        !stderr.contains(AWS_KEY),
        "secret leaked in stderr: {stderr}"
    );
}

#[test]
fn canonical_scan_subcommand_exits_clean_on_no_findings() {
    let diff = diff_with("+hello world\n");
    let (code, stderr) = run_scanner(
        &[env!("CARGO_BIN_EXE_obfsck"), "scan", "--no-gitleaks"],
        &diff,
    );
    assert_eq!(code, 0, "clean diff must exit 0: {stderr}");
    assert!(stderr.contains("clean"), "expected clean report: {stderr}");
}

/// The deprecated `scan` binary must keep working for existing hooks, but say
/// so and delegate to the same engine.
#[test]
fn deprecated_scan_binary_warns_but_matches_canonical() {
    let diff = diff_with(&format!("+key={AWS_KEY}\n"));
    let (shim_code, shim_stderr) =
        run_scanner(&[env!("CARGO_BIN_EXE_scan"), "--no-gitleaks"], &diff);
    let (canonical_code, canonical_stderr) = run_scanner(
        &[env!("CARGO_BIN_EXE_obfsck"), "scan", "--no-gitleaks"],
        &diff,
    );

    assert_eq!(
        shim_code, canonical_code,
        "exit codes diverged: shim={shim_code} canonical={canonical_code}"
    );
    assert!(
        shim_stderr.contains("deprecated") && shim_stderr.contains("obfsck scan"),
        "shim must name its replacement: {shim_stderr}"
    );
    assert!(
        canonical_stderr.contains("f.txt:1"),
        "canonical output missing location: {canonical_stderr}"
    );
}
