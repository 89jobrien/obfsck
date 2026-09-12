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
}
