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
