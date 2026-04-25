//! Conformance tests: SecretScanner port boundary.

use obfsck::adapters::gitleaks::GitleaksAdapter;
use obfsck::ports::SecretScanner;

// Trait object safety: SecretScanner can be used as dyn SecretScanner.
#[test]
fn secret_scanner_is_object_safe() {
    let adapter = GitleaksAdapter::new();
    let _dyn_ref: &dyn SecretScanner = &adapter;
}

// Combined gitleaks integration test — single adapter, three scenarios.
// Ignored by default because gitleaks startup is ~50s per invocation.
// Run with: cargo test -- --ignored gitleaks_scan_diff_contracts
#[test]
#[ignore]
fn gitleaks_scan_diff_contracts() {
    let adapter = GitleaksAdapter::new();
    if !adapter.is_available() {
        eprintln!("gitleaks not available, skipping scan_diff tests");
        return;
    }

    // 1. Empty diff → Ok(empty)
    let result = adapter.scan_diff("");
    assert!(result.is_ok(), "scan_diff(\"\") must succeed");
    let findings = result.unwrap();
    assert!(
        findings.is_empty(),
        "empty diff must yield no findings, got: {findings:?}"
    );

    // 2. Clean diff → Ok(empty)
    let clean_diff = r#"diff --git a/foo.rs b/foo.rs
--- a/foo.rs
+++ b/foo.rs
@@ -1 +1 @@
-let x = 1;
+let x = 2;
"#;
    let result = adapter.scan_diff(clean_diff);
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_empty(),
        "clean diff must yield no findings"
    );

    // 3. Diff with secret → findings carry source == "gitleaks"
    let diff_with_secret = concat!(
        "diff --git a/config.txt b/config.txt\n",
        "--- a/config.txt\n",
        "+++ b/config.txt\n",
        "@@ -0,0 +1 @@\n",
        "+token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    );
    let result = adapter.scan_diff(diff_with_secret);
    assert!(result.is_ok(), "scan_diff must not error for a valid diff");
    for finding in result.unwrap() {
        assert_eq!(
            finding.source, "gitleaks",
            "all findings must carry source = 'gitleaks'"
        );
    }
}

// Error path: non-existent binary path returns Err.
#[test]
fn gitleaks_unavailable_binary_returns_err() {
    let adapter = GitleaksAdapter::with_binary("/nonexistent/binary/gitleaks");
    let result = adapter.scan_diff("anything");
    assert!(
        result.is_err(),
        "spawning a non-existent binary must return Err"
    );
}

// is_available() reflects actual binary presence.
#[test]
fn gitleaks_is_available_reflects_binary_presence() {
    let absent = GitleaksAdapter::with_binary("/nonexistent/binary/gitleaks");
    let _ = GitleaksAdapter::new().is_available(); // must not panic
    assert!(
        !absent.is_available(),
        "non-existent binary must not be available"
    );
}
