//! Golden (snapshot) tests for the `redact` CLI binary.
//!
//! Each test runs the binary against a fixture input file and compares the
//! output byte-for-byte with a committed expected file in
//! `tests/fixtures/expected/{level}/{input}`.
//!
//! # Regenerating goldens
//!
//! ```bash
//! UPDATE_GOLDENS=1 cargo test --test golden_tests --features analyzer
//! ```
//!
//! Commit the updated expected files alongside any binary change that alters
//! redaction output.
#![cfg(feature = "analyzer")]

use std::path::Path;
use std::process::Command;

/// Run the `redact` binary against an input file path and return stdout.
fn run_redact(input_path: &str, level: &str) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_redact"))
        .args(["--level", level, input_path])
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn redact: {e}"));

    assert!(
        output.status.success(),
        "redact exited {:?} for input={input_path} level={level}\nstderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    String::from_utf8(output.stdout).unwrap_or_else(|e| panic!("redact stdout was not UTF-8: {e}"))
}

/// Resolve a fixture path relative to the workspace root via `CARGO_MANIFEST_DIR`.
fn fixture_input(filename: &str) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/tests/fixtures/inputs/{filename}")
}

fn expected_path(level: &str, filename: &str) -> String {
    let manifest = env!("CARGO_MANIFEST_DIR");
    format!("{manifest}/tests/fixtures/expected/{level}/{filename}")
}

/// Core of every golden test: diff actual output vs the committed expected file.
/// Set `UPDATE_GOLDENS=1` to overwrite the expected file in-place.
fn assert_golden(input_file: &str, level: &str) {
    let input_path = fixture_input(input_file);
    let actual = run_redact(&input_path, level);

    let expected_file = expected_path(level, input_file);

    if std::env::var("UPDATE_GOLDENS").is_ok() {
        // Create parent directory if it doesn't exist.
        if let Some(parent) = Path::new(&expected_file).parent() {
            std::fs::create_dir_all(parent)
                .unwrap_or_else(|e| panic!("could not create {}: {e}", parent.display()));
        }
        std::fs::write(&expected_file, &actual)
            .unwrap_or_else(|e| panic!("could not write golden {expected_file}: {e}"));
        return;
    }

    let expected = std::fs::read_to_string(&expected_file).unwrap_or_else(|_| {
        panic!(
            "missing golden file: {expected_file}\n\
             Run with UPDATE_GOLDENS=1 to generate it:\n\
             UPDATE_GOLDENS=1 cargo test --test golden_tests --features analyzer"
        )
    });

    assert_eq!(
        actual, expected,
        "golden mismatch for input={input_file} level={level}\n\
         Run with UPDATE_GOLDENS=1 to regenerate:\n\
         UPDATE_GOLDENS=1 cargo test --test golden_tests --features analyzer"
    );
}

// =============================================================================
// pii_sample.txt — PII patterns gated at min_level: standard
// =============================================================================

#[test]
fn pii_minimal() {
    assert_golden("pii_sample.txt", "minimal");
}

#[test]
fn pii_standard() {
    assert_golden("pii_sample.txt", "standard");
}

#[test]
fn pii_paranoid() {
    assert_golden("pii_sample.txt", "paranoid");
}

// =============================================================================
// secrets_sample.txt — Secrets that fire at all levels (minimal+)
// =============================================================================

#[test]
fn secrets_minimal() {
    assert_golden("secrets_sample.txt", "minimal");
}

#[test]
fn secrets_standard() {
    assert_golden("secrets_sample.txt", "standard");
}

#[test]
fn secrets_paranoid() {
    assert_golden("secrets_sample.txt", "paranoid");
}

// =============================================================================
// mixed_sample.txt — Secrets + PII + paranoid + innocent text combined
// =============================================================================

#[test]
fn mixed_minimal() {
    assert_golden("mixed_sample.txt", "minimal");
}

#[test]
fn mixed_standard() {
    assert_golden("mixed_sample.txt", "standard");
}

#[test]
fn mixed_paranoid() {
    assert_golden("mixed_sample.txt", "paranoid");
}

// =============================================================================
// paranoid_sample.txt — paranoid_only patterns and structural paranoid patterns
// =============================================================================

#[test]
fn paranoid_sample_minimal() {
    assert_golden("paranoid_sample.txt", "minimal");
}

#[test]
fn paranoid_sample_standard() {
    assert_golden("paranoid_sample.txt", "standard");
}

#[test]
fn paranoid_sample_paranoid() {
    assert_golden("paranoid_sample.txt", "paranoid");
}

// =============================================================================
// Invariant tests — assertions about level semantics that must always hold
// =============================================================================

/// Core invariant: --level minimal MUST NOT redact standard-gated PII.
///
/// This test directly asserts PII content from `pii_sample.txt` survives
/// unchanged at minimal, regardless of what the golden file contains.
/// A failure here means the PII min_level gate is broken — treat as P0.
///
/// Note: The `Co-Authored-By` git-trailer pattern fires a name redaction at
/// minimal because it belongs to the git-identity group, not the `pii` group.
/// That is expected behavior — only the standard-gated pii patterns are tested.
#[test]
fn invariant_pii_untouched_at_minimal() {
    let input_path = fixture_input("pii_sample.txt");
    let output = run_redact(&input_path, "minimal");

    // Names in plain `author:` / `name=` context are PII-gated at standard.
    assert!(
        output.contains("Jane Smith"),
        "Jane Smith was redacted at minimal — PII min_level invariant broken:\n{output}"
    );
    assert!(
        output.contains("John Doe"),
        "John Doe was redacted at minimal — PII min_level invariant broken:\n{output}"
    );
    // SSN, phone, and credit card must all survive unchanged at minimal.
    assert!(
        output.contains("123-45-6789"),
        "SSN was redacted at minimal — PII min_level invariant broken:\n{output}"
    );
    assert!(
        output.contains("(415) 555-1234"),
        "phone was redacted at minimal — PII min_level invariant broken:\n{output}"
    );
    assert!(
        output.contains("4111111111111111"),
        "credit card was redacted at minimal — PII min_level invariant broken:\n{output}"
    );
    // Tokens that are strictly standard-gated must not appear.
    assert!(
        !output.contains("[REDACTED-SSN"),
        "SSN redaction token appeared at minimal level:\n{output}"
    );
    assert!(
        !output.contains("[REDACTED-PHONE"),
        "phone redaction token appeared at minimal level:\n{output}"
    );
    assert!(
        !output.contains("[REDACTED-CREDIT-CARD"),
        "credit card redaction token appeared at minimal level:\n{output}"
    );
}

/// Secrets MUST be redacted even at minimal level.
///
/// Confirms that the secrets in `secrets_sample.txt` are never passed through
/// at any level.
#[test]
fn invariant_secrets_always_redacted() {
    let input_path = fixture_input("secrets_sample.txt");

    for level in ["minimal", "standard", "paranoid"] {
        let output = run_redact(&input_path, level);

        assert!(
            !output.contains("sk-ant-api03-"),
            "Anthropic key leaked at {level}:\n{output}"
        );
        assert!(
            !output.contains("sk-proj-"),
            "OpenAI key leaked at {level}:\n{output}"
        );
        assert!(
            !output.contains("ghp_"),
            "GitHub PAT leaked at {level}:\n{output}"
        );
        assert!(
            !output.contains("AKIAIOSFODNN7EXAMPLE"),
            "AWS key leaked at {level}:\n{output}"
        );
        assert!(
            !output.contains("glpat-"),
            "GitLab PAT leaked at {level}:\n{output}"
        );
        assert!(
            output.contains("[REDACTED-ANTHROPIC-KEY]"),
            "Anthropic key not redacted at {level}:\n{output}"
        );
        assert!(
            output.contains("[REDACTED-GITHUB-TOKEN]"),
            "GitHub token not redacted at {level}:\n{output}"
        );
    }
}

/// paranoid_only patterns in `paranoid_sample.txt` must NOT fire at minimal or standard.
///
/// Locks in the paranoid_only gate: IBAN, passport, AWS secret key, Telegram
/// token, etc. are preserved at lower levels.
#[test]
fn invariant_paranoid_only_untouched_below_paranoid() {
    let input_path = fixture_input("paranoid_sample.txt");

    for level in ["minimal", "standard"] {
        let output = run_redact(&input_path, level);

        assert!(
            output.contains("GB29NWBK60161331926819"),
            "IBAN was redacted at {level} (paranoid_only violation):\n{output}"
        );
        assert!(
            output.contains("AB1234567"),
            "passport was redacted at {level} (paranoid_only violation):\n{output}"
        );
        assert!(
            !output.contains("[REDACTED-IBAN]"),
            "IBAN redaction token appeared at {level}:\n{output}"
        );
        assert!(
            !output.contains("[REDACTED-AWS-SECRET]"),
            "AWS secret redaction token appeared at {level}:\n{output}"
        );
        assert!(
            !output.contains("[REDACTED-TELEGRAM-BOT]"),
            "Telegram token redaction appeared at {level}:\n{output}"
        );
    }
}

/// paranoid_only patterns MUST fire at paranoid.
#[test]
fn invariant_paranoid_only_fires_at_paranoid() {
    let input_path = fixture_input("paranoid_sample.txt");
    let output = run_redact(&input_path, "paranoid");

    assert!(
        output.contains("[REDACTED-IBAN]"),
        "IBAN not redacted at paranoid:\n{output}"
    );
    assert!(
        output.contains("[REDACTED-AWS-SECRET]"),
        "AWS secret not redacted at paranoid:\n{output}"
    );
    assert!(
        output.contains("[REDACTED-TELEGRAM-BOT]"),
        "Telegram token not redacted at paranoid:\n{output}"
    );
    assert!(
        !output.contains("GB29NWBK60161331926819"),
        "IBAN literal survived at paranoid:\n{output}"
    );
}

/// Innocent context lines must survive at every level.
///
/// Confirms that non-sensitive config values like log_level, service name,
/// and region are never clobbered by redaction patterns.
///
/// Note: at paranoid, version strings like "1.2.3" match the hostname pattern
/// and are redacted — so that assertion is limited to minimal/standard only.
#[test]
fn invariant_innocent_lines_survive_all_levels() {
    // secrets_sample.txt contains clearly innocent lines.
    let input_path = fixture_input("secrets_sample.txt");
    for level in ["minimal", "standard", "paranoid"] {
        let output = run_redact(&input_path, level);
        assert!(
            output.contains(r#"log_level = "debug""#),
            "log_level clobbered at {level}:\n{output}"
        );
        assert!(
            output.contains(r#"service = "payments-api""#),
            "service name clobbered at {level}:\n{output}"
        );
        assert!(
            output.contains(r#"region = "us-east-1""#),
            "region clobbered at {level}:\n{output}"
        );
    }

    // mixed_sample.txt — check values that survive at all levels.
    // Note: at paranoid, "1.2.3" matches the hostname pattern and is redacted.
    // Only assert version at minimal/standard; use other stable values for paranoid.
    let mixed_path = fixture_input("mixed_sample.txt");
    for level in ["minimal", "standard", "paranoid"] {
        let output = run_redact(&mixed_path, level);
        assert!(
            output.contains(r#"service = "billing""#),
            "service clobbered at {level}:\n{output}"
        );
        assert!(
            output.contains(r#"log_level = "warn""#),
            "log_level clobbered at {level}:\n{output}"
        );
    }
    // "1.2.3" looks like a hostname to the paranoid level — only assert at minimal/standard.
    for level in ["minimal", "standard"] {
        let output = run_redact(&mixed_path, level);
        assert!(
            output.contains(r#"version = "1.2.3""#),
            "version clobbered at {level}:\n{output}"
        );
    }
}
