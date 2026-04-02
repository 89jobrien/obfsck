// Smoke test: verifies the generated secrets.rs contains expected pattern names.
// This test will PASS currently (src/secrets.rs exists). After Task 3 deletes
// src/secrets.rs and wires build.rs, it must still pass.

#[test]
fn secret_pattern_defs_non_empty() {
    assert!(
        !obfsck::SECRET_PATTERN_DEFS.is_empty(),
        "SECRET_PATTERN_DEFS must not be empty"
    );
}

#[test]
fn known_patterns_present() {
    let names: Vec<&str> = obfsck::SECRET_PATTERN_DEFS.iter().map(|p| p.name).collect();
    for expected in &[
        "aws_access_key",
        "github_pat",
        "anthropic_api_key",
        "openai_api_key",
        "jwt",
        "postgres_uri",
        "slack_bot_token",
    ] {
        assert!(
            names.contains(expected),
            "Expected pattern '{}' not found in SECRET_PATTERN_DEFS",
            expected
        );
    }
}

#[test]
fn paranoid_only_flag_present() {
    // At least one pattern should be paranoid_only = true (e.g. heroku_api_key, aws_secret_key)
    let has_paranoid = obfsck::SECRET_PATTERN_DEFS.iter().any(|p| p.paranoid_only);
    assert!(has_paranoid, "Expected at least one paranoid_only pattern");
}
