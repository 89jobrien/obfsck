// Smoke test: verifies the generated secrets.rs contains expected pattern names.
// This test will PASS currently (src/secrets.rs exists). After Task 3 deletes
// src/secrets.rs and wires build.rs, it must still pass.

#[test]
fn secret_pattern_defs_is_non_empty() {
    let defs = obfsck::SECRET_PATTERN_DEFS;
    assert!(!defs.is_empty(), "SECRET_PATTERN_DEFS must not be empty");
}

#[test]
fn secret_pattern_defs_contains_known_patterns() {
    let defs = obfsck::SECRET_PATTERN_DEFS;
    let names: Vec<&str> = defs.iter().map(|p| p.name).collect();
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
fn secret_pattern_defs_has_paranoid_only_flag() {
    let defs = obfsck::SECRET_PATTERN_DEFS;
    let has_paranoid = defs.iter().any(|p| p.paranoid_only);
    assert!(has_paranoid, "Expected at least one paranoid_only pattern");
}
