use obfsck::ObfuscationLevel;
use obfsck::yaml_config::SecretsConfig;
use regex::{Regex, RegexBuilder};

fn apply_yaml_patterns(yaml: &str, input: &str, level: ObfuscationLevel) -> String {
    let config: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
    let is_paranoid = level == ObfuscationLevel::Paranoid;

    let patterns: Vec<(Regex, String)> = config
        .groups
        .values()
        .filter(|g| g.enabled)
        .flat_map(|g| g.patterns.iter())
        .chain(config.custom.iter())
        .filter(|p| !p.paranoid_only || is_paranoid)
        .filter_map(|p| {
            RegexBuilder::new(&p.pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| eprintln!("Bad pattern '{}': {e}", p.name))
                .ok()
                .map(|re| (re, format!("[REDACTED-{}]", p.label)))
        })
        .collect();

    let mut text = input.to_string();
    for (re, replacement) in &patterns {
        text = re.replace_all(&text, replacement.as_str()).into_owned();
    }
    text
}

#[test]
fn test_anthropic_key_redacted() {
    let yaml = include_str!("../config/secrets.yaml");
    // 40-char suffix satisfies {32,}
    let input = "key=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(result.contains("[REDACTED-ANTHROPIC-KEY]"), "got: {result}");
    assert!(!result.contains("sk-ant"), "key leaked: {result}");
}

#[test]
fn test_openai_key_redacted() {
    let yaml = include_str!("../config/secrets.yaml");
    let input = "OPENAI_API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(result.contains("[REDACTED-OPENAI-KEY]"), "got: {result}");
    assert!(!result.contains("sk-proj"), "key leaked: {result}");
}

#[test]
fn test_pii_disabled_by_default() {
    let yaml = include_str!("../config/secrets.yaml");
    let input = "ssn=123-45-6789 card=4111111111111111";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(
        result.contains("123-45-6789"),
        "SSN should not be redacted (pii off): {result}"
    );
    assert!(
        result.contains("4111111111111111"),
        "CC should not be redacted (pii off): {result}"
    );
}

#[test]
fn test_paranoid_only_not_applied_at_minimal() {
    let yaml = include_str!("../config/secrets.yaml");
    // 40-char hex matches aws_secret_key paranoid pattern
    let input = "val=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(
        result.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "paranoid pattern should not fire at minimal: {result}"
    );
}

#[test]
fn test_paranoid_only_applied_at_paranoid_level() {
    let yaml = include_str!("../config/secrets.yaml");
    // 40-char hex matches aws_secret_key paranoid pattern
    let input = "val=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Paranoid);
    assert!(
        !result.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "paranoid pattern should fire at paranoid level: {result}"
    );
}

#[test]
fn test_custom_patterns_applied() {
    let yaml = r#"
groups: {}
custom:
  - name: internal_token
    pattern: '\bMYCO-[A-Za-z0-9]{16}\b'
    label: INTERNAL-TOKEN
    paranoid_only: false
"#;
    let input = "token=MYCO-abcd1234efgh5678";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(
        result.contains("[REDACTED-INTERNAL-TOKEN]"),
        "got: {result}"
    );
}

#[test]
fn test_disabled_group_not_applied() {
    let yaml = r#"
groups:
  ai_apis:
    enabled: false
    patterns:
      - name: openai_api_key
        pattern: '\bsk-[A-Za-z0-9_-]{32,}\b'
        label: OPENAI-KEY
        paranoid_only: false
custom: []
"#;
    let input = "key=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(
        !result.contains("[REDACTED-OPENAI-KEY]"),
        "disabled group was applied: {result}"
    );
}
