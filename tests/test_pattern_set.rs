use obfsck::{ObfuscationLevel, PatternSet, yaml_config::SecretsConfig};

fn parse_config(yaml: &str) -> SecretsConfig {
    serde_yaml::from_str(yaml).expect("test config should parse")
}

#[test]
fn runtime_patterns_expose_group_provenance() {
    let config = parse_config(
        r#"
groups:
  enabled_group:
    enabled: true
    patterns:
      - name: grouped
        pattern: 'grouped-[0-9]+'
        label: GROUPED
  disabled_group:
    enabled: false
    patterns:
      - name: disabled
        pattern: 'disabled-[0-9]+'
        label: DISABLED
custom:
  - name: custom
    pattern: 'custom-[0-9]+'
    label: CUSTOM
"#,
    );

    let patterns = PatternSet::from_config(&config);

    assert_eq!(patterns.patterns().len(), 2);
    assert_eq!(patterns.patterns()[0].name(), "grouped");
    assert_eq!(patterns.patterns()[0].group(), Some("enabled_group"));
    assert_eq!(patterns.patterns()[1].name(), "custom");
    assert_eq!(patterns.patterns()[1].group(), None);
}

#[test]
fn paranoid_only_normalizes_min_level() {
    let config = parse_config(
        r#"
groups:
  contextual:
    enabled: true
    patterns:
      - name: contextual_secret
        pattern: 'context-[0-9]+'
        label: CONTEXT
        paranoid_only: true
"#,
    );

    let patterns = PatternSet::from_config(&config);

    assert_eq!(
        patterns.patterns()[0].min_level(),
        ObfuscationLevel::Paranoid
    );
    assert!(!patterns.patterns()[0].applies_at(ObfuscationLevel::Standard, true));
    assert!(patterns.patterns()[0].applies_at(ObfuscationLevel::Paranoid, true));
}

#[test]
fn invalid_patterns_are_reported_and_skipped() {
    let config = parse_config(
        r#"
groups:
  invalid:
    enabled: true
    patterns:
      - name: invalid_regex
        pattern: '(?=unsupported-lookahead)'
        label: INVALID
"#,
    );

    let patterns = PatternSet::from_config(&config);

    assert!(patterns.is_empty());
    assert_eq!(patterns.diagnostics().len(), 1);
    assert_eq!(patterns.diagnostics()[0].name(), "invalid_regex");
    assert_eq!(patterns.diagnostics()[0].group(), Some("invalid"));
}
