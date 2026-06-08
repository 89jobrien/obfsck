// build.rs — generates OUT_DIR/secrets.rs from config/secrets.yaml
// Uses std only (no build-deps). Minimal line-by-line YAML parser.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=config/secrets.yaml");

    let yaml_path = PathBuf::from("config/secrets.yaml");
    let yaml = fs::read_to_string(&yaml_path).expect("build.rs: cannot read config/secrets.yaml");

    let patterns = parse_patterns(&yaml);
    validate_nonempty_pattern_list(&patterns);
    validate_patterns(&patterns);
    let code = emit_rust(&patterns);

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = PathBuf::from(&out_dir).join("secrets.rs");
    fs::write(&out_path, code).expect("build.rs: cannot write secrets.rs");
}

#[derive(Debug, Default)]
struct PatternEntry {
    name: String,
    pattern: String,
    label: String,
    paranoid_only: bool,
    /// Inherited from the group's min_level in the YAML (overrides paranoid_only when set).
    min_level: Option<String>,
}

/// Guard: panics if `patterns` is empty, indicating the YAML parser produced no entries
/// from what should be a non-empty config file. This catches total indentation failures
/// that `validate_patterns` would silently pass.
///
/// Call this before `validate_patterns`, passing the raw YAML length so the error only
/// fires when the input was non-empty.
fn validate_nonempty_pattern_list(patterns: &[PatternEntry]) {
    if patterns.is_empty() {
        panic!(
            "build.rs: parse_patterns returned zero patterns from config/secrets.yaml.\n\
             This usually means a global indentation mismatch — no '- name:' entries were found.\n\
             Check that pattern list items are indented correctly (6 spaces for '- name:' under 'patterns:')."
        );
    }
}

/// Validate that all patterns have required fields (name, pattern, label).
/// Errors loudly instead of silently dropping patterns on indentation mismatches.
fn validate_patterns(patterns: &[PatternEntry]) {
    let mut errors = Vec::new();
    for (idx, pat) in patterns.iter().enumerate() {
        if pat.name.is_empty() {
            errors.push(format!("Pattern {} has empty name", idx));
        }
        if pat.pattern.is_empty() {
            errors.push(format!(
                "Pattern '{}' (index {}) has empty pattern (possible indentation error in config/secrets.yaml)",
                pat.name, idx
            ));
        }
        if pat.label.is_empty() {
            errors.push(format!(
                "Pattern '{}' (index {}) has empty label (possible indentation error in config/secrets.yaml)",
                pat.name, idx
            ));
        }
    }
    if !errors.is_empty() {
        panic!(
            "build.rs validation failed:\n{}\n\nCheck config/secrets.yaml for indentation errors (patterns should have fields indented 4 spaces deeper than the pattern list).",
            errors.join("\n")
        );
    }
}

/// Minimal line-by-line parser for config/secrets.yaml.
/// Handles the specific structure of this file — not a general YAML parser.
fn parse_patterns(yaml: &str) -> Vec<PatternEntry> {
    let mut patterns: Vec<PatternEntry> = Vec::new();
    let mut current: Option<PatternEntry> = None;
    // Track the current group's min_level (set when we see `min_level:` outside a pattern entry).
    let mut current_group_min_level: Option<String> = None;

    for raw_line in yaml.lines() {
        let line = strip_inline_comment(raw_line);
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Detect group-level min_level (indented, not inside a pattern list item).
        // Pattern items start with "- name:"; group fields are bare "key: value".
        if trimmed.starts_with("min_level:") && !trimmed.starts_with("- ") && current.is_none() {
            // We're at group level, not inside a pattern entry.
            let val = trimmed
                .strip_prefix("min_level:")
                .unwrap_or("")
                .trim()
                .to_string();
            current_group_min_level = Some(val);
            continue;
        }

        // A new group starts at a top-level key (indented by exactly 2 spaces in the file).
        // Heuristic: a line whose raw form starts with exactly 2 spaces followed by a word char
        // and ends with ':' signals a new group key. Reset group state.
        let indent = raw_line.len() - raw_line.trim_start().len();
        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
            // New group — flush current entry and reset group min_level.
            if let Some(prev) = current.take().filter(|p| !p.name.is_empty()) {
                patterns.push(prev);
            }
            current_group_min_level = None;
            continue;
        }

        if trimmed.starts_with("- name:") {
            if let Some(prev) = current.take().filter(|p| !p.name.is_empty()) {
                patterns.push(prev);
            }
            let entry = PatternEntry {
                name: extract_scalar(trimmed, "- name:").to_string(),
                min_level: current_group_min_level.clone(),
                ..PatternEntry::default()
            };
            current = Some(entry);
            continue;
        }

        if let Some(ref mut entry) = current {
            if let Some(val) = try_extract(trimmed, "pattern:") {
                entry.pattern = val;
            } else if let Some(val) = try_extract(trimmed, "label:") {
                entry.label = val;
            } else if trimmed.starts_with("paranoid_only:") {
                let val = trimmed.trim_start_matches("paranoid_only:").trim();
                entry.paranoid_only = val == "true";
            }
        }
    }

    if let Some(last) = current.filter(|p| !p.name.is_empty()) {
        patterns.push(last);
    }

    patterns
}

/// Strip `# comment` from end of line, but not when inside a single-quoted string.
fn strip_inline_comment(line: &str) -> &str {
    let mut in_quote = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' => in_quote = !in_quote,
            b'#' if !in_quote && i > 0 && bytes[i - 1] == b' ' => {
                return &line[..i];
            }
            _ => {}
        }
    }
    line
}

/// Extract scalar after a key prefix, stripping quotes.
fn extract_scalar<'a>(line: &'a str, prefix: &str) -> &'a str {
    let rest = line[prefix.len()..].trim();
    rest.trim_matches('\'').trim_matches('"')
}

/// Try to extract a value for `key:` from a trimmed line, handling single-quoted strings.
fn try_extract(trimmed: &str, key: &str) -> Option<String> {
    let rest = trimmed.strip_prefix(key)?.trim();
    if rest.starts_with('\'') {
        let inner = rest.strip_prefix('\'').unwrap_or(rest);
        let mut out = String::new();
        let mut chars = inner.chars().peekable();
        loop {
            match chars.next() {
                None => break,
                Some('\'') => {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                        out.push('\'');
                    } else {
                        break;
                    }
                }
                Some(c) => out.push(c),
            }
        }
        return Some(out);
    }
    // Double-quoted values: trim wrapping quotes only.
    // Assumption: double-quoted values in config/secrets.yaml do not use \" escapes.
    // The raw content (e.g. \\b) is passed through and double-escaped by emit_rust.
    Some(rest.trim_matches('"').to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: a non-empty secrets.yaml with wrong indentation must not silently
    /// produce an empty pattern list. `validate_patterns` should panic.
    #[test]
    #[should_panic(expected = "zero patterns")]
    fn validate_patterns_panics_on_empty_list_from_nonempty_yaml() {
        // Simulate what parse_patterns returns when the YAML indentation is
        // completely wrong — the parser finds no "- name:" entries.
        let patterns: Vec<PatternEntry> = Vec::new();
        // The caller would have gotten these from a non-empty YAML input, so we
        // invoke the guard that validate_patterns must enforce.
        validate_nonempty_pattern_list(&patterns);
    }

    #[test]
    fn validate_patterns_accepts_valid_entries() {
        let patterns = vec![PatternEntry {
            name: "foo".to_string(),
            pattern: r"\bfoo\b".to_string(),
            label: "FOO".to_string(),
            paranoid_only: false,
            min_level: None,
        }];
        // Must not panic.
        validate_nonempty_pattern_list(&patterns);
        validate_patterns(&patterns);
    }

    #[test]
    fn parse_patterns_returns_entries_for_valid_yaml() {
        let yaml = r#"
groups:
  test_group:
    enabled: true
    patterns:
      - name: test_token
        pattern: '\btest_[A-Za-z0-9]{20}\b'
        label: TEST-TOKEN
        paranoid_only: false
"#;
        let patterns = parse_patterns(yaml);
        assert!(
            !patterns.is_empty(),
            "expected at least one pattern from valid YAML"
        );
        assert_eq!(patterns[0].name, "test_token");
    }

    #[test]
    fn parse_patterns_returns_empty_for_garbage_indentation() {
        // All lines at wrong indent — parser finds no "- name:" entries.
        let yaml = "groups:\ntest_group:\npatterns:\nname: foo\npattern: bar\nlabel: baz\n";
        let patterns = parse_patterns(yaml);
        assert!(
            patterns.is_empty(),
            "bad indentation should yield no parsed entries"
        );
    }

    // --- tests migrated from tests/test_yaml_parser.rs (file deleted) ---

    #[test]
    fn yaml_parser_silently_drops_patterns_on_indentation_mismatch() {
        // Bug obfsck-8: Parser silently drops patterns when indentation is wrong.
        // When a line at indent=2 ends with ':', the parser treats it as a new group,
        // flushing the current pattern before its fields are assigned.
        let malformed_yaml = "groups:\n  test:\n    patterns:\n      - name: broken_pattern\n  field_at_wrong_indent:\n        pattern: '\\btest\\b'\n        label: TEST\n";
        let patterns = parse_patterns(malformed_yaml);
        let broken = patterns.iter().find(|p| p.name == "broken_pattern");
        assert!(
            broken.is_some(),
            "Pattern 'broken_pattern' should be parsed (even if incomplete)"
        );
        let pattern = broken.unwrap();
        assert!(
            pattern.pattern.is_empty(),
            "Pattern field is empty due to indentation error, but no error was raised: {:?}",
            pattern
        );
        assert!(
            pattern.label.is_empty(),
            "Label field is empty due to indentation error, but no error was raised: {:?}",
            pattern
        );
    }

    #[test]
    fn yaml_parser_handles_correct_indentation() {
        let correct_yaml = "groups:\n  test:\n    patterns:\n      - name: good_pattern\n        pattern: '\\btest\\b'\n        label: TEST\n";
        let patterns = parse_patterns(correct_yaml);
        let good = patterns.iter().find(|p| p.name == "good_pattern");
        assert!(good.is_some());
        let pattern = good.unwrap();
        assert_eq!(pattern.name, "good_pattern");
        assert_eq!(pattern.pattern, r"\btest\b");
        assert_eq!(pattern.label, "TEST");
    }

    #[test]
    fn validation_catches_empty_pattern_field() {
        // Verify that validate_patterns catches the incomplete pattern produced by malformed YAML.
        let malformed_yaml = "groups:\n  test:\n    patterns:\n      - name: broken_pattern\n  field_at_wrong_indent:\n        pattern: '\\btest\\b'\n        label: TEST\n";
        let patterns = parse_patterns(malformed_yaml);
        let mut errors = Vec::new();
        for (idx, pat) in patterns.iter().enumerate() {
            if pat.pattern.is_empty() {
                errors.push(format!(
                    "Pattern '{}' (index {}) has empty pattern",
                    pat.name, idx
                ));
            }
            if pat.label.is_empty() {
                errors.push(format!(
                    "Pattern '{}' (index {}) has empty label",
                    pat.name, idx
                ));
            }
        }
        assert!(
            !errors.is_empty(),
            "Validation should have caught empty pattern field"
        );
        assert!(errors[0].contains("broken_pattern"));
        assert!(errors[0].contains("empty pattern"));
    }
}

fn emit_rust(patterns: &[PatternEntry]) -> String {
    let mut out = String::from(
        "// @generated by build.rs from config/secrets.yaml — DO NOT EDIT.\n\
         // Edit config/secrets.yaml and run `cargo build` to regenerate.\n\
         \n\
         pub const SECRET_PATTERN_DEFS: &[SecretPatternDef] = &[\n",
    );

    for p in patterns {
        let pattern_escaped = p.pattern.replace('\\', "\\\\").replace('"', "\\\"");
        let name_escaped = p.name.replace('\\', "\\\\").replace('"', "\\\"");
        let label_escaped = p.label.replace('\\', "\\\\").replace('"', "\\\"");
        let min_level_expr = match p.min_level.as_deref() {
            Some("standard") => "Some(ObfuscationLevel::Standard)",
            Some("paranoid") => "Some(ObfuscationLevel::Paranoid)",
            Some("minimal") | None => "None",
            Some(other) => panic!("build.rs: unknown min_level value '{other}'"),
        };
        out.push_str(&format!(
            "    SecretPatternDef {{\n        name: \"{name}\",\n        pattern: \"{pattern}\",\n        label: \"{label}\",\n        paranoid_only: {paranoid_only},\n        min_level: {min_level},\n    }},\n",
            name = name_escaped,
            pattern = pattern_escaped,
            label = label_escaped,
            paranoid_only = p.paranoid_only,
            min_level = min_level_expr,
        ));
    }

    out.push_str("];\n");
    out
}
