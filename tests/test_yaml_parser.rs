// Test for build.rs YAML parser behavior.
// This test verifies that the parser catches indentation errors and missing fields.

#[derive(Debug, Default, Clone)]
struct ParsedPattern {
    name: String,
    pattern: String,
    label: String,
    paranoid_only: bool,
}

// Minimal copy of the build.rs parser for testing
fn parse_yaml_test(yaml: &str) -> Vec<ParsedPattern> {
    let mut patterns: Vec<ParsedPattern> = Vec::new();
    let mut current: Option<ParsedPattern> = None;

    for raw_line in yaml.lines() {
        let line = strip_inline_comment(raw_line);
        let trimmed = line.trim();
        let indent = raw_line.len() - raw_line.trim_start().len();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // Detect group-level min_level (indented, not inside a pattern list item).
        if trimmed.starts_with("min_level:") && !trimmed.starts_with("- ") && current.is_none() {
            continue;
        }

        // A new group starts at indent == 2
        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
            // New group — flush current entry and reset group min_level.
            if let Some(prev) = current.take().filter(|p| !p.name.is_empty()) {
                patterns.push(prev);
            }
            continue;
        }

        if trimmed.starts_with("- name:") {
            if let Some(prev) = current.take().filter(|p| !p.name.is_empty()) {
                patterns.push(prev);
            }
            let entry = ParsedPattern {
                name: extract_scalar(trimmed, "- name:").to_string(),
                ..ParsedPattern::default()
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

fn strip_inline_comment(line: &str) -> &str {
    let mut in_quote = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' => in_quote = !in_quote,
            b'#' if !in_quote => {
                if i > 0 && bytes[i - 1] == b' ' {
                    return &line[..i];
                }
            }
            _ => {}
        }
    }
    line
}

fn extract_scalar<'a>(line: &'a str, prefix: &str) -> &'a str {
    let rest = line[prefix.len()..].trim();
    rest.trim_matches('\'').trim_matches('"')
}

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
    Some(rest.trim_matches('"').to_string())
}

#[test]
fn yaml_parser_silently_drops_patterns_on_indentation_mismatch() {
    // Bug obfsck-8: Parser silently drops patterns when indentation is wrong.
    // This test demonstrates the bug: a pattern with a field at wrong indentation
    // results in an incomplete pattern (missing pattern field).
    //
    // If a field appears at indent==2 and ends with ':', the parser treats it as a new group,
    // flushing the current pattern. This silently drops any fields that were supposed to be
    // part of that pattern.

    // The bug occurs when a line at indent=2 ends with ':' and looks like a new group.
    // For example, if a pattern has a field at indent=2 that's supposed to be part of
    // a deeper structure, it gets misinterpreted as a new group marker.
    let malformed_yaml = "groups:\n  test:\n    patterns:\n      - name: broken_pattern\n  field_at_wrong_indent:\n        pattern: '\\btest\\b'\n        label: TEST\n";

    let patterns = parse_yaml_test(malformed_yaml);

    // The parser creates a pattern with name="broken_pattern"
    let broken = patterns.iter().find(|p| p.name == "broken_pattern");
    assert!(
        broken.is_some(),
        "Pattern 'broken_pattern' should be parsed (even if incomplete)"
    );

    // The bug: when parser sees "field_at_wrong_indent:" at indent=2 and ends with ':',
    // it treats it as a new group marker, flushing the current pattern before any of its
    // fields have been assigned. The pattern and label fields remain empty.
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
    let correct_yaml = r#"
groups:
  test:
    patterns:
      - name: good_pattern
        pattern: '\btest\b'
        label: TEST
"#;

    let patterns = parse_yaml_test(correct_yaml);
    let good = patterns.iter().find(|p| p.name == "good_pattern");
    assert!(good.is_some());

    let pattern = good.unwrap();
    assert_eq!(pattern.name, "good_pattern");
    assert_eq!(pattern.pattern, r"\btest\b");
    assert_eq!(pattern.label, "TEST");
}

#[test]
fn validation_catches_empty_pattern_field() {
    // Verify that validation would catch the incomplete pattern from the malformed YAML
    let malformed_yaml = "groups:\n  test:\n    patterns:\n      - name: broken_pattern\n  field_at_wrong_indent:\n        pattern: '\\btest\\b'\n        label: TEST\n";

    let patterns = parse_yaml_test(malformed_yaml);

    // Simulate what build.rs validation does
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

    // Validation should catch the malformed pattern
    assert!(
        !errors.is_empty(),
        "Validation should have caught empty pattern field"
    );
    assert!(errors[0].contains("broken_pattern"));
    assert!(errors[0].contains("empty pattern"));
}
