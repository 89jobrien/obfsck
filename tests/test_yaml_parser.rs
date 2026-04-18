// Test for build.rs YAML parser behavior (Issue #3).
// Verifies that the parser catches indentation errors via validate_patterns()
// rather than silently dropping patterns with missing fields.

#[derive(Debug, Default, Clone)]
struct ParsedPattern {
    name: String,
    pattern: String,
    label: String,
    paranoid_only: bool,
}

// Minimal copy of the build.rs parser and validator for testing.
// Must stay in sync with build.rs logic.
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

        if trimmed.starts_with("min_level:") && !trimmed.starts_with("- ") && current.is_none() {
            continue;
        }

        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('-') {
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

/// Mirror of build.rs validate_patterns — returns errors instead of panicking.
fn validate_patterns_test(patterns: &[ParsedPattern]) -> Vec<String> {
    let mut errors = Vec::new();
    for (idx, pat) in patterns.iter().enumerate() {
        if pat.name.is_empty() {
            errors.push(format!("Pattern {} has empty name", idx));
        }
        if pat.pattern.is_empty() {
            errors.push(format!(
                "Pattern '{}' (index {}) has empty pattern field \
                 (possible indentation error in config/secrets.yaml)",
                pat.name, idx
            ));
        }
        if pat.label.is_empty() {
            errors.push(format!(
                "Pattern '{}' (index {}) has empty label field \
                 (possible indentation error in config/secrets.yaml)",
                pat.name, idx
            ));
        }
    }
    errors
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

// Issue #3: parser silently drops pattern/label fields when indentation is wrong.
// This test documents the existing silent-drop behavior to ensure validate_patterns()
// catches it.
#[test]
fn yaml_parser_silently_drops_patterns_on_indentation_mismatch() {
    // A line at indent==2 that ends with ':' is misinterpreted as a new group header,
    // flushing the current pattern before its fields are set.
    let malformed_yaml = concat!(
        "groups:\n",
        "  test:\n",
        "    patterns:\n",
        "      - name: broken_pattern\n",
        "  looks_like_group:\n", // indent=2, ends ':' — triggers group flush
        "        pattern: '\\btest\\b'\n",
        "        label: TEST\n",
    );

    let patterns = parse_yaml_test(malformed_yaml);
    let broken = patterns.iter().find(|p| p.name == "broken_pattern");
    assert!(
        broken.is_some(),
        "Pattern 'broken_pattern' should be present (even if incomplete)"
    );

    let pat = broken.unwrap();
    // The fields were at the wrong indentation — they weren't assigned.
    assert!(
        pat.pattern.is_empty(),
        "pattern field should be empty due to indentation mismatch: {:?}",
        pat
    );
}

#[test]
fn yaml_parser_handles_correct_indentation() {
    let yaml = concat!(
        "groups:\n",
        "  test:\n",
        "    patterns:\n",
        "      - name: good_pattern\n",
        "        pattern: '\\btest\\b'\n",
        "        label: TEST\n",
    );

    let patterns = parse_yaml_test(yaml);
    let good = patterns.iter().find(|p| p.name == "good_pattern");
    assert!(good.is_some(), "good_pattern should be parsed");

    let pat = good.unwrap();
    assert_eq!(pat.pattern, r"\btest\b");
    assert_eq!(pat.label, "TEST");
}

// Issue #3 fix: validate_patterns() must catch patterns with empty fields.
#[test]
fn validation_catches_empty_pattern_field() {
    let malformed_yaml = concat!(
        "groups:\n",
        "  test:\n",
        "    patterns:\n",
        "      - name: broken_pattern\n",
        "  looks_like_group:\n",
        "        pattern: '\\btest\\b'\n",
        "        label: TEST\n",
    );

    let patterns = parse_yaml_test(malformed_yaml);
    let errors = validate_patterns_test(&patterns);

    assert!(
        !errors.is_empty(),
        "validate_patterns should have caught empty pattern/label fields"
    );
    assert!(
        errors.iter().any(|e| e.contains("broken_pattern")),
        "error should identify the pattern by name: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("empty pattern")),
        "error should mention empty pattern: {:?}",
        errors
    );
}
