/// Extract the first complete, non-overlapping JSON object from `raw`.
///
/// Uses a brace-depth state machine so that nested objects are handled
/// correctly and only the outermost object is returned.  Both sibling
/// objects in `{"a":1}{"b":2}` and deeply nested objects in
/// `{"a":{"b":{"c":3}}}` are handled correctly.
///
/// Returns `None` if no balanced `{…}` is found.
pub(crate) fn extract_json_object(raw: &str) -> Option<&str> {
    let start = raw.find('{')?;
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape_next = false;

    for (i, ch) in raw[start..].char_indices() {
        if escape_next {
            escape_next = false;
            continue;
        }
        match ch {
            '\\' if in_string => escape_next = true,
            '"' => in_string = !in_string,
            '{' if !in_string => depth += 1,
            '}' if !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some(&raw[start..start + i + 1]);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_simple_object() {
        assert_eq!(extract_json_object(r#"{"a":1}"#), Some(r#"{"a":1}"#));
    }

    #[test]
    fn extracts_first_of_sibling_objects() {
        let input = r#"{"a":1}{"b":2}"#;
        assert_eq!(extract_json_object(input), Some(r#"{"a":1}"#));
    }

    #[test]
    fn extracts_nested_object() {
        let input = r#"{"outer":{"inner":42}}"#;
        assert_eq!(extract_json_object(input), Some(r#"{"outer":{"inner":42}}"#));
    }

    #[test]
    fn skips_leading_text() {
        let input = r#"prefix {"key":"val"} suffix"#;
        assert_eq!(extract_json_object(input), Some(r#"{"key":"val"}"#));
    }

    #[test]
    fn ignores_braces_in_strings() {
        let input = r#"{"key":"val{not}brace"}"#;
        assert_eq!(
            extract_json_object(input),
            Some(r#"{"key":"val{not}brace"}"#)
        );
    }

    #[test]
    fn returns_none_for_no_object() {
        assert_eq!(extract_json_object("no braces here"), None);
    }

    #[test]
    fn returns_none_for_unbalanced() {
        assert_eq!(extract_json_object(r#"{"unclosed"#), None);
    }
}
