//! Inline suppression markers.
//!
//! Test fixtures and examples legitimately contain credential-shaped strings
//! (`AKIAIOSFODNN7EXAMPLE`, `ghp_aaa…`) that are not secrets. Listing every one
//! in an allowlist file works but does not travel with the code, so a reviewer
//! reading the fixture cannot see why it is safe.
//!
//! An inline marker keeps the justification next to the value:
//!
//! ```text
//! let key = "AKIAIOSFODNN7EXAMPLE"; // obfsck:ignore
//! ```
//!
//! The marker is matched as a bare token anywhere in the line rather than
//! requiring a comment sigil, so it works unchanged in Rust (`#`), Python and
//! YAML (`#`), TOML and shell (`#`), and JS/C (`//`) without a per-language
//! table.
//!
//! Scope is the whole line. That matches `gitleaks:allow` and `noqa` precedent:
//! the line is an assertion that this is fixture data, and honouring only the
//! matched token would leave the line partially rewritten, which is harder to
//! reason about than either extreme.

/// The marker token. Matched case-insensitively, with optional whitespace
/// around the colon, so `obfsck:ignore` and `obfsck: ignore` both work.
const MARKER: &str = "obfsck";

/// True if `c` continues an identifier, so it terminates the marker token.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Returns true if `line` carries an inline `obfsck:ignore` marker.
///
/// ```
/// assert!(obfsck::suppression::is_suppressed_line("k = \"AKIA1\"  # obfsck:ignore"));
/// assert!(obfsck::suppression::is_suppressed_line("k = \"AKIA1\"  // obfsck: ignore"));
/// assert!(!obfsck::suppression::is_suppressed_line("k = \"AKIA1\""));
/// assert!(!obfsck::suppression::is_suppressed_line("see obfsck:ignored tokens"));
/// ```
pub fn is_suppressed_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let mut from = 0usize;

    while let Some(idx) = lower[from..].find(MARKER) {
        let after = &lower[from + idx + MARKER.len()..];
        if let Some(rest) = after.trim_start().strip_prefix(':') {
            let rest = rest.trim_start();
            if let Some(tail) = rest.strip_prefix("ignore") {
                // Require a word boundary: `obfsck:ignore` and `obfsck:ignore,`
                // are markers, but `obfsck:ignored`, `obfsck:ignores`, and
                // `obfsck:ignore_this` are prose or an identifier and must not
                // silently suppress a line. `_` counts as a word character
                // because it is one in every language this marker applies to.
                if tail.chars().next().is_none_or(|c| !is_word_char(c)) {
                    return true;
                }
            }
        }
        // Only advance past the token itself: overlapping candidates such as
        // "obfsckobfsck:ignore" still need the inner occurrence to be seen.
        from += idx + MARKER.len();
    }

    false
}

/// Returns true if any line in `text` carries the marker.
///
/// Callers use this as a cheap gate before switching to line-by-line
/// processing, so the common case keeps whole-text behaviour and its
/// cross-line matching intact.
pub fn has_marker(text: &str) -> bool {
    text.lines().any(is_suppressed_line)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_marker_is_detected() {
        assert!(is_suppressed_line(r#"k = "AKIA1" # obfsck:ignore"#));
    }

    #[test]
    fn space_after_colon_is_allowed() {
        assert!(is_suppressed_line(r#"k = "AKIA1" # obfsck: ignore"#));
    }

    #[test]
    fn no_space_before_colon_is_allowed() {
        assert!(is_suppressed_line("k = \"AKIA1\" #obfsck:ignore"));
    }

    #[test]
    fn marker_case_is_ignored() {
        assert!(is_suppressed_line("k = \"AKIA1\" # Obfsck:Ignore"));
        assert!(is_suppressed_line("k = \"AKIA1\" # OBFSCK:IGNORE"));
    }

    #[test]
    fn works_without_hash_comment_sigil() {
        assert!(is_suppressed_line("k = \"AKIA1\" // obfsck:ignore"));
        assert!(is_suppressed_line("<!-- obfsck:ignore -->"));
    }

    #[test]
    fn marker_before_the_value_on_same_line_is_detected() {
        assert!(is_suppressed_line(r#"obfsck:ignore k = "AKIA1""#));
    }

    #[test]
    fn unmarked_line_is_not_suppressed() {
        assert!(!is_suppressed_line(r#"k = "AKIA1""#));
    }

    #[test]
    fn marker_at_end_of_crlf_line_is_detected() {
        // The trailing "\r\n" must not defeat the word-boundary check: "\r" is
        // not alphanumeric, so a marker ending the line still matches.
        assert!(is_suppressed_line("k = \"AKIA1\" # obfsck:ignore\r\n"));
        assert!(is_suppressed_line("k = \"AKIA1\" # obfsck:ignore\r"));
        assert!(is_suppressed_line("k = \"AKIA1\" # obfsck:ignore\n"));
    }

    #[test]
    fn has_marker_sees_marker_in_crlf_block() {
        let text = "a = x\r\nb = y # obfsck:ignore\r\nc = z\r\n";
        assert!(has_marker(text));
    }

    #[test]
    fn word_boundary_is_required_after_ignore() {
        // `ignored` / `ignores` are prose, not the marker, and must not
        // silently suppress a line that still contains a real secret.
        assert!(!is_suppressed_line("see obfsck:ignored tokens"));
        assert!(!is_suppressed_line("see obfsck:ignores tokens"));
        assert!(!is_suppressed_line("# obfsck:ignore_this"));
    }

    #[test]
    fn marker_followed_by_punctuation_or_eol_still_matches() {
        assert!(is_suppressed_line("# obfsck:ignore"));
        assert!(is_suppressed_line("# obfsck:ignore,"));
        assert!(is_suppressed_line("# obfsck:ignore."));
        assert!(is_suppressed_line("# obfsck:ignore "));
    }

    #[test]
    fn prose_mentioning_the_exact_marker_does_suppress() {
        // Documented tradeoff of matching the bare token anywhere in the line
        // rather than requiring a comment sigil: a line that talks about the
        // marker is treated as suppressed. This only over-suppresses prose,
        // where there is no secret to leak.
        assert!(is_suppressed_line("// we should obfsck:ignore this later"));
    }

    #[test]
    fn marker_without_ignore_suffix_is_not_a_marker() {
        assert!(!is_suppressed_line("# obfsck:redact"));
        assert!(!is_suppressed_line("# obfsck"));
        assert!(!is_suppressed_line("# obfsckignore"));
    }

    #[test]
    fn overlapping_token_candidates_are_checked() {
        assert!(is_suppressed_line("# obfsckobfsck:ignore"));
    }

    #[test]
    fn has_marker_finds_marker_anywhere_in_block() {
        assert!(has_marker("line one\nline two # obfsck:ignore\nline three"));
    }

    #[test]
    fn has_marker_is_false_for_clean_text() {
        assert!(!has_marker("line one\nline two\nline three"));
        assert!(!has_marker(""));
    }
}
