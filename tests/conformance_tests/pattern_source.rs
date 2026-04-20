//! Conformance tests: PatternSource port boundary.

use obfsck::adapters::regex_patterns::RegexPatternSource;
use obfsck::ports::PatternSource;

// Trait object safety: PatternSource can be used as dyn PatternSource.
#[test]
fn pattern_source_is_object_safe() {
    let adapter = RegexPatternSource;
    let _dyn_ref: &dyn PatternSource = &adapter;
}

// Contract: patterns() must return a non-empty slice.
#[test]
fn regex_pattern_source_returns_non_empty_patterns() {
    let source = RegexPatternSource;
    let patterns = source.patterns();
    assert!(
        !patterns.is_empty(),
        "RegexPatternSource must return at least one compiled pattern"
    );
}

// Contract: all returned values are valid compiled Regexes (non-empty source strings).
#[test]
fn regex_pattern_source_patterns_are_compiled() {
    let source = RegexPatternSource;
    for (i, re) in source.patterns().iter().enumerate() {
        assert!(
            !re.as_str().is_empty(),
            "pattern at index {i} has an empty source string"
        );
    }
}

// Idempotency: two calls return slices of the same length (OnceLock guarantee).
#[test]
fn regex_pattern_source_is_idempotent() {
    let source = RegexPatternSource;
    let first = source.patterns().len();
    let second = source.patterns().len();
    assert_eq!(
        first, second,
        "patterns() must return a stable slice on repeated calls"
    );
}
