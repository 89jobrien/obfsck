//! Conformance tests: FilterSuggester port boundary.

use obfsck::mcp::{FilterSuggester, FilterSuggestion, PatternSuggester};

// Trait object safety.
#[test]
fn filter_suggester_is_object_safe() {
    let adapter = PatternSuggester::default();
    let _dyn_ref: &dyn FilterSuggester = &adapter;
}

// Contract: suggest(&[]) returns no suggestions.
#[test]
fn filter_suggester_empty_examples_returns_no_suggestions() {
    let suggester = PatternSuggester::default();
    assert!(
        suggester.suggest(&[]).is_empty(),
        "empty examples must yield no suggestions"
    );
}

// Contract: example with a known secret produces at least one suggestion.
#[test]
fn filter_suggester_known_secret_produces_suggestion() {
    let suggester = PatternSuggester::default();
    let examples = vec!["token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
    let suggestions = suggester.suggest(&examples);
    assert!(
        !suggestions.is_empty(),
        "example containing a known secret must produce at least one suggestion"
    );
}

// Contract: FilterSuggestion fields are non-empty.
#[test]
fn filter_suggestion_fields_are_non_empty() {
    let suggester = PatternSuggester::default();
    let examples = vec!["token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()];
    for sug in suggester.suggest(&examples) {
        assert!(!sug.label.is_empty(), "suggestion label must not be empty");
        assert!(
            !sug.pattern.is_empty(),
            "suggestion pattern must not be empty"
        );
    }
}

// Contract: suggestions are de-duplicated — same label appears at most once.
#[test]
fn filter_suggester_deduplicates_by_label() {
    let suggester = PatternSuggester::default();
    let pat = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let examples: Vec<String> = (0..3).map(|i| format!("token{i}={pat}")).collect();
    let suggestions = suggester.suggest(&examples);
    let labels: Vec<&str> = suggestions.iter().map(|s| s.label.as_str()).collect();
    let unique: std::collections::HashSet<&str> = labels.iter().copied().collect();
    assert_eq!(
        labels.len(),
        unique.len(),
        "suggestions must be de-duplicated by label"
    );
}

// Contract: FilterSuggestion implements Debug.
#[test]
fn filter_suggestion_implements_debug() {
    let sug = FilterSuggestion {
        pattern: "abc".to_string(),
        label: "test".to_string(),
    };
    let _ = format!("{sug:?}");
}
