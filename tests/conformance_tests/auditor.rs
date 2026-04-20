//! Conformance tests: Auditor port boundary.

use obfsck::mcp::{AuditHit, Auditor, ObfsckAuditor};

// Trait object safety.
#[test]
fn auditor_is_object_safe() {
    let adapter = ObfsckAuditor::default();
    let _dyn_ref: &dyn Auditor = &adapter;
}

// Contract: audit("") returns no hits.
#[test]
fn auditor_empty_text_returns_no_hits() {
    let auditor = ObfsckAuditor::default();
    assert!(auditor.audit("").is_empty(), "empty input must yield no hits");
}

// Contract: text with a known secret pattern produces at least one hit.
#[test]
fn auditor_detects_known_secret_pattern() {
    let auditor = ObfsckAuditor::default();
    let text = "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let hits = auditor.audit(text);
    assert!(
        !hits.is_empty(),
        "text containing a known secret pattern must produce hits"
    );
}

// Contract: AuditHit fields are non-empty and count > 0.
#[test]
fn audit_hits_have_valid_fields() {
    let auditor = ObfsckAuditor::default();
    let text = "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    for hit in auditor.audit(text) {
        assert!(!hit.label.is_empty(), "hit label must not be empty");
        assert!(hit.count > 0, "hit count must be > 0");
    }
}

// Contract: hits are sorted by label (deterministic output).
#[test]
fn auditor_hits_are_sorted_by_label() {
    let auditor = ObfsckAuditor::default();
    let text = concat!(
        "token=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa ",
        "key=AKIAIOSFODNN7EXAMPLE ",
    );
    let hits = auditor.audit(text);
    let labels: Vec<&str> = hits.iter().map(|h| h.label.as_str()).collect();
    let mut sorted = labels.clone();
    sorted.sort();
    assert_eq!(labels, sorted, "hits must be returned sorted by label");
}

// Contract: two occurrences of the same pattern yield count >= 2.
#[test]
fn auditor_counts_multiple_occurrences() {
    let auditor = ObfsckAuditor::default();
    let pat = "ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let text = format!("token1={pat} token2={pat}");
    let hits = auditor.audit(&text);
    let total: usize = hits.iter().map(|h| h.count).sum();
    assert!(total >= 2, "two occurrences must produce count >= 2, got {total}");
}

// Contract: AuditHit implements Debug and PartialEq.
#[test]
fn audit_hit_implements_debug_and_eq() {
    let hit = AuditHit { label: "test".to_string(), count: 1 };
    let _ = format!("{hit:?}");
    assert_eq!(hit, AuditHit { label: "test".to_string(), count: 1 });
}
