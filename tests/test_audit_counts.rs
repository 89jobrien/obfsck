//! Double-count guard: ensures `ObfsckAuditor::audit` counts each secret
//! exactly once per pattern (via `SECRET_PATTERN_DEFS` only, never also YAML groups).

use obfsck::mcp::{Auditor, ObfsckAuditor};

/// Run audit twice on identical input — results must be identical (deterministic,
/// no accumulation across calls).
#[test]
fn audit_is_deterministic_no_accumulation() {
    let text = "token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef01\n";

    let auditor = ObfsckAuditor;
    let hits_a = auditor.audit(text);
    let hits_b = auditor.audit(text);

    assert_eq!(
        hits_a, hits_b,
        "repeated audit calls must produce identical results"
    );
}

/// A single GitHub PAT should produce exactly one GITHUB-TOKEN hit with count=1.
/// If double-counting via YAML groups were reintroduced, the count would be 2.
#[test]
fn github_pat_counted_once() {
    // Use a token long enough to match only the github_pat pattern (40 chars after prefix)
    let text = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd";

    let auditor = ObfsckAuditor;
    let hits = auditor.audit(text);

    let gh_hits: Vec<_> = hits.iter().filter(|h| h.label == "GITHUB-TOKEN").collect();
    assert_eq!(
        gh_hits.len(),
        1,
        "expected exactly one GITHUB-TOKEN entry, got: {hits:?}"
    );
    assert_eq!(
        gh_hits[0].count, 1,
        "GITHUB-TOKEN count should be 1 (no double-counting), got: {hits:?}"
    );
}

/// A single Anthropic key should produce exactly one ANTHROPIC-KEY hit with count=1.
#[test]
fn anthropic_key_counted_once() {
    let text = "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";

    let auditor = ObfsckAuditor;
    let hits = auditor.audit(text);

    let ant_hits: Vec<_> = hits.iter().filter(|h| h.label == "ANTHROPIC-KEY").collect();
    assert_eq!(
        ant_hits.len(),
        1,
        "expected exactly one ANTHROPIC-KEY entry, got: {hits:?}"
    );
    assert_eq!(
        ant_hits[0].count, 1,
        "ANTHROPIC-KEY count should be 1 (no double-counting), got: {hits:?}"
    );
}

/// With two distinct secrets, verify that running audit once produces the
/// same result as running it twice — no state leakage or accumulation that
/// could masquerade as double-counting from a YAML+compiled dual iteration.
#[test]
fn two_secrets_stable_counts() {
    let text = concat!(
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd\n",
        "sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx-xxxxxxxx-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
    );

    let auditor = ObfsckAuditor;
    let hits_a = auditor.audit(text);
    let hits_b = auditor.audit(text);

    assert_eq!(
        hits_a, hits_b,
        "audit results must be stable across calls (no accumulation)"
    );

    // The specific-label hits must each be exactly 1.
    let gh = hits_a.iter().find(|h| h.label == "GITHUB-TOKEN");
    let ant = hits_a.iter().find(|h| h.label == "ANTHROPIC-KEY");
    assert_eq!(gh.map(|h| h.count), Some(1), "GITHUB-TOKEN count must be 1");
    assert_eq!(
        ant.map(|h| h.count),
        Some(1),
        "ANTHROPIC-KEY count must be 1"
    );
}
