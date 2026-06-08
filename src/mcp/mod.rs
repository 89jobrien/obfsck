pub mod protocol;

use crate::SECRET_PATTERN_DEFS;
use regex::RegexBuilder;

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditHit {
    pub label: String,
    pub count: usize,
}

#[derive(Debug, Clone)]
pub struct FilterSuggestion {
    pub pattern: String,
    pub label: String,
}

// ---------------------------------------------------------------------------
// Ports (traits)
// ---------------------------------------------------------------------------

pub trait Auditor {
    fn audit(&self, text: &str) -> Vec<AuditHit>;
}

pub trait FilterSuggester {
    fn suggest(&self, examples: &[String]) -> Vec<FilterSuggestion>;
}

// ---------------------------------------------------------------------------
// ObfsckAuditor adapter
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct ObfsckAuditor;

impl Auditor for ObfsckAuditor {
    fn audit(&self, text: &str) -> Vec<AuditHit> {
        // Use the authoritative compiled pattern set (SECRET_PATTERN_DEFS) only.
        // The YAML config patterns are generated from the same source, so using
        // both would double-count every hit.
        let mut counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

        for def in SECRET_PATTERN_DEFS {
            if let Ok(re) = RegexBuilder::new(def.pattern)
                .case_insensitive(true)
                .build()
            {
                let n = re.find_iter(text).count();
                if n > 0 {
                    *counts.entry(def.label.to_string()).or_insert(0) += n;
                }
            }
        }

        let mut hits: Vec<AuditHit> = counts
            .into_iter()
            .map(|(label, count)| AuditHit { label, count })
            .collect();
        hits.sort_by(|a, b| a.label.cmp(&b.label));
        hits
    }
}

// ---------------------------------------------------------------------------
// PatternSuggester adapter
// ---------------------------------------------------------------------------
// NOTE: The audit pass MUST iterate SECRET_PATTERN_DEFS exactly once.
// The YAML config groups are generated from the same source at build time;
// iterating both would double-count every hit. Tests below enforce this invariant.

#[derive(Default)]
pub struct PatternSuggester;

impl FilterSuggester for PatternSuggester {
    fn suggest(&self, examples: &[String]) -> Vec<FilterSuggestion> {
        // Strategy: run audit on each example; for every hit, propose the
        // compiled pattern from SECRET_PATTERN_DEFS as the suggested filter.
        // De-duplicate by label.
        let auditor = ObfsckAuditor;
        let mut seen = std::collections::HashSet::new();
        let mut suggestions = Vec::new();

        for example in examples {
            let hits = auditor.audit(example);
            for hit in hits {
                if seen.contains(&hit.label) {
                    continue;
                }
                // Find the source pattern def for this label
                if let Some(def) = SECRET_PATTERN_DEFS.iter().find(|d| d.label == hit.label) {
                    seen.insert(hit.label.clone());
                    suggestions.push(FilterSuggestion {
                        pattern: def.pattern.to_string(),
                        label: hit.label,
                    });
                }
            }
        }

        suggestions
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{Auditor, ObfsckAuditor};

    /// Asserts that no label appears more than once in the audit results.
    ///
    /// SECRET_PATTERN_DEFS is the single source of patterns; if the audit pass
    /// were also to iterate the YAML config groups (built from the same source),
    /// every label would appear twice. This test detects that regression by
    /// verifying the hits Vec contains no duplicate labels.
    ///
    /// Concrete inputs:
    /// - One ANTHROPIC-KEY token (`sk-ant-api03-…`)
    /// - One GITHUB-TOKEN token (`ghp_…`)
    ///
    /// Other broad patterns (paranoid_only) may also fire; that is expected.
    /// The invariant is: each label appears at most once, and the expected
    /// labels each carry a count of exactly 1 (one occurrence in the input).
    #[test]
    fn audit_counts_each_secret_label_exactly_once() {
        // sk-ant-api03- prefix satisfies the anthropic_api_key pattern.
        let anthropic = "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        // ghp_ prefix + 36 alphanum satisfies github_pat.
        let github = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

        let input = format!("key1={anthropic} key2={github}");
        let auditor = ObfsckAuditor;
        let hits = auditor.audit(&input);

        // No label must appear more than once — double iteration of pattern
        // sources would produce duplicate AuditHit entries for the same label.
        let mut seen_labels = std::collections::HashSet::new();
        for hit in &hits {
            assert!(
                seen_labels.insert(hit.label.as_str()),
                "label '{}' appeared more than once in audit results — \
                 possible double-count from iterating pattern source twice: {hits:?}",
                hit.label
            );
        }

        // The two explicitly placed secrets must be present.
        let labels: Vec<&str> = hits.iter().map(|h| h.label.as_str()).collect();
        assert!(
            labels.contains(&"ANTHROPIC-KEY"),
            "ANTHROPIC-KEY hit missing: {labels:?}"
        );
        assert!(
            labels.contains(&"GITHUB-TOKEN"),
            "GITHUB-TOKEN hit missing: {labels:?}"
        );

        // Each of the expected hits must have count == 1 (one token in input).
        for hit in hits
            .iter()
            .filter(|h| h.label == "ANTHROPIC-KEY" || h.label == "GITHUB-TOKEN")
        {
            assert_eq!(
                hit.count, 1,
                "label {} count should be 1, got {} — possible double-count",
                hit.label, hit.count
            );
        }
    }

    /// Verifies that a single secret appearing once registers a count of 1,
    /// and the same input processed twice does not accumulate state across
    /// separate Auditor invocations.
    #[test]
    fn audit_is_stateless_across_invocations() {
        let input = "token=ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let auditor = ObfsckAuditor;

        let first = auditor.audit(input);
        let second = auditor.audit(input);

        assert_eq!(first, second, "audit result must be identical across calls");
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].count, 1);
    }
}
