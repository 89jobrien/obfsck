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
            if let Ok(re) = RegexBuilder::new(def.pattern).case_insensitive(true).build() {
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
