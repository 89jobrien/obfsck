//! Adapter: default in-memory regex pattern source.
//!
//! Provides compiled secret pattern regexes using lazy_regex for efficient
//! initialization on first access.

use crate::SECRET_PATTERN_DEFS;
use crate::ports::PatternSource;
use regex::Regex;
use regex::RegexBuilder;
use std::sync::OnceLock;

pub struct RegexPatternSource;

impl PatternSource for RegexPatternSource {
    fn patterns(&self) -> &[Regex] {
        static PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
        PATTERNS.get_or_init(|| {
            SECRET_PATTERN_DEFS
                .iter()
                .filter_map(|d| {
                    RegexBuilder::new(d.pattern)
                        .case_insensitive(true)
                        .build()
                        .ok()
                })
                .collect()
        })
    }
}
