use crate::yaml_config::{MinLevel, SecretsConfig};
use crate::{ObfuscationLevel, SECRET_PATTERN_DEFS};
use regex::{Regex, RegexBuilder};

/// A compiled secret-matching pattern with source provenance and level metadata.
#[derive(Debug, Clone)]
pub struct Pattern {
    name: String,
    group: Option<String>,
    expression: String,
    label: String,
    min_level: ObfuscationLevel,
    regex: Regex,
}

impl Pattern {
    /// Returns the configured pattern name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the source group, or `None` for a custom pattern.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Returns the original regular expression.
    pub fn expression(&self) -> &str {
        &self.expression
    }

    /// Returns the redaction label without wrapper text.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the minimum obfuscation level required by this pattern.
    pub fn min_level(&self) -> ObfuscationLevel {
        self.min_level
    }

    /// Returns the compiled regular expression.
    pub fn regex(&self) -> &Regex {
        &self.regex
    }

    /// Returns whether this pattern applies at the requested level and PII setting.
    pub fn applies_at(&self, level: ObfuscationLevel, pii: bool) -> bool {
        match self.min_level {
            ObfuscationLevel::Minimal => true,
            ObfuscationLevel::Standard => {
                pii && matches!(
                    level,
                    ObfuscationLevel::Standard | ObfuscationLevel::Paranoid
                )
            }
            ObfuscationLevel::Paranoid => level == ObfuscationLevel::Paranoid,
        }
    }
}

/// An ordered collection of compiled patterns and non-fatal compilation diagnostics.
#[derive(Debug, Clone)]
pub struct PatternSet {
    patterns: Vec<Pattern>,
    diagnostics: Vec<PatternCompileError>,
}

impl PatternSet {
    /// Compiles the bundled pattern definitions generated at build time.
    pub fn bundled() -> Self {
        let definitions = SECRET_PATTERN_DEFS.iter().map(|definition| {
            (
                definition.name,
                None,
                definition.pattern,
                definition.label,
                definition.paranoid_only,
                definition.min_level.unwrap_or(ObfuscationLevel::Minimal),
            )
        });
        Self::compile(definitions)
    }

    /// Compiles enabled grouped patterns and custom patterns from a runtime configuration.
    pub fn from_config(config: &SecretsConfig) -> Self {
        let grouped = config
            .groups
            .iter()
            .filter(|(_, group)| group.enabled)
            .flat_map(|(group_name, group)| {
                let min_level = min_level(group.min_level);
                group.patterns.iter().map(move |definition| {
                    (
                        definition.name.as_str(),
                        Some(group_name.as_str()),
                        definition.pattern.as_str(),
                        definition.label.as_str(),
                        definition.paranoid_only,
                        min_level,
                    )
                })
            });
        let custom = config.custom.iter().map(|definition| {
            (
                definition.name.as_str(),
                None,
                definition.pattern.as_str(),
                definition.label.as_str(),
                definition.paranoid_only,
                ObfuscationLevel::Minimal,
            )
        });

        Self::compile(grouped.chain(custom))
    }

    /// Returns compiled patterns in source order.
    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    /// Returns diagnostics for definitions that could not be compiled.
    pub fn diagnostics(&self) -> &[PatternCompileError] {
        &self.diagnostics
    }

    /// Returns true when no definitions compiled successfully.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    fn compile<'a>(
        definitions: impl IntoIterator<
            Item = (
                &'a str,
                Option<&'a str>,
                &'a str,
                &'a str,
                bool,
                ObfuscationLevel,
            ),
        >,
    ) -> Self {
        let mut patterns = Vec::new();
        let mut diagnostics = Vec::new();

        for (name, group, expression, label, paranoid_only, configured_min_level) in definitions {
            match RegexBuilder::new(expression).case_insensitive(true).build() {
                Ok(regex) => patterns.push(Pattern {
                    name: name.to_owned(),
                    group: group.map(str::to_owned),
                    expression: expression.to_owned(),
                    label: label.to_owned(),
                    min_level: if paranoid_only {
                        ObfuscationLevel::Paranoid
                    } else {
                        configured_min_level
                    },
                    regex,
                }),
                Err(error) => diagnostics.push(PatternCompileError {
                    name: name.to_owned(),
                    group: group.map(str::to_owned),
                    message: error.to_string(),
                }),
            }
        }

        Self {
            patterns,
            diagnostics,
        }
    }
}

/// Describes a pattern definition that could not be compiled.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid pattern '{name}' in group {group:?}: {message}")]
pub struct PatternCompileError {
    name: String,
    group: Option<String>,
    message: String,
}

impl PatternCompileError {
    /// Returns the configured pattern name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the source group, or `None` for a custom pattern.
    pub fn group(&self) -> Option<&str> {
        self.group.as_deref()
    }

    /// Returns the regex compiler message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

fn min_level(level: Option<MinLevel>) -> ObfuscationLevel {
    match level {
        None | Some(MinLevel::Minimal) => ObfuscationLevel::Minimal,
        Some(MinLevel::Standard) => ObfuscationLevel::Standard,
        Some(MinLevel::Paranoid) => ObfuscationLevel::Paranoid,
    }
}
