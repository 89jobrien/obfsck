//! Hexagonal architecture ports.
//!
//! Ports define the boundaries between the domain and adapters
//! (e.g. secret scanners).

/// A single secret finding from a scanner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Human-readable description of what was found (e.g. pattern label or rule name).
    pub description: String,
    /// The offending line content where the secret was found, if available.
    pub location: Option<String>,
    /// 1-based line number within the scanned input, if available.
    pub line_number: Option<usize>,
    /// Source adapter that produced this finding (e.g. "obfsck", "gitleaks").
    pub source: String,
}

impl Finding {
    /// Construct a finding with no location information.
    pub fn new(source: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            description: description.into(),
            location: None,
            line_number: None,
            source: source.into(),
        }
    }

    /// Construct a finding with source, description, location, and line number.
    pub fn with_location(
        source: impl Into<String>,
        description: impl Into<String>,
        location: String,
        line_number: usize,
    ) -> Self {
        Self {
            description: description.into(),
            location: Some(location),
            line_number: Some(line_number),
            source: source.into(),
        }
    }
}

/// Port: abstraction for scanning diff text for secrets.
///
/// Adapters implement this for the native Obfuscator scanner, gitleaks, etc.
/// Receives a full unified diff (e.g. from `git diff --staged`) as a string.
pub trait SecretScanner: Send + Sync {
    /// Scan the provided diff text and return all findings.
    fn scan_diff(&self, diff: &str) -> Result<Vec<Finding>>;
}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
