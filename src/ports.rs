//! Hexagonal architecture ports.
//!
//! Ports define the boundaries between the domain (Obfuscator) and adapters
//! (pattern sources, log clients, etc.).

use regex::Regex;

/// Port: abstraction for loading obfuscation pattern regexes.
///
/// Adapters implement this to provide pattern sources from various origins
/// (in-memory defaults, YAML config, etc.).
pub trait PatternSource {
    /// Return a slice of compiled regex patterns.
    fn patterns(&self) -> &[Regex];
}

/// Port: abstraction for sending log entries to external log aggregators.
///
/// Adapters implement this for Loki, VictoriaLogs, etc.
pub trait LogClient: Send + Sync {
    fn send(&self, entry: &LogEntry) -> Result<()>;
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub message: String,
}

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

/// Port: abstraction for scanning diff text for secrets.
///
/// Adapters implement this for the native Obfuscator scanner, gitleaks, etc.
/// Receives a full unified diff (e.g. from `git diff --staged`) as a string.
pub trait SecretScanner: Send + Sync {
    /// Scan the provided diff text and return all findings.
    fn scan_diff(&self, diff: &str) -> Result<Vec<Finding>>;
}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
