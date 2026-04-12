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

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
