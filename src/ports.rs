//! Hexagonal architecture ports.
//!
//! Ports define the boundaries between the domain and adapters
//! (e.g. secret scanners).

use miette::Diagnostic;
use thiserror::Error;

/// Errors produced by [`SecretScanner`] adapters.
#[derive(Debug, Error, Diagnostic)]
pub enum PortsError {
    /// Failed to spawn a scanner subprocess (e.g. `gitleaks` not on `PATH`).
    #[error("failed to spawn scanner process: {0}")]
    #[diagnostic(
        code(obfsck::ports::spawn),
        help("check that the scanner binary is installed and on PATH")
    )]
    Spawn(#[source] std::io::Error),

    /// I/O failure while communicating with a scanner subprocess.
    #[error("scanner process I/O failed: {0}")]
    #[diagnostic(code(obfsck::ports::io))]
    Io(#[source] std::io::Error),

    /// Failed to parse scanner configuration (e.g. the bundled `secrets.yaml`).
    #[error("failed to parse scanner configuration: {0}")]
    #[diagnostic(code(obfsck::ports::config))]
    Config(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Any other scanner failure not covered by a more specific variant.
    #[error("{0}")]
    #[diagnostic(code(obfsck::ports::other))]
    Other(String),
}

impl From<String> for PortsError {
    fn from(message: String) -> Self {
        Self::Other(message)
    }
}

impl From<&str> for PortsError {
    fn from(message: &str) -> Self {
        Self::Other(message.to_string())
    }
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

pub type Result<T> = std::result::Result<T, PortsError>;
