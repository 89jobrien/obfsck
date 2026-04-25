//! Gitleaks adapter — implements `SecretScanner` by shelling out to the `gitleaks` CLI.
//!
//! The adapter passes diff content via stdin using `gitleaks detect --pipe`
//! and parses the exit code. Gitleaks prints findings to stdout; we capture
//! them and surface each line as a `Finding`.

use crate::ports::{Finding, Result, SecretScanner};
use std::io::Write;
use std::process::{Command, Stdio};

/// Strip ANSI escape sequences from a string for classification.
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip CSI sequences: ESC [ ... final_byte
            if chars.peek() == Some(&'[') {
                chars.next(); // consume '['
                while let Some(&next) = chars.peek() {
                    chars.next();
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Adapter that delegates secret scanning to the installed `gitleaks` binary.
///
/// # Availability
///
/// If `gitleaks` is not on `PATH`, `scan_diff` returns an error. Callers can
/// treat this as non-fatal (skip gitleaks) or fatal depending on policy.
pub struct GitleaksAdapter {
    /// Path to the gitleaks binary. Defaults to `"gitleaks"` (resolved via PATH).
    pub binary: String,
}

impl GitleaksAdapter {
    /// Construct an adapter using the default binary name `"gitleaks"`.
    pub fn new() -> Self {
        Self {
            binary: "gitleaks".to_string(),
        }
    }

    /// Construct an adapter with a specific binary path.
    pub fn with_binary(binary: impl Into<String>) -> Self {
        Self {
            binary: binary.into(),
        }
    }

    /// Returns `true` if the gitleaks binary is resolvable on the current PATH.
    pub fn is_available(&self) -> bool {
        Command::new(&self.binary)
            .arg("version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok()
    }
}

impl Default for GitleaksAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretScanner for GitleaksAdapter {
    fn scan_diff(&self, diff: &str) -> Result<Vec<Finding>> {
        // `gitleaks detect --pipe` reads a diff from stdin.
        // Exit code 1 means findings; exit code 0 means clean.
        let mut child = Command::new(&self.binary)
            .args(["detect", "--pipe", "--no-git", "--redact"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("failed to spawn gitleaks binary '{}': {e}", self.binary))?;

        // Write diff to stdin, then close it.
        if let Some(stdin) = child.stdin.take() {
            let mut stdin = stdin;
            stdin
                .write_all(diff.as_bytes())
                .map_err(|e| format!("failed to write diff to gitleaks stdin: {e}"))?;
            // stdin dropped here — EOF sent
        }

        let output = child
            .wait_with_output()
            .map_err(|e| format!("failed to wait for gitleaks process: {e}"))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Parse output lines, filtering out gitleaks' ASCII banner, ANSI
        // escape sequences, and status/info messages that are not findings.
        let mut findings: Vec<Finding> = Vec::new();
        for line in stdout.lines().chain(stderr.lines()) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let stripped = strip_ansi(trimmed);

            // Skip decorative banner lines (box-drawing, dots, etc.).
            if stripped.chars().all(|c| {
                matches!(
                    c,
                    '○' | '│'
                        | '╲'
                        | '░'
                        | '─'
                        | '┐'
                        | '┘'
                        | '┌'
                        | '└'
                        | '╱'
                        | '█'
                        | ' '
                )
            }) {
                continue;
            }
            // Skip status/info lines from gitleaks.
            if stripped.contains("gitleaks")
                && !stripped.contains("Finding")
                && !stripped.contains("Secret")
                && !stripped.contains("RuleID")
            {
                continue;
            }
            if stripped.starts_with("INF") || stripped.starts_with("WRN") {
                continue;
            }
            // Skip scanned/timing/summary lines.
            if stripped.contains("scanned ~")
                || stripped.contains("no leaks found")
                || stripped.contains("leaks found:")
            {
                continue;
            }
            findings.push(Finding {
                description: trimmed.to_string(),
                location: None,
                line_number: None,
                source: "gitleaks".to_string(),
            });
        }

        // Exit code 1 from gitleaks means secrets found (even if findings is empty from parsing).
        // If gitleaks exits 1 but we got no parseable findings, synthesize a generic finding.
        if !output.status.success() && findings.is_empty() {
            findings.push(Finding {
                description: "gitleaks detected secrets in diff (no parseable output)".to_string(),
                location: None,
                line_number: None,
                source: "gitleaks".to_string(),
            });
        }

        Ok(findings)
    }
}
