//! Unified diff scanning combining the native obfsck patterns and gitleaks.
//!
//! Reads a unified diff from stdin (or captures `git diff --staged` itself),
//! runs both scanners, merges the findings, and reports them on stderr.
//! Exit codes: `0` clean, `1` findings reported, `2` scanner or git failure.
//!
//! Usage:
//!   git diff --staged | obfsck scan [OPTIONS]
//!   obfsck scan --staged [OPTIONS]
//! TODO(roadmap-scan-path): Add recursive file and repository scanning alongside diff scanning.

use crate::adapters::GitleaksAdapter;
use crate::ports::{Finding, SecretScanner};
use crate::{Allowlist, ObfuscationLevel, Obfuscator, PatternSet};
use clap::Parser;
use miette::Result;
use std::io::{self, Read};

/// Exit code used when the scanner itself could not run, as opposed to
/// finding something. Distinct from `1`, which means findings were reported.
const EXIT_ERROR: i32 = 2;

/// Arguments accepted by the diff scanning command.
///
/// The command name is pinned to `scan` so the usage line reads correctly
/// both under the canonical `obfsck scan` and under the deprecated
/// standalone `scan` binary, which shares this struct.
#[derive(Debug, Parser)]
#[command(
    name = "scan",
    version,
    about = "Scan a diff for secrets using obfsck and gitleaks. \
             Reads unified diff from stdin or uses --staged to capture git diff automatically."
)]
pub struct ScanArgs {
    /// Run `git diff --staged` internally instead of reading from stdin.
    #[arg(long)]
    pub staged: bool,

    /// Obfuscation level for obfsck patterns: minimal, standard, paranoid.
    #[arg(short, long, default_value = "minimal")]
    pub level: String,

    /// Skip the gitleaks scan even if gitleaks is on PATH.
    #[arg(long)]
    pub no_gitleaks: bool,

    /// Treat a missing gitleaks binary as an error (default: skip silently).
    #[arg(long)]
    pub require_gitleaks: bool,
}

/// Run diff scanning using already-parsed command arguments, returning the
/// process exit code.
pub fn run_scan_from_args(args: ScanArgs) -> Result<i32> {
    let diff = capture_diff(&args)?;

    if diff.trim().is_empty() {
        eprintln!("scan: no diff content to scan");
        return Ok(0);
    }

    let level = ObfuscationLevel::parse(&args.level).unwrap_or_else(|| {
        eprintln!("scan: unknown level '{}', using minimal", args.level);
        ObfuscationLevel::Minimal
    });

    let mut all_findings: Vec<Finding> = Vec::new();

    // Run native obfsck scanner.
    let obfsck = ObfsckScanner {
        level,
        allowlist: load_allowlist(),
        patterns: PatternSet::bundled(),
    };
    match obfsck.scan_diff(&diff) {
        Ok(findings) => all_findings.extend(findings),
        Err(e) => {
            eprintln!("scan: obfsck scanner error");
            eprintln!("{:?}", miette::Report::new(e));
            return Ok(EXIT_ERROR);
        }
    }

    // Run gitleaks scanner if requested and available.
    if !args.no_gitleaks {
        let gitleaks = GitleaksAdapter::new();
        if gitleaks.is_available() {
            match gitleaks.scan_diff(&diff) {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => {
                    eprintln!("scan: gitleaks scanner error");
                    eprintln!("{:?}", miette::Report::new(e));
                    return Ok(EXIT_ERROR);
                }
            }
        } else if args.require_gitleaks {
            eprintln!("scan: gitleaks binary not found on PATH (--require-gitleaks is set)");
            return Ok(EXIT_ERROR);
        } else {
            eprintln!("scan: gitleaks not found on PATH — skipping gitleaks check");
        }
    }

    // Report findings.
    if all_findings.is_empty() {
        eprintln!("scan: clean — no secrets found");
        return Ok(0);
    }

    eprintln!("scan: {} finding(s) detected:", all_findings.len());
    for f in &all_findings {
        match (f.location.as_deref(), f.line_number) {
            (Some(path), Some(line)) => {
                eprintln!("  [{}] {path}:{line}: {}", f.source, f.description)
            }
            (Some(path), None) => eprintln!("  [{}] {path}: {}", f.source, f.description),
            (None, Some(line)) => eprintln!("  [{}] line {line}: {}", f.source, f.description),
            (None, None) => eprintln!("  [{}] {}", f.source, f.description),
        }
    }
    Ok(1)
}

/// Obtain the diff text, either by capturing `git diff --staged` or by
/// reading stdin.
fn capture_diff(args: &ScanArgs) -> Result<String> {
    if !args.staged {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("scan: failed to read stdin: {e}");
            std::process::exit(EXIT_ERROR);
        });
        return Ok(buf);
    }

    let output = std::process::Command::new("git")
        .args(["diff", "--staged"])
        .output()
        .unwrap_or_else(|e| {
            eprintln!("scan: failed to run `git diff --staged`: {e}");
            std::process::exit(EXIT_ERROR);
        });
    if !output.status.success() {
        eprintln!("scan: `git diff --staged` exited non-zero");
        std::process::exit(EXIT_ERROR);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Load allowlist entries from multiple sources (merged in order):
///   1. `~/.config/obfsck/allowlist` (global, one entry per line)
///   2. `.obfsck.toml` in the repo root (per-repo, `[allowlist] patterns = [...]`)
///
/// Entries containing `*` or `?` are treated as glob patterns.
// qual:allow(iosp) reason: "I/O boundary — reads files and parses TOML; cannot cleanly separate"
fn load_allowlist() -> Allowlist {
    let mut entries = Vec::new();

    // 1. Global allowlist file
    let home = std::env::var("HOME").unwrap_or_default();
    let global_path = std::path::PathBuf::from(home).join(".config/obfsck/allowlist");
    if let Ok(contents) = std::fs::read_to_string(&global_path) {
        entries.extend(
            contents
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from),
        );
    }

    // 2. Repo-local .obfsck.toml (walk up from cwd to find it)
    if let Some(toml_entries) = load_repo_toml_allowlist() {
        entries.extend(toml_entries);
    }

    Allowlist::new(entries)
}

/// Walk up from cwd looking for `.obfsck.toml`, parse `[allowlist] patterns`.
fn load_repo_toml_allowlist() -> Option<Vec<String>> {
    let mut dir = std::env::current_dir().ok()?;
    loop {
        let candidate = dir.join(".obfsck.toml");
        if candidate.is_file() {
            let contents = std::fs::read_to_string(&candidate).ok()?;
            let table: toml::Table = contents.parse().ok()?;
            let allowlist = table.get("allowlist")?;
            let patterns = allowlist.get("patterns")?.as_array()?;
            return Some(
                patterns
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect(),
            );
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

/// Native obfsck diff scanner — implements SecretScanner by running the YAML
/// secret patterns over each added line in the diff.
struct ObfsckScanner {
    level: ObfuscationLevel,
    allowlist: Allowlist,
    patterns: PatternSet,
}

impl SecretScanner for ObfsckScanner {
    fn scan_diff(&self, diff: &str) -> crate::ports::Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let mut current_path: Option<String> = None;
        let mut next_source_line: Option<usize> = None;
        // Carries a standalone `obfsck:ignore` marker down to the next line,
        // since the scanner walks the diff rather than the file.
        let mut tracker = crate::suppression::SuppressionTracker::default();

        for (line_no, line) in diff.lines().enumerate() {
            if let Some(path) = line.strip_prefix("+++ ") {
                current_path = diff_path(path);
                tracker.reset();
                continue;
            }
            if line.starts_with("@@ ") {
                next_source_line = hunk_new_line_start(line);
                tracker.reset();
                continue;
            }

            // Only scan added lines in the diff (lines starting with '+' but not '+++').
            if !line.starts_with('+') {
                // Removed lines are neither scanned nor allowed to consume a
                // marker: `-old` and `+new` occupy the same file line, so a
                // marker above the pair governs the added line. A marker on a
                // removed line is therefore never honoured.
                if !line.starts_with('-') {
                    // Context lines are not scanned, but an existing marker
                    // above an added line still applies. Feed the line so the
                    // tracker can see it; the verdict is unused here.
                    let _ = tracker.is_suppressed(line);
                    if next_source_line.is_some() {
                        next_source_line = next_source_line.map(|line| line + 1);
                    }
                }
                continue;
            }
            let content = &line[1..]; // strip leading '+'
            let source_line = next_source_line.unwrap_or(line_no + 1);
            next_source_line = next_source_line.map(|line| line + 1);

            // Skip lines carrying an inline suppression marker or sitting
            // below a standalone one, then lines that match any allowlisted
            // value or glob pattern.
            if tracker.is_suppressed(content) || self.allowlist.matches_line(content) {
                continue;
            }

            let mut matched_pattern = false;
            for pattern in self.patterns.patterns() {
                if pattern.applies_at(self.level, true) && pattern.regex().is_match(content) {
                    matched_pattern = true;
                    let provenance = pattern
                        .group()
                        .map(|group| format!(" (group: {group})"))
                        .unwrap_or_default();
                    findings.push(finding_at(
                        format!("[REDACTED-{}] pattern matched{provenance}", pattern.label()),
                        current_path.as_deref(),
                        source_line,
                    ));
                }
            }

            // Run structural obfuscator — if any obfuscation happens the text changed.
            let mut obfuscator = Obfuscator::new(self.level)
                .with_pattern_set(self.patterns.clone())
                .with_allowlist(self.allowlist.exact_entries());
            let obfuscated = obfuscator.obfuscate(content);
            if obfuscated != content && !matched_pattern {
                findings.push(finding_at(
                    "structural secret/PII detected by obfsck",
                    current_path.as_deref(),
                    source_line,
                ));
            }
        }

        Ok(findings)
    }
}

fn diff_path(raw: &str) -> Option<String> {
    let path = raw.split('\t').next()?.trim();
    if path == "/dev/null" {
        return None;
    }
    Some(path.strip_prefix("b/").unwrap_or(path).to_string())
}

fn hunk_new_line_start(header: &str) -> Option<usize> {
    let range = header
        .split_whitespace()
        .find(|part| part.starts_with('+'))?;
    range
        .trim_start_matches('+')
        .split(',')
        .next()?
        .parse()
        .ok()
}

fn finding_at(description: impl Into<String>, path: Option<&str>, line_number: usize) -> Finding {
    match path {
        Some(path) => Finding::with_location("obfsck", description, path.to_string(), line_number),
        None => {
            let mut finding = Finding::new("obfsck", description);
            finding.line_number = Some(line_number);
            finding
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ObfuscationLevel;

    fn scanner(level: ObfuscationLevel) -> ObfsckScanner {
        ObfsckScanner {
            level,
            allowlist: Allowlist::new(vec![]),
            patterns: PatternSet::bundled(),
        }
    }

    /// The port only fails on I/O it cannot express, so a well-formed diff
    /// always scans. Crate-wide `unwrap_used` and `expect_used` are denied,
    /// hence the explicit match rather than `.expect(...)`.
    fn scan(diff: &str) -> Vec<Finding> {
        scan_at(ObfuscationLevel::Minimal, diff)
    }

    fn scan_at(level: ObfuscationLevel, diff: &str) -> Vec<Finding> {
        match scanner(level).scan_diff(diff) {
            Ok(findings) => findings,
            Err(e) => panic!("scan_diff failed on a well-formed diff: {e:?}"),
        }
    }

    fn diff_with(body: &str) -> String {
        format!("diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -0,0 +1,2 @@\n{body}")
    }

    const AWS_KEY: &str = "AKIAIOSFODNN7EXAMPLE";

    #[test]
    fn clean_diff_reports_nothing() {
        assert!(scan(&diff_with("+hello world\n")).is_empty());
    }

    #[test]
    fn added_line_with_secret_is_reported_with_location() {
        let findings = scan(&diff_with(&format!("+key={AWS_KEY}\n")));
        assert_eq!(findings.len(), 1, "one finding expected: {findings:?}");
        assert_eq!(findings[0].location.as_deref(), Some("f.txt"));
        assert_eq!(findings[0].line_number, Some(1));
    }

    #[test]
    fn removed_line_is_not_scanned() {
        let diff = format!(
            "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -1,1 +0,0 @@\n-key={AWS_KEY}\n"
        );
        assert!(scan(&diff).is_empty());
    }

    #[test]
    fn trailing_marker_suppresses_its_own_line() {
        let diff = diff_with(&format!("+key={AWS_KEY} // obfsck:ignore\n"));
        assert!(scan(&diff).is_empty());
    }

    #[test]
    fn standalone_marker_suppresses_only_the_line_below() {
        let diff = diff_with(&format!("+#[obfsck:ignore]\n+{AWS_KEY}\n+{AWS_KEY}\n"));
        let findings = scan(&diff);
        assert_eq!(
            findings.len(),
            1,
            "second key must still be reported: {findings:?}"
        );
        assert_eq!(findings[0].line_number, Some(3));
    }

    #[test]
    fn context_marker_above_an_added_line_suppresses_it() {
        let diff = format!(
            "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -1,2 +1,2 @@\n #[obfsck:ignore]\n-{AWS_KEY}\n+{AWS_KEY}\n tail\n"
        );
        assert!(scan(&diff).is_empty());
    }

    #[test]
    fn removed_marker_does_not_suppress_the_added_line() {
        // The marker is on its way out; it must not carry over to the line
        // replacing it.
        let diff = format!(
            "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -1,2 +1,1 @@\n-#[obfsck:ignore]\n+key={AWS_KEY}\n"
        );
        let findings = scan(&diff);
        assert_eq!(
            findings.len(),
            1,
            "a removed marker must not suppress: {findings:?}"
        );
    }

    #[test]
    fn marker_does_not_reach_across_a_hunk_boundary() {
        let diff = format!(
            "diff --git a/f.txt b/f.txt\n--- a/f.txt\n+++ b/f.txt\n@@ -1,1 +1,2 @@\n+#[obfsck:ignore]\n+safe=1\n@@ -10,1 +11,2 @@\n+key={AWS_KEY}\n"
        );
        assert_eq!(scan(&diff).len(), 1);
    }

    #[test]
    fn allowlisted_value_is_skipped() {
        let scanner = ObfsckScanner {
            level: ObfuscationLevel::Minimal,
            allowlist: Allowlist::new(vec![AWS_KEY.to_string()]),
            patterns: PatternSet::bundled(),
        };
        let diff = diff_with(&format!("+key={AWS_KEY}\n"));
        match scanner.scan_diff(&diff) {
            Ok(findings) => assert!(findings.is_empty()),
            Err(e) => panic!("scan_diff failed: {e:?}"),
        }
    }

    #[test]
    fn level_gates_pattern_visibility() {
        let diff = diff_with("+ip=192.168.1.10 user=alice\n");
        // PII is level-gated, so minimal stays silent where paranoid fires.
        assert!(scan_at(ObfuscationLevel::Minimal, &diff).is_empty());
        assert!(!scan_at(ObfuscationLevel::Paranoid, &diff).is_empty());
    }

    #[test]
    fn diff_path_strips_the_b_prefix_and_ignores_dev_null() {
        assert_eq!(diff_path("b/f.txt"), Some("f.txt".to_string()));
        assert_eq!(diff_path("b/f.txt\t2026-01-01"), Some("f.txt".to_string()));
        assert_eq!(diff_path("/dev/null"), None);
    }

    #[test]
    fn hunk_header_parses_the_new_start_line() {
        assert_eq!(hunk_new_line_start("@@ -1,2 +7,3 @@"), Some(7));
        assert_eq!(hunk_new_line_start("@@ -0,0 +1 @@"), Some(1));
        assert_eq!(hunk_new_line_start("no range here"), None);
    }
}
