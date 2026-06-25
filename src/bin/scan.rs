//! `scan` binary — unified diff scanner combining obfsck and gitleaks.
//!
//! Reads a unified diff from stdin (or runs `git diff --staged` internally),
//! runs both the native obfsck pattern scanner and the GitleaksAdapter,
//! merges all findings, prints them to stderr, and exits non-zero if any
//! finding is reported by either scanner.
//!
//! Usage:
//!   git diff --staged | scan [OPTIONS]
//!   scan --staged [OPTIONS]

use clap::Parser;
use obfsck::adapters::GitleaksAdapter;
use obfsck::ports::{Finding, SecretScanner};
use obfsck::yaml_config::SecretsConfig;
use obfsck::{Allowlist, ObfuscationLevel, Obfuscator};
use regex::RegexBuilder;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process;

static BUNDLED_CONFIG: &str = include_str!("../../config/secrets.yaml");

#[derive(Parser)]
#[command(about = "Scan a diff for secrets using obfsck and gitleaks. \
             Reads unified diff from stdin or uses --staged to capture git diff automatically.")]
struct Args {
    /// Run `git diff --staged` internally instead of reading from stdin.
    #[arg(long)]
    staged: bool,

    /// Obfuscation level for obfsck patterns: minimal, standard, paranoid.
    #[arg(short, long, default_value = "minimal")]
    level: String,

    /// Skip the gitleaks scan even if gitleaks is on PATH.
    #[arg(long)]
    no_gitleaks: bool,

    /// Treat a missing gitleaks binary as an error (default: skip silently).
    #[arg(long)]
    require_gitleaks: bool,
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
    let global_path = PathBuf::from(home).join(".config/obfsck/allowlist");
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
}

impl SecretScanner for ObfsckScanner {
    fn scan_diff(&self, diff: &str) -> obfsck::ports::Result<Vec<Finding>> {
        let yaml = BUNDLED_CONFIG;
        let config: SecretsConfig = serde_yaml::from_str(yaml)
            .map_err(|e| format!("failed to parse bundled secrets config: {e}"))?;

        let level = self.level;
        let is_paranoid = level == ObfuscationLevel::Paranoid;

        let patterns: Vec<(regex::Regex, String)> = config
            .groups
            .values()
            .filter(|g| g.applies_at(level))
            .flat_map(|g| g.patterns.iter())
            .chain(config.custom.iter())
            .filter(|p| !p.paranoid_only || is_paranoid)
            .filter_map(
                |p| match RegexBuilder::new(&p.pattern).case_insensitive(true).build() {
                    Ok(re) => Some((re, p.label.clone())),
                    Err(e) => {
                        const PATTERN_SNIPPET_LEN: usize = 60;
                        let snippet: String = p.pattern.chars().take(PATTERN_SNIPPET_LEN).collect();
                        eprintln!(
                            "warning: skipping invalid pattern '{}' ({}): {e}",
                            p.label, snippet
                        );
                        None
                    }
                },
            )
            .collect();

        let mut findings = Vec::new();

        for (line_no, line) in diff.lines().enumerate() {
            // Only scan added lines in the diff (lines starting with '+' but not '+++').
            if !line.starts_with('+') || line.starts_with("+++") {
                continue;
            }
            let content = &line[1..]; // strip leading '+'

            // Skip lines that match any allowlisted value or glob pattern.
            if self.allowlist.matches_line(content) {
                continue;
            }

            const MAX_LOCATION_LEN: usize = 120;

            // Run YAML patterns.
            for (re, label) in &patterns {
                if re.is_match(content) {
                    findings.push(Finding::with_location(
                        "obfsck",
                        format!("[REDACTED-{label}] pattern matched"),
                        line.chars().take(MAX_LOCATION_LEN).collect(),
                        line_no + 1,
                    ));
                }
            }

            // Run structural obfuscator — if any obfuscation happens the text changed.
            let mut obfuscator =
                Obfuscator::new(level).with_allowlist(self.allowlist.exact_entries());
            let obfuscated = obfuscator.obfuscate(content);
            if obfuscated != content {
                findings.push(Finding::with_location(
                    "obfsck",
                    "structural secret/PII detected by obfsck",
                    line.chars().take(MAX_LOCATION_LEN).collect(),
                    line_no + 1,
                ));
            }
        }

        Ok(findings)
    }
}

fn main() {
    let args = Args::parse();

    // Obtain diff text.
    let diff = if args.staged {
        let output = std::process::Command::new("git")
            .args(["diff", "--staged"])
            .output()
            .unwrap_or_else(|e| {
                eprintln!("scan: failed to run `git diff --staged`: {e}");
                process::exit(2);
            });
        if !output.status.success() {
            eprintln!("scan: `git diff --staged` exited non-zero");
            process::exit(2);
        }
        String::from_utf8_lossy(&output.stdout).into_owned()
    } else {
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
            eprintln!("scan: failed to read stdin: {e}");
            process::exit(2);
        });
        buf
    };

    if diff.trim().is_empty() {
        eprintln!("scan: no diff content to scan");
        process::exit(0);
    }

    let level = ObfuscationLevel::parse(&args.level).unwrap_or_else(|| {
        eprintln!("scan: unknown level '{}', using minimal", args.level);
        ObfuscationLevel::Minimal
    });

    let mut all_findings: Vec<Finding> = Vec::new();

    // Run native obfsck scanner.
    let allowlist = load_allowlist();
    let obfsck = ObfsckScanner { level, allowlist };
    match obfsck.scan_diff(&diff) {
        Ok(findings) => all_findings.extend(findings),
        Err(e) => {
            eprintln!("scan: obfsck scanner error: {e}");
            process::exit(2);
        }
    }

    // Run gitleaks scanner if requested and available.
    if !args.no_gitleaks {
        let gitleaks = GitleaksAdapter::new();
        if gitleaks.is_available() {
            match gitleaks.scan_diff(&diff) {
                Ok(findings) => all_findings.extend(findings),
                Err(e) => {
                    eprintln!("scan: gitleaks scanner error: {e}");
                    process::exit(2);
                }
            }
        } else if args.require_gitleaks {
            eprintln!("scan: gitleaks binary not found on PATH (--require-gitleaks is set)");
            process::exit(2);
        } else {
            eprintln!("scan: gitleaks not found on PATH — skipping gitleaks check");
        }
    }

    // Report findings.
    if all_findings.is_empty() {
        eprintln!("scan: clean — no secrets found");
        process::exit(0);
    }

    eprintln!("scan: {} finding(s) detected:", all_findings.len());
    for f in &all_findings {
        let loc = f.location.as_deref().unwrap_or("<unknown location>");
        match f.line_number {
            Some(n) => eprintln!("  [{}] line {}: {} — {}", f.source, n, f.description, loc),
            None => eprintln!("  [{}] {} — {}", f.source, f.description, loc),
        }
    }
    process::exit(1);
}
