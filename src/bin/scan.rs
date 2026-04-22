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
use obfsck::{ObfuscationLevel, Obfuscator};
use regex::RegexBuilder;
use std::io::{self, Read};
use std::process;

static BUNDLED_CONFIG: &str = include_str!("../../config/secrets.yaml");

#[derive(Parser)]
#[command(
    about = "Scan a diff for secrets using obfsck and gitleaks. \
             Reads unified diff from stdin or uses --staged to capture git diff automatically."
)]
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

/// Native obfsck diff scanner — implements SecretScanner by running the YAML
/// secret patterns over each added line in the diff.
struct ObfsckScanner {
    level: ObfuscationLevel,
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
            .filter_map(|p| {
                match RegexBuilder::new(&p.pattern).case_insensitive(true).build() {
                    Ok(re) => Some((re, p.label.clone())),
                    Err(e) => {
                        let snippet: String = p.pattern.chars().take(60).collect();
                        eprintln!("warning: skipping invalid pattern '{}' ({}): {e}", p.label, snippet);
                        None
                    }
                }
            })
            .collect();

        let mut findings = Vec::new();

        for (line_no, line) in diff.lines().enumerate() {
            // Only scan added lines in the diff (lines starting with '+' but not '+++').
            if !line.starts_with('+') || line.starts_with("+++") {
                continue;
            }
            let content = &line[1..]; // strip leading '+'

            // Run YAML patterns.
            for (re, label) in &patterns {
                if re.is_match(content) {
                    findings.push(Finding {
                        description: format!("[REDACTED-{label}] pattern matched"),
                        location: Some(line.chars().take(120).collect()),
                        line_number: Some(line_no + 1),
                        source: "obfsck".to_string(),
                    });
                }
            }

            // Run structural obfuscator — if any obfuscation happens the text changed.
            let mut obfuscator = Obfuscator::new(level);
            let obfuscated = obfuscator.obfuscate(content);
            if obfuscated != content {
                findings.push(Finding {
                    description: "structural secret/PII detected by obfsck".to_string(),
                    location: Some(line.chars().take(120).collect()),
                    line_number: Some(line_no + 1),
                    source: "obfsck".to_string(),
                });
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
    let obfsck = ObfsckScanner { level };
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
