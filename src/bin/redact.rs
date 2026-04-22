use clap::Parser;
use obfsck::yaml_config::SecretsConfig;
use obfsck::{ObfuscationLevel, Obfuscator};
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

// Path relative to this source file (src/bin/ → ../../config/)
static BUNDLED_CONFIG: &str = include_str!("../../config/secrets.yaml");

#[derive(Parser)]
#[command(
    about = "Redact secrets and PII from a file or stdin. Output goes to stdout unless -o is given."
)]
#[command(override_usage = "redact [OPTIONS] [INPUT]\n       cat file | redact [OPTIONS]")]
struct Args {
    /// Input file to redact. Reads from stdin if omitted.
    input: Option<PathBuf>,

    /// Write redacted output to this file instead of stdout.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Obfuscation level: minimal, standard, paranoid
    #[arg(short, long, default_value = "minimal")]
    level: String,

    /// Path to secrets YAML config.
    /// Lookup order: explicit path → ~/.config/obfsck/secrets.yaml → bundled config.
    #[arg(short, long)]
    config: Option<String>,

    /// Print a per-pattern match report to stderr. Output is still written to stdout.
    #[arg(long)]
    audit: bool,

    /// Preset profile: default, pii, full, paranoid
    #[arg(long, default_value = "default")]
    profile: String,

    /// Enable or disable PII redaction (email, IP, names, SSN, etc.).
    /// Secrets (API keys, tokens) are always redacted regardless of this flag.
    /// Accepted values: on, off, true, false, yes, no, 1, 0.
    #[arg(long, default_value = "on")]
    pii: String,

    /// Values to never redact, even if they match a pattern. Repeatable.
    /// Also loaded from ~/.config/obfsck/allowlist (one entry per line).
    #[arg(long = "allowlist", value_name = "VALUE")]
    allowlist: Vec<String>,

    /// File containing allowlist entries, one per line.
    #[arg(long = "allowlist-file", value_name = "PATH")]
    allowlist_file: Option<PathBuf>,
}

fn apply_profile(config: &mut SecretsConfig, profile: &str, level: &mut ObfuscationLevel) {
    match profile {
        "pii" => {
            if let Some(g) = config.groups.get_mut("pii") {
                g.enabled = true;
            }
            // pii group has min_level: standard — bump if currently minimal
            if *level == ObfuscationLevel::Minimal {
                *level = ObfuscationLevel::Standard;
            }
        }
        "full" => {
            for g in config.groups.values_mut() {
                g.enabled = true;
            }
        }
        "paranoid" => {
            for g in config.groups.values_mut() {
                g.enabled = true;
            }
            *level = ObfuscationLevel::Paranoid;
        }
        _ => {} // "default": use config as-is
    }
}

fn main() {
    let args = Args::parse();

    let mut level = ObfuscationLevel::parse(&args.level).unwrap_or_else(|| {
        eprintln!("Unknown level '{}', using minimal", args.level);
        ObfuscationLevel::Minimal
    });

    let yaml = load_config(args.config.as_deref());
    let mut config: SecretsConfig = serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
        eprintln!("Failed to parse secrets config: {e}");
        std::process::exit(1);
    });

    let pii_enabled = !matches!(
        args.pii.to_ascii_lowercase().as_str(),
        "off" | "false" | "no" | "0"
    );

    apply_profile(&mut config, &args.profile, &mut level);

    // When PII is disabled, skip YAML groups whose min_level is standard (PII groups).
    if !pii_enabled {
        for group in config.groups.values_mut() {
            if matches!(
                group.min_level,
                Some(obfsck::yaml_config::MinLevel::Standard)
            ) {
                group.enabled = false;
            }
        }
    }

    let is_paranoid = level == ObfuscationLevel::Paranoid;
    let patterns: Vec<(Regex, String)> = config
        .groups
        .values()
        .filter(|g| g.applies_at(level))
        .flat_map(|g| g.patterns.iter())
        .chain(config.custom.iter())
        .filter(|p| !p.paranoid_only || is_paranoid)
        .filter_map(|p| {
            // Log invalid patterns (e.g. unsupported lookaheads) — they are skipped but
            // the user should know which pattern caused the issue.
            match RegexBuilder::new(&p.pattern).case_insensitive(true).build() {
                Ok(re) => Some((re, format!("[REDACTED-{}]", p.label))),
                Err(e) => {
                    let snippet: String = p.pattern.chars().take(60).collect();
                    eprintln!("warning: skipping invalid pattern '{}' ({}): {e}", p.label, snippet);
                    None
                }
            }
        })
        .collect();

    // Build allowlist: CLI flags + allowlist-file + ~/.config/obfsck/allowlist
    let mut allowlist = args.allowlist;
    if let Some(path) = &args.allowlist_file {
        match std::fs::read_to_string(path) {
            Ok(content) => allowlist.extend(
                content
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#')),
            ),
            Err(e) => {
                eprintln!("Cannot read allowlist-file '{}': {e}", path.display());
                std::process::exit(1);
            }
        }
    }
    let user_allowlist = shellexpand::tilde("~/.config/obfsck/allowlist").into_owned();
    if let Ok(content) = std::fs::read_to_string(&user_allowlist) {
        allowlist.extend(
            content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')),
        );
    }
    let allowlist_set: std::collections::HashSet<String> = allowlist.into_iter().collect();

    // Obfuscator persists token mappings across lines — same user/IP/host gets
    // the same stable token throughout the entire input.
    let mut obfuscator = Obfuscator::new(level)
        .with_pii(pii_enabled)
        .with_allowlist(allowlist_set.iter().cloned().collect());

    // Audit counts accumulated across all lines.
    let mut audit_counts: HashMap<String, usize> = HashMap::new();

    let reader = open_reader(args.input.as_deref());
    let writer = open_writer(args.output.as_deref());
    let mut writer = BufWriter::new(writer);

    for (line_no, line) in reader.lines().enumerate() {
        let line = line.unwrap_or_else(|e| {
            eprintln!("Failed to read input at line {}: {e}", line_no + 1);
            std::process::exit(1);
        });

        // Apply YAML secret patterns first (compiled once above, reused per line).
        let mut text = line;
        for (re, replacement) in &patterns {
            if args.audit {
                let count = re
                    .find_iter(&text)
                    .filter(|m| !allowlist_set.contains(m.as_str()))
                    .count();
                if count > 0 {
                    *audit_counts.entry(replacement.clone()).or_insert(0) += count;
                }
            }
            text = re
                .replace_all(&text, |caps: &regex::Captures<'_>| {
                    let matched = &caps[0];
                    if allowlist_set.contains(matched) {
                        matched.to_string()
                    } else {
                        replacement.clone()
                    }
                })
                .into_owned();
        }

        // Structural obfuscation (IPs, emails, hostnames, etc.).
        let out = obfuscator.obfuscate(&text);

        writeln!(writer, "{out}").unwrap_or_else(|e| {
            eprintln!("Failed to write output: {e}");
            std::process::exit(1);
        });
    }

    if args.audit {
        let total: usize = audit_counts.values().sum();
        eprintln!(
            "Audit report: {} pattern type(s), {} total match(es)",
            audit_counts.len(),
            total
        );
        let mut sorted: Vec<_> = audit_counts.iter().collect();
        sorted.sort_by_key(|(label, _)| label.as_str());
        for (label, count) in sorted {
            eprintln!("  {:<35} {}", label, count);
        }
    }
}

fn open_reader(path: Option<&std::path::Path>) -> Box<dyn BufRead> {
    match path {
        Some(p) => {
            let f = std::fs::File::open(p).unwrap_or_else(|e| {
                eprintln!("Cannot read '{}': {e}", p.display());
                std::process::exit(1);
            });
            Box::new(BufReader::new(f))
        }
        None => Box::new(BufReader::new(io::stdin())),
    }
}

fn open_writer(path: Option<&std::path::Path>) -> Box<dyn Write> {
    match path {
        Some(p) => {
            let f = std::fs::File::create(p).unwrap_or_else(|e| {
                eprintln!("Cannot create '{}': {e}", p.display());
                std::process::exit(1);
            });
            Box::new(f)
        }
        None => Box::new(io::stdout()),
    }
}

fn load_config(explicit_path: Option<&str>) -> String {
    if let Some(path) = explicit_path {
        let expanded = shellexpand::tilde(path);
        return std::fs::read_to_string(expanded.as_ref()).unwrap_or_else(|e| {
            eprintln!("Cannot read config {path}: {e}");
            std::process::exit(1);
        });
    }

    let user_config = shellexpand::tilde("~/.config/obfsck/secrets.yaml").into_owned();
    if let Ok(content) = std::fs::read_to_string(&user_config) {
        // Only use user config if it has meaningful content (not just an empty scaffold)
        let trimmed = content.trim();
        if !trimmed.is_empty() && trimmed != "groups: {}\ncustom: []" {
            return content;
        }
    }

    BUNDLED_CONFIG.to_string()
}
