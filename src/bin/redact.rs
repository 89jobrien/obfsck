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
            // Silently skip invalid patterns — Rust's regex crate doesn't support
            // lookaheads/lookbehinds; bad patterns in user config should not produce
            // stderr noise that leaks through hook runners.
            RegexBuilder::new(&p.pattern)
                .case_insensitive(true)
                .build()
                .ok()
                .map(|re| (re, format!("[REDACTED-{}]", p.label)))
        })
        .collect();

    // Obfuscator persists token mappings across lines — same user/IP/host gets
    // the same stable token throughout the entire input.
    let mut obfuscator = Obfuscator::new(level).with_pii(pii_enabled);

    // Audit counts accumulated across all lines.
    let mut audit_counts: HashMap<String, usize> = HashMap::new();

    let reader = open_reader(args.input.as_deref());
    let writer = open_writer(args.output.as_deref());
    let mut writer = BufWriter::new(writer);

    for line in reader.lines() {
        let line = line.unwrap_or_else(|e| {
            eprintln!("Failed to read input: {e}");
            std::process::exit(1);
        });

        // Apply YAML secret patterns first (compiled once above, reused per line).
        let mut text = line;
        for (re, replacement) in &patterns {
            if args.audit {
                let count = re.find_iter(&text).count();
                if count > 0 {
                    *audit_counts.entry(replacement.clone()).or_insert(0) += count;
                }
            }
            text = re.replace_all(&text, replacement.as_str()).into_owned();
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
