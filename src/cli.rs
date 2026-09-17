use crate::yaml_config::SecretsConfig;
use crate::{Allowlist, ObfuscationLevel, Obfuscator, PatternSet};
use clap::{Parser, Subcommand};
use miette::{Context, IntoDiagnostic, Result};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::path::PathBuf;

static BUNDLED_CONFIG: &str = include_str!("../config/secrets.yaml");

/// Arguments accepted by the canonical `obfsck` executable.
#[derive(Debug, Parser)]
#[command(
    name = "obfsck",
    version,
    about = "Redact and analyze sensitive log data"
)]
pub struct ObfsckArgs {
    #[command(subcommand)]
    command: ObfsckCommand,
}

#[derive(Debug, Subcommand)]
enum ObfsckCommand {
    /// Redact secrets and PII from a file or stdin.
    Redact {
        #[command(flatten)]
        args: RedactArgs,
    },
    /// Fetch and analyze security alerts.
    Analyze {
        #[command(flatten)]
        args: crate::analyzer::CliArgs,
    },
}

/// Arguments accepted by the redaction command.
#[derive(Debug, Parser)]
#[command(
    about = "Redact secrets and PII from a file or stdin. Output goes to stdout unless -o is given."
)]
pub struct RedactArgs {
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

/// Dispatch a canonical `obfsck` command and return its process exit code.
pub fn run_from_args(args: ObfsckArgs) -> Result<i32> {
    match args.command {
        ObfsckCommand::Redact { args } => {
            run_redact_from_args(args)?;
            Ok(0)
        }
        ObfsckCommand::Analyze { args } => {
            crate::logging::init(crate::ANALYZER_DEFAULT_FILTER);
            crate::analyzer::run_from_args(args).map_err(miette::Report::new)
        }
    }
}

/// Run redaction using already-parsed command arguments.
pub fn run_redact_from_args(args: RedactArgs) -> Result<()> {
    let mut level = ObfuscationLevel::parse(&args.level).unwrap_or_else(|| {
        eprintln!("Unknown level '{}', using minimal", args.level);
        ObfuscationLevel::Minimal
    });

    let yaml = load_config(args.config.as_deref())?;
    let mut config: SecretsConfig = serde_yaml::from_str(&yaml)
        .into_diagnostic()
        .wrap_err("failed to parse secrets config")?;

    let pii_enabled = !matches!(
        args.pii.to_ascii_lowercase().as_str(),
        "off" | "false" | "no" | "0"
    );

    apply_profile(&mut config, &args.profile, &mut level);

    let pattern_set = PatternSet::from_config(&config);
    for diagnostic in pattern_set.diagnostics() {
        let definition = match diagnostic.group() {
            Some(group) => config.groups.get(group).and_then(|group| {
                group
                    .patterns
                    .iter()
                    .find(|pattern| pattern.name == diagnostic.name())
            }),
            None => config
                .custom
                .iter()
                .find(|pattern| pattern.name == diagnostic.name()),
        };
        if let Some(definition) = definition {
            const PATTERN_SNIPPET_LEN: usize = 60;
            let snippet: String = definition
                .pattern
                .chars()
                .take(PATTERN_SNIPPET_LEN)
                .collect();
            eprintln!(
                "warning: skipping invalid pattern '{}' ({}): {}",
                definition.label,
                snippet,
                diagnostic.message()
            );
        } else {
            eprintln!("warning: skipping {diagnostic}");
        }
    }

    // Build allowlist: CLI flags + allowlist-file + ~/.config/obfsck/allowlist
    let mut allowlist = args.allowlist;
    if let Some(path) = &args.allowlist_file {
        let content = std::fs::read_to_string(path)
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot read allowlist-file '{}'", path.display()))?;
        allowlist.extend(
            content
                .lines()
                .map(|l| l.trim().to_string())
                .filter(|l| !l.is_empty() && !l.starts_with('#')),
        );
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
    let audit_allowlist = Allowlist::new(allowlist.clone());

    // Obfuscator persists token mappings across lines — same user/IP/host gets
    // the same stable token throughout the entire input.
    let mut obfuscator = Obfuscator::new(level)
        .with_pii(pii_enabled)
        .with_pattern_set(pattern_set.clone())
        .with_allowlist(allowlist);

    // TODO(roadmap-audit): Provide structured, non-mutating findings for the full engine.
    // Audit counts accumulated across all lines.
    let mut audit_counts: HashMap<String, usize> = HashMap::new();

    let reader = open_reader(args.input.as_deref())?;
    let writer = open_writer(args.output.as_deref())?;
    let mut writer = BufWriter::new(writer);

    for (line_no, line) in reader.lines().enumerate() {
        let line = line
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to read input at line {}", line_no + 1))?;

        if args.audit {
            let mut audit_text = line.clone();
            for pattern in pattern_set.patterns() {
                if !pattern.applies_at(level, pii_enabled) {
                    continue;
                }
                let replacement = format!("[REDACTED-{}]", pattern.label());
                let count = pattern
                    .regex()
                    .find_iter(&audit_text)
                    .filter(|matched| !audit_allowlist.contains(matched.as_str()))
                    .count();
                if count > 0 {
                    *audit_counts.entry(replacement.clone()).or_insert(0) += count;
                }
                audit_text = pattern
                    .regex()
                    .replace_all(&audit_text, |captures: &regex::Captures<'_>| {
                        let matched = &captures[0];
                        if audit_allowlist.contains(matched) {
                            matched.to_string()
                        } else {
                            replacement.clone()
                        }
                    })
                    .into_owned();
            }
        }

        let out = obfuscator.obfuscate(&line);

        writeln!(writer, "{out}")
            .into_diagnostic()
            .wrap_err("failed to write output")?;
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

    Ok(())
}

fn open_reader(path: Option<&std::path::Path>) -> Result<Box<dyn BufRead>> {
    match path {
        Some(p) => {
            let f = std::fs::File::open(p)
                .into_diagnostic()
                .wrap_err_with(|| format!("cannot read '{}'", p.display()))?;
            Ok(Box::new(BufReader::new(f)))
        }
        None => Ok(Box::new(BufReader::new(io::stdin()))),
    }
}

fn open_writer(path: Option<&std::path::Path>) -> Result<Box<dyn Write>> {
    match path {
        Some(p) => {
            let f = std::fs::File::create(p)
                .into_diagnostic()
                .wrap_err_with(|| format!("cannot create '{}'", p.display()))?;
            Ok(Box::new(f))
        }
        None => Ok(Box::new(io::stdout())),
    }
}

fn load_config(explicit_path: Option<&str>) -> Result<String> {
    if let Some(path) = explicit_path {
        let expanded = shellexpand::tilde(path);
        return std::fs::read_to_string(expanded.as_ref())
            .into_diagnostic()
            .wrap_err_with(|| format!("cannot read config {path}"));
    }

    let user_config = shellexpand::tilde("~/.config/obfsck/secrets.yaml").into_owned();
    if let Ok(content) = std::fs::read_to_string(&user_config) {
        // Only use user config if it has meaningful content (not just an empty scaffold)
        let trimmed = content.trim();
        if !trimmed.is_empty() && trimmed != "groups: {}\ncustom: []" {
            return Ok(content);
        }
    }

    Ok(BUNDLED_CONFIG.to_string())
}
