use clap::Parser;
use obfsck::{ObfuscationLevel, obfuscate_text};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, Read};

// Path relative to this source file (src/bin/ → ../../config/)
static BUNDLED_CONFIG: &str = include_str!("../../config/secrets.yaml");

#[derive(Parser)]
#[command(about = "Redact secrets and PII from stdin")]
struct Args {
    /// Obfuscation level: minimal, standard, paranoid
    #[arg(short, long, default_value = "minimal")]
    level: String,

    /// Path to secrets YAML config.
    /// Lookup order: explicit path → ~/.config/obfsck/secrets.yaml → bundled config.
    #[arg(short, long)]
    config: Option<String>,
}

#[derive(Deserialize)]
struct SecretsConfig {
    groups: HashMap<String, Group>,
    #[serde(default)]
    custom: Vec<PatternDef>,
}

#[derive(Deserialize)]
struct Group {
    enabled: bool,
    patterns: Vec<PatternDef>,
}

#[derive(Deserialize)]
struct PatternDef {
    name: String,
    pattern: String,
    label: String,
    #[serde(default)]
    paranoid_only: bool,
}

fn main() {
    let args = Args::parse();

    let level = ObfuscationLevel::parse(&args.level).unwrap_or_else(|| {
        eprintln!("Unknown level '{}', using minimal", args.level);
        ObfuscationLevel::Minimal
    });

    let yaml = load_config(args.config.as_deref());
    let config: SecretsConfig = serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
        eprintln!("Failed to parse secrets config: {e}");
        std::process::exit(1);
    });

    let is_paranoid = level == ObfuscationLevel::Paranoid;
    let patterns: Vec<(Regex, String)> = config
        .groups
        .values()
        .filter(|g| g.enabled)
        .flat_map(|g| g.patterns.iter())
        .chain(config.custom.iter())
        .filter(|p| !p.paranoid_only || is_paranoid)
        .filter_map(|p| {
            RegexBuilder::new(&p.pattern)
                .case_insensitive(true)
                .build()
                .map_err(|e| eprintln!("Bad pattern '{}': {e}", p.name))
                .ok()
                .map(|re| (re, format!("[REDACTED-{}]", p.label)))
        })
        .collect();

    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .expect("failed to read stdin");

    // Apply YAML secret patterns first.
    // Then call obfuscate_text for structural obfuscation (IPs, emails, hostnames).
    // obfuscate_text also runs secrets.rs patterns — harmless double-application since
    // [REDACTED-X] tokens won't match secret regexes.
    let mut text = input;
    for (re, replacement) in &patterns {
        text = re.replace_all(&text, replacement.as_str()).into_owned();
    }
    let (out, _) = obfuscate_text(&text, level);
    print!("{}", out);
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
