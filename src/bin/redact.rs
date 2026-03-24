use clap::Parser;
use obfsck::yaml_config::SecretsConfig;
use obfsck::{ObfuscationLevel, obfuscate_text};
use regex::{Regex, RegexBuilder};
use std::io::{self, Read, Write};
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

    let input = read_input(args.input.as_deref());

    // Apply YAML secret patterns first.
    // Then call obfuscate_text for structural obfuscation (IPs, emails, hostnames).
    // obfuscate_text also runs secrets.rs patterns — harmless double-application since
    // [REDACTED-X] tokens won't match secret regexes.
    let mut text = input;
    for (re, replacement) in &patterns {
        text = re.replace_all(&text, replacement.as_str()).into_owned();
    }
    let (out, _) = obfuscate_text(&text, level);

    write_output(&out, args.output.as_deref());
}

fn read_input(path: Option<&std::path::Path>) -> String {
    match path {
        Some(p) => std::fs::read_to_string(p).unwrap_or_else(|e| {
            eprintln!("Cannot read '{}': {e}", p.display());
            std::process::exit(1);
        }),
        None => {
            let mut buf = String::new();
            io::stdin().read_to_string(&mut buf).unwrap_or_else(|e| {
                eprintln!("Failed to read stdin: {e}");
                std::process::exit(1);
            });
            buf
        }
    }
}

fn write_output(text: &str, path: Option<&std::path::Path>) {
    match path {
        Some(p) => {
            let mut f = std::fs::File::create(p).unwrap_or_else(|e| {
                eprintln!("Cannot create '{}': {e}", p.display());
                std::process::exit(1);
            });
            f.write_all(text.as_bytes()).unwrap_or_else(|e| {
                eprintln!("Failed to write '{}': {e}", p.display());
                std::process::exit(1);
            });
        }
        None => print!("{text}"),
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
