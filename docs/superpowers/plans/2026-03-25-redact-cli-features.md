# redact CLI Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add four features to the `redact` binary: `--audit` mode, `--profile` presets, `redact scan <dir>`, and `redact verify`.

**Architecture:** Restructure `src/bin/redact.rs` to dispatch subcommands via manual `args().peek()` before clap parsing — each subcommand gets its own clap `Args` struct. `--audit` and `--profile` are added as flags to the existing redact command. `scan` walks a directory tree reporting matches without modifying files; `verify` compares pattern names+content between `secrets.rs` and `config/secrets.yaml`. `walkdir` is added under the `analyzer` feature. `build_patterns` uses `g.applies_at(level)` (not `g.enabled`) to preserve `min_level` enforcement.

**Tech Stack:** Rust 2024, `clap` (derive, already present), `walkdir` (new dep), `serde_yaml` (already present), `regex` (already present), `indexmap` (already present).

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `Cargo.toml` | Modify | Add `walkdir` under `analyzer` feature |
| `src/lib.rs` | Modify | Make `SecretPatternDef` + all fields `pub`; re-export `SECRET_PATTERN_DEFS` |
| `src/secrets.rs` | Modify | Change `pub(super)` → `pub(crate)` on `SECRET_PATTERN_DEFS` |
| `src/bin/redact.rs` | Rewrite | Subcommand dispatch, `--audit`, `--profile`, `build_patterns`, `cmd_scan`, `cmd_verify` |
| `tests/redact_features.rs` | Create | Integration tests for all four features |

---

## Task 1: Add `walkdir`, expose `SECRET_PATTERN_DEFS` publicly

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/secrets.rs:3`
- Modify: `src/lib.rs`

- [ ] **Step 1: Add `walkdir` to Cargo.toml under `analyzer` feature**

In `[dependencies]`:
```toml
walkdir = { version = "2", optional = true }
```

In `[features] → analyzer = [...]`, add `"walkdir"`.

- [ ] **Step 2: Change visibility of `SECRET_PATTERN_DEFS` in `src/secrets.rs`**

Change line 3:
```rust
// before
pub(super) const SECRET_PATTERN_DEFS: &[SecretPatternDef] = &[

// after
pub(crate) const SECRET_PATTERN_DEFS: &[SecretPatternDef] = &[
```

- [ ] **Step 3: Make `SecretPatternDef` and all its fields `pub` in `src/lib.rs`**

Find the `struct SecretPatternDef` definition (currently private — no `pub`). Change it to:

```rust
pub struct SecretPatternDef {
    pub name: &'static str,
    pub pattern: &'static str,
    pub label: &'static str,
    pub paranoid_only: bool,
}
```

This is required so the `redact` binary can access field values via `SECRET_PATTERN_DEFS`.

- [ ] **Step 4: Verify it builds**

```bash
cargo build --bin redact 2>&1
```

Expected: clean build, no visibility errors.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/secrets.rs src/lib.rs
git commit -m "feat(redact): expose SecretPatternDef and SECRET_PATTERN_DEFS, add walkdir dep"
```

---

## Task 2: `--audit` flag

Shows a per-pattern match report on stderr after redacting. Redacted output still goes to stdout — both are independent.

**Files:**
- Modify: `src/bin/redact.rs`
- Create: `tests/redact_features.rs`

- [ ] **Step 1: Create test file with feature gate**

Create `tests/redact_features.rs`:

```rust
#![cfg(feature = "analyzer")]

use std::process::Command;

fn redact_bin() -> Command {
    let bin = env!("CARGO_BIN_EXE_redact");
    Command::new(bin)
}

#[test]
fn test_audit_reports_to_stderr() {
    let out = redact_bin()
        .arg("--audit")
        .arg("tests/fixtures/demo-secrets.txt")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("Audit report"), "expected audit header, got: {stderr}");
    assert!(stderr.contains("ANTHROPIC-KEY"), "expected pattern label, got: {stderr}");

    // Redacted content still goes to stdout
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[REDACTED-"), "expected redacted output on stdout, got: {stdout}");
    assert!(!stdout.contains("sk-ant-"), "key should be redacted on stdout, got: {stdout}");
}

#[test]
fn test_audit_shows_match_counts() {
    let out = redact_bin()
        .arg("--audit")
        .arg("tests/fixtures/demo-secrets.txt")
        .output()
        .unwrap();

    let stderr = String::from_utf8_lossy(&out.stderr);
    // Audit header should include totals
    assert!(stderr.contains("pattern"), "expected summary line, got: {stderr}");
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test --test redact_features test_audit 2>&1 | tail -15
```

Expected: compile error (no `--audit` flag yet).

- [ ] **Step 3: Add `--audit` flag and implement**

In the `RedactArgs` struct, add:

```rust
/// Print a per-pattern match report to stderr. Output is still written to stdout.
#[arg(long)]
audit: bool,
```

After building `patterns`, collect counts before replacing. Replace the existing apply-loop in `cmd_redact` with:

```rust
let mut audit_counts: Vec<(String, usize)> = Vec::new();
let mut text = input;
for (re, replacement) in &patterns {
    let count = re.find_iter(&text).count();
    if count > 0 {
        audit_counts.push((replacement.clone(), count));
    }
    text = re.replace_all(&text, replacement.as_str()).into_owned();
}

if args.audit {
    let total: usize = audit_counts.iter().map(|(_, c)| c).sum();
    eprintln!("Audit report: {} pattern type(s), {} total match(es)", audit_counts.len(), total);
    for (label, count) in &audit_counts {
        eprintln!("  {:<35} {}", label, count);
    }
}
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cargo test --test redact_features test_audit 2>&1
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/bin/redact.rs tests/redact_features.rs
git commit -m "feat(redact): add --audit flag with per-pattern match report on stderr"
```

---

## Task 3: `--profile` presets

Profiles override the `enabled` state of groups in the loaded config. The `pii` group has `min_level: standard`, so enabling it via `--profile pii` requires `--level standard` or higher to actually fire.

| Profile | Effect |
|---------|--------|
| `default` | No change — use config as-is |
| `pii` | Enable `pii` group; also sets level to `standard` if currently `minimal` |
| `full` | Enable all groups |
| `paranoid` | Enable all groups + force level to `paranoid` |

**Files:**
- Modify: `src/bin/redact.rs`
- Modify: `tests/redact_features.rs`

- [ ] **Step 1: Write the failing tests**

Add to `tests/redact_features.rs`:

```rust
#[test]
fn test_profile_pii_enables_ssn_redaction() {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "ssn=123-45-6789").unwrap();

    // pii profile must use level >= standard (pii group has min_level: standard)
    let out = redact_bin()
        .args(["--profile", "pii", "--level", "standard"])
        .arg(f.path())
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[REDACTED-SSN]"), "SSN should be redacted with pii profile at standard level, got: {stdout}");
    assert!(!stdout.contains("123-45-6789"), "raw SSN value should not appear, got: {stdout}");
}

#[test]
fn test_default_profile_does_not_redact_ssn() {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().unwrap();
    writeln!(f, "ssn=123-45-6789").unwrap();

    let out = redact_bin().arg(f.path()).output().unwrap();

    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("123-45-6789"), "SSN should pass through by default, got: {stdout}");
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test --test redact_features test_profile 2>&1 | tail -10
```

Expected: compile error (no `--profile` flag yet).

- [ ] **Step 3: Add `--profile` flag and `apply_profile` helper**

In `RedactArgs`:

```rust
/// Preset profile: default, pii, full, paranoid
#[arg(long, default_value = "default")]
profile: String,
```

Add module-level helper (not inside any function — it will be reused by `cmd_scan` in Task 4):

```rust
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
```

Call it in `cmd_redact` after loading config:

```rust
let mut config: SecretsConfig = serde_yaml::from_str(&yaml)...;
apply_profile(&mut config, &args.profile, &mut level);
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
cargo test --test redact_features test_profile 2>&1
```

Expected: both tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/bin/redact.rs tests/redact_features.rs
git commit -m "feat(redact): add --profile flag (default, pii, full, paranoid)"
```

---

## Task 4: `redact scan <path>`

Walks a path (file or directory), reports which files contain secrets, exits non-zero if any found. Never modifies files.

**Files:**
- Modify: `src/bin/redact.rs`
- Modify: `tests/redact_features.rs`

**Output format:**
```
MATCH  path/to/file.log  [REDACTED-ANTHROPIC-KEY](2) [REDACTED-GITHUB-TOKEN](1)
MATCH  path/to/other.env  [REDACTED-PASSWORD](1)
---
Secrets found. Review the files above.
```

- [ ] **Step 1: Write failing tests**

Add to `tests/redact_features.rs`:

```rust
#[test]
fn test_scan_finds_secrets_in_dir() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();

    let mut f1 = std::fs::File::create(dir.path().join("secrets.log")).unwrap();
    writeln!(f1, "key=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-END").unwrap();

    let mut f2 = std::fs::File::create(dir.path().join("clean.log")).unwrap();
    writeln!(f2, "hello world, no secrets here").unwrap();

    let out = redact_bin()
        .arg("scan")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_ne!(out.status.code(), Some(0), "scan should exit non-zero when secrets found");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("secrets.log"), "should report file with secrets: {stdout}");
    assert!(stdout.contains("ANTHROPIC-KEY"), "should name the pattern: {stdout}");
    assert!(!stdout.contains("clean.log"), "should not report clean file: {stdout}");
}

#[test]
fn test_scan_exits_zero_when_clean() {
    use std::io::Write;
    let dir = tempfile::tempdir().unwrap();
    let mut f = std::fs::File::create(dir.path().join("clean.log")).unwrap();
    writeln!(f, "no secrets here at all").unwrap();

    let out = redact_bin()
        .arg("scan")
        .arg(dir.path())
        .output()
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "scan should exit zero when no secrets found");
}
```

- [ ] **Step 2: Run tests to confirm they fail**

```bash
cargo test --test redact_features test_scan 2>&1 | tail -10
```

- [ ] **Step 3: Restructure `main()` for subcommand dispatch**

Replace `main()` with manual dispatch. Add a stub for `cmd_verify` — it will be fully implemented in Task 5:

```rust
fn main() {
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(|s| s.as_str()) {
        Some("scan") => cmd_scan(&argv[2..]),
        Some("verify") => cmd_verify(),
        _ => cmd_redact(),
    }
}

fn cmd_verify() {
    todo!("implemented in a follow-up commit")
}
```

Move the existing `main()` body into `fn cmd_redact()`. Rename `Args` to `RedactArgs`.

- [ ] **Step 4: Extract `build_patterns` to module level**

Move `apply_profile` (already at module level from Task 3) and extract `build_patterns`:

```rust
fn build_patterns(config: &SecretsConfig, level: ObfuscationLevel) -> Vec<(Regex, String)> {
    let is_paranoid = level == ObfuscationLevel::Paranoid;
    config
        .groups
        .values()
        .filter(|g| g.applies_at(level))   // ← must use applies_at, not g.enabled
        .flat_map(|g| g.patterns.iter())
        .chain(config.custom.iter())
        .filter(|p| !p.paranoid_only || is_paranoid)
        .filter_map(|p| {
            RegexBuilder::new(&p.pattern)
                .case_insensitive(true)
                .build()
                .ok()
                .map(|re| (re, format!("[REDACTED-{}]", p.label)))
        })
        .collect()
}
```

Replace the inline pattern-building in `cmd_redact` with a call to `build_patterns`.

- [ ] **Step 5: Implement `cmd_scan`**

```rust
#[derive(Parser)]
#[command(about = "Scan a file or directory for secrets. Exits non-zero if any found.")]
struct ScanArgs {
    /// File or directory to scan.
    path: PathBuf,

    #[arg(short, long, default_value = "minimal")]
    level: String,

    #[arg(short, long)]
    config: Option<String>,

    #[arg(long, default_value = "default")]
    profile: String,
}

fn cmd_scan(argv: &[String]) {
    let args = ScanArgs::parse_from(
        std::iter::once("redact scan".to_string()).chain(argv.iter().cloned())
    );

    let mut level = ObfuscationLevel::parse(&args.level).unwrap_or(ObfuscationLevel::Minimal);
    let yaml = load_config(args.config.as_deref());
    let mut config: SecretsConfig = serde_yaml::from_str(&yaml).unwrap_or_else(|e| {
        eprintln!("Failed to parse secrets config: {e}");
        std::process::exit(1);
    });
    apply_profile(&mut config, &args.profile, &mut level);
    let patterns = build_patterns(&config, level);

    use walkdir::WalkDir;
    let paths: Vec<PathBuf> = if args.path.is_file() {
        vec![args.path.clone()]
    } else {
        WalkDir::new(&args.path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .map(|e| e.path().to_path_buf())
            .collect()
    };

    let mut found_any = false;
    for path in paths {
        let Ok(content) = std::fs::read_to_string(&path) else { continue };
        let mut hits: Vec<(String, usize)> = Vec::new();
        for (re, label) in &patterns {
            let count = re.find_iter(&content).count();
            if count > 0 {
                hits.push((label.clone(), count));
            }
        }
        if !hits.is_empty() {
            found_any = true;
            let summary: Vec<String> = hits.iter()
                .map(|(l, c)| format!("{l}({c})"))
                .collect();
            println!("MATCH  {}  {}", path.display(), summary.join(" "));
        }
    }

    if found_any {
        eprintln!("---\nSecrets found. Review the files above.");
        std::process::exit(1);
    } else {
        println!("No secrets found.");
    }
}
```

- [ ] **Step 6: Run tests to confirm they pass**

```bash
cargo test --test redact_features test_scan 2>&1
```

Expected: both tests pass.

- [ ] **Step 7: Smoke test**

```bash
cargo build --release --bin redact -q && cp target/release/redact ~/.local/bin/redact

# Should find secrets (use the demo fixture which has real-shaped patterns)
echo "key=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-END" > /tmp/smoke-secret.txt
redact scan /tmp/smoke-secret.txt; echo "exit: $?"
# Expected: MATCH line, exit 1

# Clean file should exit 0
echo "hello world" > /tmp/smoke-clean.txt
redact scan /tmp/smoke-clean.txt; echo "exit: $?"
# Expected: "No secrets found.", exit 0
```

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml Cargo.lock src/bin/redact.rs tests/redact_features.rs
git commit -m "feat(redact): add scan subcommand for secret detection without modification"
```

---

## Task 5: `redact verify`

Compares pattern names and content between `src/secrets.rs` (exported as `obfsck::SECRET_PATTERN_DEFS`) and `config/secrets.yaml` (embedded as `BUNDLED_CONFIG`). Reports: patterns only in one source, pattern string mismatches, `paranoid_only` mismatches.

**Files:**
- Modify: `src/bin/redact.rs` (replace `todo!()` stub)
- Modify: `src/lib.rs` (add `pub use`)
- Modify: `tests/redact_features.rs`

- [ ] **Step 1: Re-export `SECRET_PATTERN_DEFS` from `src/lib.rs`**

Add to `src/lib.rs`:

```rust
pub use secrets::SECRET_PATTERN_DEFS;
```

This makes it accessible as `obfsck::SECRET_PATTERN_DEFS` from the binary.

- [ ] **Step 2: Write the failing test**

Add to `tests/redact_features.rs`:

```rust
#[test]
fn test_verify_exits_zero_when_in_sync() {
    let out = redact_bin().arg("verify").output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if out.status.code() != Some(0) {
        eprintln!("verify found drift:\nstdout: {stdout}\nstderr: {stderr}");
    }
    assert_eq!(out.status.code(), Some(0), "secrets.rs and config/secrets.yaml should be in sync");
}
```

- [ ] **Step 3: Run to see current drift**

```bash
cargo build --release --bin redact -q
./target/release/redact verify || echo "(expected: todo panic)"
```

This will either panic (stub) or show drift once implemented. Run it after Step 4.

- [ ] **Step 4: Implement `cmd_verify`**

Replace the `todo!()` stub:

```rust
fn cmd_verify() {
    use std::collections::HashMap;

    // Patterns from secrets.rs — compiled into binary
    let rs_map: HashMap<&str, (&str, bool)> = obfsck::SECRET_PATTERN_DEFS
        .iter()
        .map(|p| (p.name, (p.pattern, p.paranoid_only)))
        .collect();

    // Patterns from config/secrets.yaml — embedded via include_str!
    let config: SecretsConfig = serde_yaml::from_str(BUNDLED_CONFIG).unwrap_or_else(|e| {
        eprintln!("Failed to parse bundled config: {e}");
        std::process::exit(1);
    });
    let yaml_map: HashMap<&str, (&str, bool)> = config
        .groups
        .values()
        .flat_map(|g| g.patterns.iter())
        .map(|p| (p.name.as_str(), (p.pattern.as_str(), p.paranoid_only)))
        .collect();

    let mut issues: Vec<String> = Vec::new();

    for name in rs_map.keys() {
        if !yaml_map.contains_key(name) {
            issues.push(format!("  only in secrets.rs:    {name}"));
        }
    }
    for name in yaml_map.keys() {
        if !rs_map.contains_key(name) {
            issues.push(format!("  only in secrets.yaml:  {name}"));
        }
    }
    for (name, (rs_pat, rs_p)) in &rs_map {
        if let Some((yaml_pat, yaml_p)) = yaml_map.get(name) {
            if rs_pat != yaml_pat {
                issues.push(format!("  pattern mismatch:      {name}"));
                issues.push(format!("    secrets.rs:   {rs_pat}"));
                issues.push(format!("    secrets.yaml: {yaml_pat}"));
            }
            if rs_p != yaml_p {
                issues.push(format!(
                    "  paranoid_only mismatch: {name} (rs={rs_p}, yaml={yaml_p})"
                ));
            }
        }
    }

    if issues.is_empty() {
        println!("OK — {} patterns in sync between secrets.rs and config/secrets.yaml.", rs_map.len());
    } else {
        println!("DRIFT DETECTED — {} issue(s):", issues.len());
        for issue in &issues {
            println!("{issue}");
        }
        std::process::exit(1);
    }
}
```

- [ ] **Step 5: Run verify and fix any drift**

```bash
cargo build --release --bin redact -q && ./target/release/redact verify
```

For any issues reported, update the YAML to match `secrets.rs` (treat `secrets.rs` as source of truth for pattern strings). Re-run until `verify` exits 0.

- [ ] **Step 6: Run all tests**

```bash
cargo test --test redact_features 2>&1
```

Expected: all tests pass, including `test_verify_exits_zero_when_in_sync`.

- [ ] **Step 7: Add `verify-patterns` to mise tasks**

In `mise.toml`, add:
```toml
[tasks.verify-patterns]
run = "cargo run --bin redact -- verify"
description = "Verify secrets.rs and config/secrets.yaml are in sync"
```

- [ ] **Step 8: Commit**

```bash
git add src/bin/redact.rs src/lib.rs tests/redact_features.rs mise.toml
git commit -m "feat(redact): add verify subcommand to detect secrets.rs/yaml pattern drift"
```

---

## Notes

- `build_patterns` **must** use `g.applies_at(level)`, not `g.enabled` — the `pii` group has `min_level: standard` and would silently fire at `minimal` otherwise
- `apply_profile("pii")` bumps level to `standard` automatically so pii patterns actually activate
- `apply_profile` and `build_patterns` are module-level so both `cmd_redact` and `cmd_scan` can call them
- `cmd_verify` uses `obfsck::SECRET_PATTERN_DEFS` directly — no file I/O for the `secrets.rs` side; the YAML side uses the already-embedded `BUNDLED_CONFIG` constant
- `tests/redact_features.rs` requires `#![cfg(feature = "analyzer")]` at the top — all three binaries and clap are behind that feature flag
