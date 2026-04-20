# Codegen `secrets.rs` from YAML Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-maintained `src/secrets.rs` pattern list with a `build.rs` code generator that reads `config/secrets.yaml` and emits `src/secrets.rs` as a generated Rust file, eliminating drift between the two sources of truth.

**Architecture:** A `build.rs` at the workspace root reads `config/secrets.yaml`, parses it with a minimal inline YAML parser (no external deps — `build.rs` cannot use `[dependencies]`), and writes a `secrets.rs` file into `$OUT_DIR`. `src/lib.rs` replaces `mod secrets;` with `include!(concat!(env!("OUT_DIR"), "/secrets.rs"))`. The generated file is no longer checked in. A CI step (`cargo build`) regenerates it; drift is impossible at build time.

**Tech Stack:** Rust `build.rs`, `std` only (no deps), `cargo test`, `mise run ci`

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `build.rs` | **Create** | Reads YAML, emits `secrets.rs` into `$OUT_DIR` |
| `src/lib.rs` | **Modify** | Replace `mod secrets; use secrets::SECRET_PATTERN_DEFS;` with `include!` macro pointing to `$OUT_DIR/secrets.rs` |
| `src/secrets.rs` | **Delete** | No longer needed — generated at build time |
| `config/secrets.yaml` | No change | Remains the single source of truth |

---

## Task 1: Write a failing test that verifies `build.rs` output structure

**Files:**
- Create: `tests/codegen_smoke.rs`

The goal is a smoke test that calls `cargo build` and then checks that `obfsck::SECRET_PATTERN_DEFS` is non-empty and that known pattern names are present. Since `SECRET_PATTERN_DEFS` is currently exposed via `pub use secrets::SECRET_PATTERN_DEFS` in `lib.rs`, we can test it directly.

- [ ] **Step 1: Write the test**

Create `tests/codegen_smoke.rs`:

```rust
// Smoke test: verifies the generated secrets.rs contains expected pattern names.
// This test will PASS currently (src/secrets.rs exists). After Task 3 deletes
// src/secrets.rs and wires build.rs, it must still pass.

#[test]
fn secret_pattern_defs_non_empty() {
    assert!(
        !obfsck::SECRET_PATTERN_DEFS.is_empty(),
        "SECRET_PATTERN_DEFS must not be empty"
    );
}

#[test]
fn known_patterns_present() {
    let names: Vec<&str> = obfsck::SECRET_PATTERN_DEFS.iter().map(|p| p.name).collect();
    for expected in &[
        "aws_access_key",
        "github_pat",
        "anthropic_api_key",
        "openai_api_key",
        "jwt",
        "postgres_uri",
        "slack_bot_token",
    ] {
        assert!(
            names.contains(expected),
            "Expected pattern '{}' not found in SECRET_PATTERN_DEFS",
            expected
        );
    }
}

#[test]
fn paranoid_only_flag_present() {
    // At least one pattern should be paranoid_only = true (e.g. heroku_api_key, aws_secret_key)
    let has_paranoid = obfsck::SECRET_PATTERN_DEFS.iter().any(|p| p.paranoid_only);
    assert!(has_paranoid, "Expected at least one paranoid_only pattern");
}
```

- [ ] **Step 2: Verify `SECRET_PATTERN_DEFS` is currently public**

Check `src/lib.rs` for the `pub` visibility of `SecretPatternDef` and `SECRET_PATTERN_DEFS`:

```bash
cargo test codegen_smoke 2>&1 | tail -20
```

If it fails with "no field `name`" or visibility errors, make `SECRET_PATTERN_DEFS` pub in `src/secrets.rs` (it already is: `pub(crate) const`). The test will need it `pub`. Check:

```rust
// In src/secrets.rs, line 3 — currently:
pub(crate) const SECRET_PATTERN_DEFS: &[SecretPatternDef] = &[
// Change to:
pub const SECRET_PATTERN_DEFS: &[SecretPatternDef] = &[
```

And in `src/lib.rs`, re-export it:
```rust
pub use secrets::SECRET_PATTERN_DEFS;
```

- [ ] **Step 3: Run the test and confirm it passes (baseline)**

```bash
cargo test codegen_smoke 2>&1
```

Expected: all 3 tests pass. This is the baseline we must preserve after the codegen refactor.

- [ ] **Step 4: Commit**

```bash
git add tests/codegen_smoke.rs src/secrets.rs src/lib.rs
git commit -m "test(codegen): add smoke tests for SECRET_PATTERN_DEFS baseline"
```

---

## Task 2: Write `build.rs` — YAML parser and code emitter

**Files:**
- Create: `build.rs`

`build.rs` cannot use `[dependencies]` — only `std`. We write a minimal line-by-line YAML parser sufficient for `config/secrets.yaml`'s structure.

The YAML structure is:
```yaml
groups:
  group_name:
    enabled: true
    patterns:
      - name: foo
        pattern: 'regex'
        label: FOO
        paranoid_only: false
```

We parse patterns from all groups and emit a Rust `const` array.

- [ ] **Step 1: Create `build.rs`**

```rust
// build.rs — generates src/secrets.rs from config/secrets.yaml
// Uses std only (no build-deps). Minimal line-by-line YAML parser.

use std::fs;
use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=config/secrets.yaml");

    let yaml_path = PathBuf::from("config/secrets.yaml");
    let yaml = fs::read_to_string(&yaml_path)
        .expect("build.rs: cannot read config/secrets.yaml");

    let patterns = parse_patterns(&yaml);
    let code = emit_rust(&patterns);

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = PathBuf::from(&out_dir).join("secrets.rs");
    fs::write(&out_path, code).expect("build.rs: cannot write secrets.rs");
}

#[derive(Debug, Default)]
struct PatternEntry {
    name: String,
    pattern: String,
    label: String,
    paranoid_only: bool,
}

/// Minimal line-by-line parser for config/secrets.yaml.
/// Handles the specific structure produced by this file — not a general YAML parser.
fn parse_patterns(yaml: &str) -> Vec<PatternEntry> {
    let mut patterns: Vec<PatternEntry> = Vec::new();
    let mut current: Option<PatternEntry> = None;

    for raw_line in yaml.lines() {
        // Strip inline comments (# not inside quotes)
        let line = strip_inline_comment(raw_line);
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        // New list item — start a pattern entry
        if trimmed.starts_with("- name:") {
            if let Some(prev) = current.take() {
                if !prev.name.is_empty() {
                    patterns.push(prev);
                }
            }
            let mut entry = PatternEntry::default();
            entry.name = extract_scalar(trimmed, "- name:").to_string();
            current = Some(entry);
            continue;
        }

        if let Some(ref mut entry) = current {
            if let Some(val) = try_extract(trimmed, "pattern:") {
                entry.pattern = val;
            } else if let Some(val) = try_extract(trimmed, "label:") {
                entry.label = val;
            } else if trimmed.starts_with("paranoid_only:") {
                let val = trimmed.trim_start_matches("paranoid_only:").trim();
                entry.paranoid_only = val == "true";
            }
        }
    }

    if let Some(last) = current {
        if !last.name.is_empty() {
            patterns.push(last);
        }
    }

    patterns
}

/// Strip `# comment` from end of line, but not when inside a single-quoted string.
fn strip_inline_comment(line: &str) -> &str {
    let mut in_quote = false;
    let bytes = line.as_bytes();
    for i in 0..bytes.len() {
        match bytes[i] {
            b'\'' => in_quote = !in_quote,
            b'#' if !in_quote => {
                // Only strip if preceded by whitespace
                if i > 0 && bytes[i - 1] == b' ' {
                    return &line[..i];
                }
            }
            _ => {}
        }
    }
    line
}

/// Extract scalar after a key prefix, stripping quotes.
fn extract_scalar<'a>(line: &'a str, prefix: &str) -> &'a str {
    let rest = line[prefix.len()..].trim();
    rest.trim_matches('\'').trim_matches('"')
}

/// Try to extract a value for `key:` from a trimmed line, handling single-quoted strings.
fn try_extract(trimmed: &str, key: &str) -> Option<String> {
    if !trimmed.starts_with(key) {
        return None;
    }
    let rest = trimmed[key.len()..].trim();
    // Single-quoted: may contain escaped quotes as ''
    if rest.starts_with('\'') {
        // Find closing quote — '' is an escaped single quote inside single-quoted YAML
        let inner = &rest[1..]; // strip opening quote
        let mut out = String::new();
        let mut chars = inner.chars().peekable();
        loop {
            match chars.next() {
                None => break,
                Some('\'') => {
                    if chars.peek() == Some(&'\'') {
                        // Escaped quote: '' → '
                        chars.next();
                        out.push('\'');
                    } else {
                        // Closing quote
                        break;
                    }
                }
                Some(c) => out.push(c),
            }
        }
        return Some(out);
    }
    // Unquoted or double-quoted
    Some(rest.trim_matches('"').to_string())
}

fn emit_rust(patterns: &[PatternEntry]) -> String {
    let mut out = String::from(
        "// @generated by build.rs from config/secrets.yaml — DO NOT EDIT.\n\
         // Edit config/secrets.yaml and run `cargo build` to regenerate.\n\
         \n\
         use super::SecretPatternDef;\n\
         \n\
         pub const SECRET_PATTERN_DEFS: &[SecretPatternDef] = &[\n",
    );

    for p in patterns {
        // Escape backslashes for Rust raw string — use r#"..."# to avoid issues
        let pattern_escaped = p.pattern.replace('\\', "\\\\").replace('"', "\\\"");
        out.push_str(&format!(
            "    SecretPatternDef {{\n\
             \        name: \"{name}\",\n\
             \        pattern: \"{pattern}\",\n\
             \        label: \"{label}\",\n\
             \        paranoid_only: {paranoid_only},\n\
             \    }},\n",
            name = p.name,
            pattern = pattern_escaped,
            label = p.label,
            paranoid_only = p.paranoid_only,
        ));
    }

    out.push_str("];\n");
    out
}
```

- [ ] **Step 2: Verify `build.rs` compiles and generates output**

```bash
cargo build --no-default-features 2>&1 | tail -20
```

Expected: compiles cleanly. Check the generated file:

```bash
cat $(cargo metadata --no-deps --format-version 1 | python3 -c "import sys,json; print(json.load(sys.stdin)['target_directory']")/debug/build/obfsck-*/out/secrets.rs | head -30
```

Or simply:

```bash
find target -name "secrets.rs" -path "*/obfsck-*/out/*" 2>/dev/null | head -1 | xargs head -30
```

Expected output starts with:
```
// @generated by build.rs from config/secrets.yaml — DO NOT EDIT.
```

- [ ] **Step 3: Commit**

```bash
git add build.rs
git commit -m "build: add build.rs to generate secrets.rs from config/secrets.yaml"
```

---

## Task 3: Wire `src/lib.rs` to use the generated file, delete `src/secrets.rs`

**Files:**
- Modify: `src/lib.rs` (2 lines)
- Delete: `src/secrets.rs`

- [ ] **Step 1: Replace the `mod secrets` declaration in `src/lib.rs`**

Find these lines in `src/lib.rs` (around line 502-503):
```rust
mod secrets;
use secrets::SECRET_PATTERN_DEFS;
```

Replace with:
```rust
mod secrets {
    use super::SecretPatternDef;
    include!(concat!(env!("OUT_DIR"), "/secrets.rs"));
}
use secrets::SECRET_PATTERN_DEFS;
```

The `include!` macro splices the generated file's content into the `secrets` module. The `use super::SecretPatternDef;` makes the type available inside the generated code (which references `SecretPatternDef` via `use super::SecretPatternDef;` in its header — but since `include!` inlines the file literally, the `use super::SecretPatternDef;` in the generated file will be a duplicate; remove it from `emit_rust` in `build.rs` and instead provide `SecretPatternDef` via the `use super::SecretPatternDef;` in the `mod secrets` block above).

Specifically, update `emit_rust` in `build.rs` to **remove** the `use super::SecretPatternDef;\n` line from the generated output header — the `mod secrets` block in `lib.rs` provides it instead:

```rust
fn emit_rust(patterns: &[PatternEntry]) -> String {
    let mut out = String::from(
        "// @generated by build.rs from config/secrets.yaml — DO NOT EDIT.\n\
         // Edit config/secrets.yaml and run `cargo build` to regenerate.\n\
         \n\
         pub const SECRET_PATTERN_DEFS: &[SecretPatternDef] = &[\n",
    );
    // ... rest unchanged
```

- [ ] **Step 2: Delete `src/secrets.rs`**

```bash
rm src/secrets.rs
```

- [ ] **Step 3: Build to verify it compiles**

```bash
cargo build --no-default-features 2>&1
```

Expected: clean build, no errors.

```bash
cargo build 2>&1
```

Expected: clean build with all features.

- [ ] **Step 4: Run the smoke tests**

```bash
cargo test codegen_smoke 2>&1
```

Expected: all 3 tests pass (`secret_pattern_defs_non_empty`, `known_patterns_present`, `paranoid_only_flag_present`).

- [ ] **Step 5: Run the full test suite**

```bash
cargo test 2>&1 | tail -30
```

Expected: all tests pass.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs build.rs
git rm src/secrets.rs
git commit -m "refactor: generate secrets.rs from YAML via build.rs, delete hand-maintained copy"
```

---

## Task 4: Verify `mise run ci` passes and add `.gitignore` note

**Files:**
- Possibly modify: `.gitignore` (if `src/secrets.rs` was listed)

- [ ] **Step 1: Run full CI gate**

```bash
mise run ci 2>&1
```

Expected: lint + test + build all pass.

- [ ] **Step 2: Check `.gitignore` — `src/secrets.rs` must not be tracked**

```bash
git status src/secrets.rs
```

Expected: `src/secrets.rs` does not appear (deleted from index in Task 3).

- [ ] **Step 3: Add a comment to `config/secrets.yaml` header**

Ensure the top of `config/secrets.yaml` has (or add) a comment:

```yaml
# Single source of truth for secret patterns.
# Edit this file and run `cargo build` to regenerate src/secrets.rs.
# DO NOT manually edit the generated file in $OUT_DIR.
```

- [ ] **Step 4: Run clippy**

```bash
cargo clippy --all-features 2>&1
```

Expected: no warnings.

- [ ] **Step 5: Commit**

```bash
git add config/secrets.yaml
git commit -m "docs(config): note that secrets.yaml is the source of truth for codegen"
```

---

## Self-Review

**Spec coverage:**
- ✅ `src/secrets.rs` deleted — generated at build time
- ✅ `build.rs` reads `config/secrets.yaml` with std-only parser
- ✅ `src/lib.rs` wired via `include!` macro
- ✅ Smoke tests guard behavioral regression
- ✅ `mise run ci` verified

**Placeholder scan:** None found.

**Type consistency:** `SecretPatternDef` referenced consistently across `lib.rs`, `build.rs` output, and tests. `SECRET_PATTERN_DEFS` is `pub const` in generated file, re-exported from `secrets` mod in `lib.rs`.

**Edge case — YAML patterns with backslashes:** The `try_extract` function handles single-quoted YAML strings (which use `''` for escaping, not `\`). The `emit_rust` function double-escapes backslashes for the Rust string literal. This covers all patterns in `config/secrets.yaml` which use single-quoted regex strings.

**Edge case — multiline patterns:** `config/secrets.yaml` has one multiline-flagged pattern (`(?s)...`). This is a single-line YAML value and parses correctly with the line-by-line approach.
