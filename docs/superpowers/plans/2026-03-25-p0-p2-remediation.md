# P0–P2 Council Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix four council-identified issues: PII level-gating (P0), username regex charset (P1), over-broad GitHub secret-scanning exclusions (P2a), and missing redact-CLI integration tests (P2b).

**Architecture:** All changes are confined to `src/lib.rs`, `config/secrets.yaml`, `tests/`, and `.github/secret_scanning.yml`. No new crates needed; the existing test harness pattern (`env!("CARGO_BIN_EXE_redact")`) covers CLI integration tests.

**Tech Stack:** Rust (regex, serde/serde_yaml), YAML config, `std::process::Command` for CLI tests. One new dev-dependency: `tempfile = "3"` (Task 4).

---

## File Map

| File | Change |
|------|--------|
| `src/lib.rs` (yaml_config, lines 643–668) | Add `MinLevel` enum + `min_level` field to `Group`; add `Group::applies_at()` method |
| `src/lib.rs` (user_re, line 615) | Expand `\w+` → `[A-Za-z0-9._-]+` in username capture group |
| `config/secrets.yaml` (pii block, ~line 282) | Add `min_level: standard` to the `pii` group |
| `src/bin/redact.rs` (filter chain, lines 49–66) | Replace `filter(g.enabled)` with `filter(g.applies_at(level))` |
| `tests/redact_yaml.rs` (apply_yaml_patterns, lines 5–31) | Replace `filter(g.enabled)` with `filter(g.applies_at(level))` |
| `tests/redact_yaml.rs` | Add `test_pii_not_applied_at_minimal` and `test_pii_applied_at_standard` |
| `tests/test_obfuscation.rs` | Add tests for dotted and hyphenated usernames |
| `tests/test_redact_cli.rs` (new) | Integration tests for redact CLI file I/O |
| `.github/secret_scanning.yml` | Narrow `demo/examples/**` → `demo/examples/*.yaml` |

---

## Task 1 (P0): PII Level-Gating — data structures

**Files:**
- Modify: `src/lib.rs:643-668` (yaml_config module)

- [ ] **Step 1: Write the failing test** in `tests/redact_yaml.rs`

Add after the existing `test_pii_redacted_at_standard` test.
Note: `test_pii_redacted_at_standard` already covers standard-level behaviour; only the minimal-level guard is new.

```rust
#[test]
fn test_pii_not_applied_at_minimal() {
    let yaml = include_str!("../config/secrets.yaml");
    // SSN and CC are PII-group patterns — must NOT fire at minimal level
    let input = "ssn=123-45-6789 card=4111111111111111";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(
        result.contains("123-45-6789"),
        "PII (SSN) should NOT be redacted at minimal: {result}"
    );
    assert!(
        result.contains("4111111111111111"),
        "PII (CC) should NOT be redacted at minimal: {result}"
    );
}
```

- [ ] **Step 2: Run to confirm it fails**

```bash
mise run test -- --test redact_yaml test_pii_not_applied_at_minimal 2>&1 | tail -20
```

Expected: FAILS — PII fires even at minimal before the fix.

- [ ] **Step 3: Add `MinLevel` enum and `applies_at` to `yaml_config` in `src/lib.rs`**

Replace the `yaml_config` module (lines 643–668) with:

```rust
pub mod yaml_config {
    use indexmap::IndexMap;
    use serde::Deserialize;

    #[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
    #[serde(rename_all = "lowercase")]
    pub enum MinLevel {
        Minimal,
        Standard,
        Paranoid,
    }

    #[derive(Deserialize)]
    pub struct SecretsConfig {
        pub groups: IndexMap<String, Group>,
        #[serde(default)]
        pub custom: Vec<PatternDef>,
    }

    #[derive(Deserialize)]
    pub struct Group {
        pub enabled: bool,
        #[serde(default)]
        pub min_level: Option<MinLevel>,
        pub patterns: Vec<PatternDef>,
    }

    impl Group {
        /// Returns true if this group should run at the given obfuscation level.
        pub fn applies_at(&self, level: super::ObfuscationLevel) -> bool {
            if !self.enabled {
                return false;
            }
            match self.min_level {
                None | Some(MinLevel::Minimal) => true,
                Some(MinLevel::Standard) => matches!(
                    level,
                    super::ObfuscationLevel::Standard | super::ObfuscationLevel::Paranoid
                ),
                Some(MinLevel::Paranoid) => level == super::ObfuscationLevel::Paranoid,
            }
        }
    }

    #[derive(Deserialize)]
    pub struct PatternDef {
        pub name: String,
        pub pattern: String,
        pub label: String,
        #[serde(default)]
        pub paranoid_only: bool,
    }
}
```

- [ ] **Step 4: Add `min_level: standard` to the `pii` group in `config/secrets.yaml`**

Find the `pii:` block (around line 282) and add the field right after `enabled: true`:

```yaml
  pii:
    enabled: true
    min_level: standard
    patterns:
```

- [ ] **Step 5: Update filter in `src/bin/redact.rs` (lines 49–52)**

Replace:
```rust
        .filter(|g| g.enabled)
```
With:
```rust
        .filter(|g| g.applies_at(level))
```

- [ ] **Step 6: Update `apply_yaml_patterns` helper in `tests/redact_yaml.rs` (lines 9–11)**

Replace:
```rust
        .filter(|g| g.enabled)
```
With:
```rust
        .filter(|g| g.applies_at(level))
```

- [ ] **Step 7: Run tests to confirm they pass**

```bash
mise run test -- --test redact_yaml 2>&1 | tail -20
```

Expected: all redact_yaml tests pass, including the two new PII tests.

- [ ] **Step 8: Run full CI check**

```bash
mise run ci 2>&1 | tail -30
```

Expected: all tests pass, no clippy warnings.

- [ ] **Step 9: Commit**

```bash
git add src/lib.rs config/secrets.yaml src/bin/redact.rs tests/redact_yaml.rs
git commit -m "feat(pii): gate PII group to standard+ level with min_level field

Adds MinLevel enum and Group::applies_at() to yaml_config.
Sets min_level: standard on the pii group so minimal mode
remains secrets-only as documented.
Adds regression tests: pii_not_applied_at_minimal, pii_applied_at_standard."
```

---

## Task 2 (P1): Username Regex — POSIX charset expansion

**Files:**
- Modify: `src/lib.rs:615` (user_re function)
- Modify: `tests/test_obfuscation.rs` (add tests)

- [ ] **Step 1: Write the failing tests** in `tests/test_obfuscation.rs`

Add after `obfuscate_text_replaces_ip_email_and_user_tokens`:

```rust
#[test]
fn user_re_matches_dotted_username() {
    // /Users/john.smith should redact john.smith as a username
    let input = "session started /Users/john.smith/.config";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        map.users.contains_key("john.smith"),
        "dotted username not captured; map={map:?}\nout={out}"
    );
}

#[test]
fn user_re_matches_hyphenated_username() {
    // /home/deploy-user paths should redact deploy-user
    let input = "running as /home/deploy-user process";
    let (out, map) = obfuscate_text(input, ObfuscationLevel::Standard);
    assert!(
        map.users.contains_key("deploy-user"),
        "hyphenated username not captured; map={map:?}\nout={out}"
    );
}
```

- [ ] **Step 2: Run to confirm they fail**

```bash
mise run test -- --test test_obfuscation user_re_matches_dotted_username user_re_matches_hyphenated_username 2>&1 | tail -20
```

Expected: both FAIL (only `\w+` chars captured, stopping at `.` or `-`).

- [ ] **Step 3: Fix user_re in `src/lib.rs` line 615**

Replace:
```rust
        Regex::new(r"(?i)(user=|uid=|username=|--username\s+|by user |/users/|/home/)(\w+)")
```
With:
```rust
        Regex::new(r"(?i)(user=|uid=|username=|--username\s+|by user |/users/|/home/)([A-Za-z0-9._-]+)")
```

- [ ] **Step 4: Run tests to confirm they pass**

```bash
mise run test -- --test test_obfuscation 2>&1 | tail -20
```

Expected: all test_obfuscation tests pass.

- [ ] **Step 5: Run full CI check**

```bash
mise run ci 2>&1 | tail -20
```

Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add src/lib.rs tests/test_obfuscation.rs
git commit -m "fix(users): expand username regex charset to include dots and hyphens

\w+ missed POSIX usernames like john.smith or deploy-user.
Now captures [A-Za-z0-9._-]+ to match common real-world usernames.
Adds regression tests for dotted and hyphenated paths under
/Users/ and /home/."
```

---

## Task 3 (P2a): Narrow GitHub secret-scanning ignore rules

**Files:**
- Modify: `.github/secret_scanning.yml`

This is a one-liner config change — no tests needed (GitHub Advanced Security validates it server-side).

- [ ] **Step 1: Update `.github/secret_scanning.yml`**

Replace `demo/examples/**` with `demo/examples/*.yaml` to limit the exclusion to direct YAML children only, preventing subdirectories from being silently excluded if they're added later:

```yaml
paths-ignore:
  - 'demo/examples/*.yaml'
  - 'docs/superpowers/plans/**'
  - 'docs/superpowers/specs/**'
```

- [ ] **Step 2: Commit**

```bash
git add .github/secret_scanning.yml
git commit -m "fix(security): narrow secret-scanning ignore to demo/examples/*.yaml

Was ignoring the entire demo/examples/** tree. Now only excludes
direct YAML fixture files, so any subdirectories or non-YAML files
added later will still be scanned for real credentials."
```

---

## Task 4 (P2b): Integration tests for `redact` CLI file I/O

**Files:**
- Create: `tests/test_redact_cli.rs`

- [ ] **Step 1: Create `tests/test_redact_cli.rs`** with the following content:

```rust
//! Integration tests for the `redact` CLI binary — file I/O paths.
#![cfg(feature = "analyzer")]

use std::io::Write;
use std::process::Command;

fn redact_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_redact"))
}

/// Write content to a named temp file; caller owns cleanup.
fn temp_file_with(content: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().expect("temp file");
    f.write_all(content.as_bytes()).expect("write temp");
    f
}

#[test]
fn file_input_redacts_secret_to_stdout() {
    let input = temp_file_with("aws_key=AKIA1234567890ABCDEF\n");
    let out = redact_bin()
        .arg(input.path())
        .arg("--level")
        .arg("minimal")
        .output()
        .expect("run redact");

    assert!(out.status.success(), "exit code: {:?}", out.status);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("[REDACTED-AWS-KEY]"), "got: {stdout}");
    assert!(!stdout.contains("AKIA"), "key leaked: {stdout}");
}

#[test]
fn file_output_writes_redacted_content() {
    let input = temp_file_with("aws_key=AKIA1234567890ABCDEF\n");
    let out_file = tempfile::NamedTempFile::new().expect("out temp file");

    let status = redact_bin()
        .arg(input.path())
        .arg("--level")
        .arg("minimal")
        .arg("--output")
        .arg(out_file.path())
        .status()
        .expect("run redact");

    assert!(status.success(), "exit code: {status:?}");
    let content = std::fs::read_to_string(out_file.path()).expect("read output");
    assert!(content.contains("[REDACTED-AWS-KEY]"), "got: {content}");
    assert!(!content.contains("AKIA"), "key leaked: {content}");
}

#[test]
fn file_input_and_output_round_trip() {
    let secret = "token=ghp_abcdefghijklmnopqrstuvwxyz123456789\n";
    let input = temp_file_with(secret);
    let out_file = tempfile::NamedTempFile::new().expect("out temp file");

    let status = redact_bin()
        .arg(input.path())
        .arg("--output")
        .arg(out_file.path())
        .status()
        .expect("run redact");

    assert!(status.success());
    let content = std::fs::read_to_string(out_file.path()).expect("read output");
    assert!(content.contains("[REDACTED-GITHUB-TOKEN]"), "got: {content}");
    assert!(!content.contains("ghp_"), "token leaked: {content}");
}

#[test]
fn nonexistent_input_file_exits_nonzero() {
    let status = redact_bin()
        .arg("/tmp/obfsck-test-nonexistent-file-12345.txt")
        .status()
        .expect("run redact");
    assert!(!status.success(), "should have failed with nonzero exit");
}
```

- [ ] **Step 2: Add `tempfile` to dev-dependencies in `Cargo.toml`**

In `[dev-dependencies]` section, add:
```toml
tempfile = "3"
```

- [ ] **Step 3: Run to confirm tests pass**

```bash
mise run test -- --test test_redact_cli 2>&1 | tail -20
```

Expected: all 4 tests pass.

- [ ] **Step 4: Run full CI check**

```bash
mise run ci 2>&1 | tail -30
```

Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add tests/test_redact_cli.rs Cargo.toml
git commit -m "test(redact): add CLI integration tests for file I/O paths

Covers file input, file output, combined file-in/file-out,
and nonexistent-input failure. Uses tempfile for safe isolation.
Fixes the coverage gap identified in P2 council action item."
```
