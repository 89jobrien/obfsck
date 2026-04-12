# YAML Secret Config Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace hardcoded `secrets.rs` patterns with a grouped YAML config that users can customize without recompiling, and add a PII group for the PM inquiry.

**Architecture:** Bundle `config/secrets.yaml` into the `redact` binary via `include_str!`. At runtime, check `~/.config/obfsck/secrets.yaml` for user overrides (full replacement). The `redact` binary applies YAML patterns directly — it does **not** call `obfuscate_text` for secrets, only for level-based structural obfuscation (IP, email, hostname). This ensures YAML group `enabled: false` semantics are fully respected and patterns don't double-fire from `secrets.rs`.

**Tech Stack:** Rust 2024, `serde`/`serde_yaml` (already in project behind `analyzer` feature, which is the default), `clap` (already in project behind `analyzer` feature), `regex` (non-optional), `shellexpand` (already in project behind `analyzer` feature).

> **Note on `include_str!` paths:** Paths in `include_str!` are relative to the **source file**, not the working directory. `src/bin/redact.rs` is two levels above the crate root, so `include_str!("../../config/secrets.yaml")` is correct. Integration tests at `tests/redact_yaml.rs` are one level below the crate root, so they use `include_str!("../config/secrets.yaml")`.

---

## File Map

| File | Action | Purpose |
|------|--------|---------|
| `config/secrets.yaml` | **Create** | Bundled default patterns, grouped by category — complete replacement of `secrets.rs` as source of truth |
| `src/bin/redact.rs` | **Rewrite** | Load YAML config, apply patterns, then call `obfuscate_text` only for structural obfuscation |
| `Cargo.toml` | **Modify** | Add `required-features = ["analyzer"]` to redact bin; add `serde_yaml` + `regex` to `[dev-dependencies]` |
| `tests/redact_yaml.rs` | **Create** | Integration tests for YAML loading and pattern application |

---

## Task 1: Create `config/secrets.yaml` with grouped patterns

**Files:**
- Create: `config/secrets.yaml`

This file is the single source of truth for secret patterns. Include every pattern currently in `secrets.rs`, grouped by category. `paranoid_only: true` patterns are only applied when `--level paranoid` is set. `pagerduty_api_key` (a broad 20-char base64 pattern) is moved to the `paranoid` group due to false-positive risk.

- [ ] **Step 1: Create `config/secrets.yaml`**

```yaml
# obfsck secret and PII redaction patterns
# Edit this file to customize what gets redacted.
# User overrides: ~/.config/obfsck/secrets.yaml (replaces this file entirely)
#
# Each group can be disabled with `enabled: false`.
# paranoid_only: true patterns are only applied when --level paranoid is set.

groups:

  ai_apis:
    enabled: true
    patterns:
      - name: anthropic_api_key
        pattern: '\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,}\b'
        label: ANTHROPIC-KEY
        paranoid_only: false
      - name: openai_api_key
        pattern: '\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b'
        label: OPENAI-KEY
        paranoid_only: false
      - name: groq_api_key
        pattern: '\bgsk_[A-Za-z0-9]{52}\b'
        label: GROQ-KEY
        paranoid_only: false
      - name: huggingface_token
        pattern: '\bhf_[A-Za-z0-9]{34,}\b'
        label: HUGGINGFACE-TOKEN
        paranoid_only: false
      - name: replicate_api_key
        pattern: '\br8_[A-Za-z0-9]{40}\b'
        label: REPLICATE-KEY
        paranoid_only: false
      - name: google_api_key
        pattern: '\bAIza[0-9A-Za-z_-]{35}\b'
        label: GOOGLE-API
        paranoid_only: false
      - name: google_oauth_id
        pattern: '\b[0-9]+-[A-Za-z0-9_]{32}\.apps\.googleusercontent\.com\b'
        label: GOOGLE-OAUTH
        paranoid_only: false
      - name: google_oauth_secret
        pattern: '\bGOCspx-[A-Za-z0-9_-]{28}\b'
        label: GOOGLE-SECRET
        paranoid_only: false

  cloud:
    enabled: true
    patterns:
      - name: aws_access_key
        pattern: '\b(?:A3T[A-Z0-9]|AKIA|ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA|ASIA)[A-Z0-9]{16}\b'
        label: AWS-KEY
        paranoid_only: false
      - name: aws_session_token
        pattern: '\b(?:FwoGZXIvYXdzE|IQoJb3JpZ2lu)[A-Za-z0-9/+=]+\b'
        label: AWS-SESSION
        paranoid_only: false
      - name: aws_mws_key
        pattern: '\bamzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b'
        label: AWS-MWS
        paranoid_only: false
      - name: gcp_service_account
        pattern: '\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b'
        label: GCP-SERVICE-ACCOUNT
        paranoid_only: false
      - name: azure_storage_key
        pattern: '\b[A-Za-z0-9+/]{86}==\b'
        label: AZURE-STORAGE
        paranoid_only: false
      - name: azure_sas_token
        pattern: '\bsig=[A-Za-z0-9%]+&se=[0-9]+&[A-Za-z0-9&=%]+\b'
        label: AZURE-SAS
        paranoid_only: false
      - name: digitalocean_pat
        pattern: '\bdop_v1_[a-f0-9]{64}\b'
        label: DO-TOKEN
        paranoid_only: false
      - name: digitalocean_oauth
        pattern: '\bdoo_v1_[a-f0-9]{64}\b'
        label: DO-OAUTH
        paranoid_only: false
      - name: digitalocean_refresh
        pattern: '\bdor_v1_[a-f0-9]{64}\b'
        label: DO-REFRESH
        paranoid_only: false
      - name: cloudflare_origin_ca
        pattern: '\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b'
        label: CLOUDFLARE-CA
        paranoid_only: false
      - name: heroku_api_key
        pattern: '\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b'
        label: HEROKU-KEY
        paranoid_only: false

  version_control:
    enabled: true
    patterns:
      - name: github_fine_grained
        pattern: '\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b'
        label: GITHUB-TOKEN
        paranoid_only: false
      - name: github_pat
        pattern: '\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b'
        label: GITHUB-TOKEN
        paranoid_only: false
      - name: gitlab_pat
        pattern: '\bglpat-[A-Za-z0-9_-]{20,}\b'
        label: GITLAB-TOKEN
        paranoid_only: false
      - name: gitlab_pipeline
        pattern: '\bglptt-[A-Za-z0-9]{40}\b'
        label: GITLAB-PIPELINE
        paranoid_only: false
      - name: gitlab_runner
        pattern: '\bGR1348941[A-Za-z0-9_-]{20,}\b'
        label: GITLAB-RUNNER
        paranoid_only: false

  communication:
    enabled: true
    patterns:
      - name: slack_bot_token
        pattern: '\bxoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}\b'
        label: SLACK-BOT
        paranoid_only: false
      - name: slack_user_token
        pattern: '\bxoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}\b'
        label: SLACK-USER
        paranoid_only: false
      - name: slack_app_token
        pattern: '\bxapp-[0-9]-[A-Z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{64}\b'
        label: SLACK-APP
        paranoid_only: false
      - name: slack_webhook
        pattern: 'https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24}'
        label: SLACK-WEBHOOK
        paranoid_only: false
      - name: discord_bot_token
        pattern: '\b(?:MTA|MTE|MTI|OT|Nj|Nz|OD)[A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}\b'
        label: DISCORD-BOT
        paranoid_only: false
      - name: discord_webhook
        pattern: 'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
        label: DISCORD-WEBHOOK
        paranoid_only: false
      - name: telegram_bot_token
        pattern: '\b[0-9]{8,10}:[A-Za-z0-9_-]{35}\b'
        label: TELEGRAM-BOT
        paranoid_only: false

  payments:
    enabled: true
    patterns:
      - name: stripe_secret_key
        pattern: '\b(?:sk|rk)_(?:test|live)_[A-Za-z0-9]{24,}\b'
        label: STRIPE-SECRET
        paranoid_only: false
      - name: stripe_publishable_key
        pattern: '\bpk_(?:test|live)_[A-Za-z0-9]{24,}\b'
        label: STRIPE-KEY
        paranoid_only: false
      - name: stripe_restricted_key
        pattern: '\brk_(?:test|live)_[A-Za-z0-9]{24,}\b'
        label: STRIPE-RESTRICTED
        paranoid_only: false
      - name: twilio_api_key
        pattern: '\bSK[a-f0-9]{32}\b'
        label: TWILIO-KEY
        paranoid_only: false
      - name: twilio_account_sid
        pattern: '\bAC[a-f0-9]{32}\b'
        label: TWILIO-SID
        paranoid_only: false
      - name: sendgrid_api_key
        pattern: '\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b'
        label: SENDGRID-KEY
        paranoid_only: false
      - name: mailchimp_api_key
        pattern: '\b[a-f0-9]{32}-us[0-9]{1,2}\b'
        label: MAILCHIMP-KEY
        paranoid_only: false
      - name: mailgun_api_key
        pattern: '\bkey-[A-Za-z0-9]{32}\b'
        label: MAILGUN-KEY
        paranoid_only: false

  databases:
    enabled: true
    patterns:
      - name: postgres_uri
        pattern: 'postgres(?:ql)?://[^:\s]+:[^@\s]+@[^/\s]+/\w+'
        label: DB-POSTGRES
        paranoid_only: false
      - name: mysql_uri
        pattern: 'mysql://[^:\s]+:[^@\s]+@[^/\s]+/\w+'
        label: DB-MYSQL
        paranoid_only: false
      - name: mongodb_uri
        pattern: 'mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@[^/\s]+'
        label: DB-MONGODB
        paranoid_only: false
      - name: redis_uri
        pattern: 'redis://[^:\s]+:[^@\s]+@[^/\s]+'
        label: DB-REDIS
        paranoid_only: false

  package_managers:
    enabled: true
    patterns:
      - name: npm_token
        pattern: '\bnpm_[A-Za-z0-9]{36}\b'
        label: NPM-TOKEN
        paranoid_only: false
      - name: pypi_token
        pattern: '\bpypi-[A-Za-z0-9_-]{50,}\b'
        label: PYPI-TOKEN
        paranoid_only: false
      - name: nuget_api_key
        pattern: '\boy2[A-Za-z0-9]{43}\b'
        label: NUGET-KEY
        paranoid_only: false

  monitoring:
    enabled: true
    patterns:
      - name: sentry_dsn
        pattern: 'https://[a-f0-9]{32}@[a-z0-9]+\.ingest\.sentry\.io/[0-9]+'
        label: SENTRY-DSN
        paranoid_only: false

  generic:
    enabled: true
    patterns:
      - name: jwt
        pattern: '\beyJ[A-Za-z0-9_.+-/=]*\.[A-Za-z0-9_.+-/=]*\.[A-Za-z0-9_.+-/=]*\b'
        label: JWT
        paranoid_only: false
      - name: private_key_content
        pattern: '(?s)-----BEGIN[^-]+-----[A-Za-z0-9+/=\s]+-----END[^-]+-----'
        label: PRIVATE-KEY
        paranoid_only: false
      - name: private_key
        pattern: '-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----'
        label: PRIVATE-KEY
        paranoid_only: false
      - name: ssh_private_key
        pattern: '-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
        label: SSH-PRIVATE-KEY
        paranoid_only: false
      - name: ssh_public_key
        pattern: 'ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/]+={0,2}'
        label: SSH-PUBLIC-KEY
        paranoid_only: false
      - name: password_field
        pattern: '(?:password|passwd|pwd|secret_key|auth_key|private_key|encryption_key)\s*[=:]\s*["\x27]?[^\s"\x27]{8,}["\x27]?'
        label: PASSWORD
        paranoid_only: false
      - name: basic_auth
        pattern: '\bBasic\s+[A-Za-z0-9+/]+=*\b'
        label: BASIC-AUTH
        paranoid_only: false
      - name: bearer_token
        pattern: '\bBearer\s+[A-Za-z0-9_.-]+\b'
        label: BEARER-TOKEN
        paranoid_only: false

  # PII patterns — disabled by default due to false-positive risk.
  # Enable for compliance/data-sharing use cases by copying this group
  # to ~/.config/obfsck/secrets.yaml with enabled: true.
  # For the PM inquiry: share this group and note that phone/passport
  # patterns have high false-positive rates in log data.
  pii:
    enabled: false
    patterns:
      - name: ssn_us
        pattern: '\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b'
        label: SSN
        paranoid_only: false
      - name: credit_card
        pattern: '\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b'
        label: CREDIT-CARD
        paranoid_only: false
      - name: phone_us
        pattern: '\b(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b'
        label: PHONE
        paranoid_only: false
      - name: iban
        pattern: '\b[A-Z]{2}\d{2}[A-Z0-9]{1,30}\b'
        label: IBAN
        paranoid_only: false
      - name: passport
        pattern: '\b[A-Z]{1,2}[0-9]{6,9}\b'
        label: PASSPORT
        paranoid_only: true
      - name: drivers_license_us
        pattern: '\b[A-Z]\d{7}\b'
        label: DRIVERS-LICENSE
        paranoid_only: true

  # High false-positive risk — only applied with --level paranoid.
  # pagerduty_api_key moved here (20-char base64 pattern, too broad for minimal).
  paranoid:
    enabled: true
    patterns:
      - name: aws_secret_key
        pattern: '\b[A-Za-z0-9+/]{40}\b'
        label: AWS-SECRET
        paranoid_only: true
      - name: azure_client_secret
        pattern: '\b[A-Za-z0-9~._-]{34}\b'
        label: AZURE-SECRET
        paranoid_only: true
      - name: datadog_api_key
        pattern: '\b[a-f0-9]{32}\b'
        label: DATADOG-API
        paranoid_only: true
      - name: datadog_app_key
        pattern: '\b[a-f0-9]{40}\b'
        label: DATADOG-APP
        paranoid_only: true
      - name: twilio_auth_token
        pattern: '\b[a-f0-9]{32}\b'
        label: TWILIO-AUTH
        paranoid_only: true
      - name: pagerduty_api_key
        pattern: '\b[A-Za-z0-9+/]{20}\b'
        label: PAGERDUTY-KEY
        paranoid_only: true
      - name: cloudflare_api_key
        pattern: '\b[A-Za-z0-9_-]{37}\b'
        label: CLOUDFLARE-KEY
        paranoid_only: true
      - name: base64_secret
        pattern: '\b[A-Za-z0-9+/]{40,}={0,2}\b'
        label: SECRET
        paranoid_only: true

# Add your own patterns here. Always applied (unless paranoid_only: true and level < paranoid).
custom: []
```

- [ ] **Step 2: Commit**

```bash
git add config/secrets.yaml
git commit -m "feat: add grouped secrets.yaml with ai_apis, pii, and paranoid groups"
```

---

## Task 2: Wire `redact` binary to load YAML config

**Files:**
- Modify: `Cargo.toml`
- Rewrite: `src/bin/redact.rs`
- Create: `tests/redact_yaml.rs`

**Architecture note:** The binary applies YAML patterns first (label replacement), then calls `obfuscate_text` for level-based structural obfuscation only (IPs, emails, hostnames). It does NOT rely on `obfuscate_text` for secret patterns — that would bypass group `enabled` semantics and cause double-firing for any pattern also in `secrets.rs`.

- [ ] **Step 1: Add dev-dependencies and `required-features` to `Cargo.toml`**

```toml
# Add to [dev-dependencies]:
regex = "1"
serde_yaml = "0.9"
serde = { version = "1", features = ["derive"] }

# Change the redact [[bin]] entry to:
[[bin]]
name = "redact"
path = "src/bin/redact.rs"
required-features = ["analyzer"]
```

- [ ] **Step 2: Write the failing tests** (`tests/redact_yaml.rs`)

```rust
// tests/redact_yaml.rs
use obfsck::ObfuscationLevel;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::HashMap;

// --- Inline copy of the config types (mirrors redact.rs) ---

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

fn apply_yaml_patterns(yaml: &str, input: &str, level: ObfuscationLevel) -> String {
    let config: SecretsConfig = serde_yaml::from_str(yaml).unwrap();
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

    let mut text = input.to_string();
    for (re, replacement) in &patterns {
        text = re.replace_all(&text, replacement.as_str()).into_owned();
    }
    text
}

// --- Tests ---

#[test]
fn test_anthropic_key_redacted() {
    let yaml = include_str!("../config/secrets.yaml");
    // 40-char suffix ensures it satisfies {32,}
    let input = "key=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(result.contains("[REDACTED-ANTHROPIC-KEY]"), "got: {result}");
    assert!(!result.contains("sk-ant"), "key leaked: {result}");
}

#[test]
fn test_openai_key_redacted() {
    let yaml = include_str!("../config/secrets.yaml");
    let input = "OPENAI_API_KEY=sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(result.contains("[REDACTED-OPENAI-KEY]"), "got: {result}");
    assert!(!result.contains("sk-proj"), "key leaked: {result}");
}

#[test]
fn test_pii_disabled_by_default() {
    let yaml = include_str!("../config/secrets.yaml");
    let input = "ssn=123-45-6789 card=4111111111111111";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    // pii group is enabled: false — values must pass through
    assert!(result.contains("123-45-6789"), "SSN should not be redacted (pii off): {result}");
    assert!(result.contains("4111111111111111"), "CC should not be redacted (pii off): {result}");
}

#[test]
fn test_paranoid_only_not_applied_at_minimal() {
    let yaml = include_str!("../config/secrets.yaml");
    // 40-char hex — matches aws_secret_key paranoid pattern
    let input = "val=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(result.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "paranoid pattern should not fire at minimal: {result}");
}

#[test]
fn test_paranoid_only_applied_at_paranoid_level() {
    let yaml = include_str!("../config/secrets.yaml");
    // 40-char hex — matches aws_secret_key paranoid pattern
    let input = "val=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Paranoid);
    assert!(!result.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "paranoid pattern should fire at paranoid level: {result}");
}

#[test]
fn test_custom_patterns_applied() {
    let yaml = r#"
groups: {}
custom:
  - name: internal_token
    pattern: '\bMYCO-[A-Za-z0-9]{16}\b'
    label: INTERNAL-TOKEN
    paranoid_only: false
"#;
    let input = "token=MYCO-abcd1234efgh5678";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(result.contains("[REDACTED-INTERNAL-TOKEN]"), "got: {result}");
}

#[test]
fn test_disabled_group_not_applied() {
    let yaml = r#"
groups:
  ai_apis:
    enabled: false
    patterns:
      - name: openai_api_key
        pattern: '\bsk-[A-Za-z0-9_-]{32,}\b'
        label: OPENAI-KEY
        paranoid_only: false
custom: []
"#;
    let input = "key=sk-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let result = apply_yaml_patterns(yaml, input, ObfuscationLevel::Minimal);
    assert!(!result.contains("[REDACTED-OPENAI-KEY]"),
        "disabled group was applied: {result}");
}
```

- [ ] **Step 3: Run tests to verify they fail (expected — binary not updated yet)**

```bash
cargo test --test redact_yaml 2>&1 | tail -10
```

Expected: compile errors or test failures.

- [ ] **Step 4: Rewrite `src/bin/redact.rs`**

```rust
use clap::Parser;
use obfsck::{ObfuscationLevel, obfuscate_text};
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::collections::HashMap;
use std::io::{self, Read};

// include_str! path is relative to this source file (src/bin/).
// Two levels up reaches the crate root, then into config/.
static BUNDLED_CONFIG: &str = include_str!("../../config/secrets.yaml");

#[derive(Parser)]
#[command(about = "Redact secrets and PII from stdin")]
struct Args {
    /// Obfuscation level: minimal, standard, paranoid
    #[arg(short, long, default_value = "minimal")]
    level: String,

    /// Path to secrets YAML config.
    /// Default lookup order: ~/.config/obfsck/secrets.yaml, then bundled config.
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
    // obfuscate_text also runs secrets.rs patterns internally — those may double-fire
    // on any pattern present in both files, but are harmless since [REDACTED-X] tokens
    // won't match secret regexes.
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
        // Only use user config if it has non-empty groups or custom entries
        let trimmed = content.trim();
        if !trimmed.is_empty() && trimmed != "groups: {}\ncustom: []" {
            return content;
        }
    }

    BUNDLED_CONFIG.to_string()
}
```

- [ ] **Step 5: Run tests — verify they all pass**

```bash
cargo test --test redact_yaml 2>&1
```

Expected: 7 tests, all pass.

- [ ] **Step 6: Smoke test the binary**

```bash
cargo build --release --bin redact

# Secret redaction
echo "key=sk-ant-api03-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | ./target/release/redact
# Expected: key=[REDACTED-ANTHROPIC-KEY]

# PII disabled by default
echo "ssn=123-45-6789" | ./target/release/redact
# Expected: ssn=123-45-6789

# Paranoid level catches broad patterns
echo "val=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" | ./target/release/redact --level paranoid
# Expected: val=[REDACTED-AWS-SECRET] (or similar)
```

- [ ] **Step 7: Install and commit**

```bash
cp target/release/redact ~/.local/bin/redact

git add Cargo.toml src/bin/redact.rs tests/redact_yaml.rs
git commit -m "feat: redact binary loads patterns from YAML config with group enable/disable"
```

---

## Notes

- **PII group** (`pii`) is `enabled: false` by default — intentional. High false-positive rate in log data (phone patterns especially). For the PM: share this group and note the tradeoff. Users opt in by creating `~/.config/obfsck/secrets.yaml` and setting `enabled: true`.
- **`pagerduty_api_key`** moved from non-paranoid to the `paranoid` group — the 20-char base64 pattern has near-certain false positives in normal text.
- **User config fallback:** If `~/.config/obfsck/secrets.yaml` exists but is effectively empty (just the scaffold), `load_config` falls back to the bundled config. This prevents the scaffold from silently disabling all patterns.
- **`secrets.rs` still exists** and is still used internally by `obfuscate_text`. The double-application of some patterns is harmless. Deleting `secrets.rs` and wiring `obfuscate_text` to use YAML is a future concern.
