# obfsck

Redacts secrets and PII from log lines and structured text.

## Install

```bash
cargo install --path .
```

## What it does

- Replaces secrets with labeled tokens (for example `[REDACTED-AWS-KEY]`)
- Obfuscates identifiers with stable mappings (same input => same token)
- Supports privacy levels based on how aggressive redaction should be

## Obfuscation levels

- `Minimal`: secret pattern redaction only
- `Standard`: adds IP, email, container ID, user, and PII obfuscation
- `Paranoid`: adds path, hostname, and high-entropy token redaction

Path obfuscation supports Unix, Windows drive paths, and UNC paths.
Sensitive system paths are preserved.

Preserved path segments include common roots like `home`, `usr`, `etc`,
`windows`, `users`, and `programdata`.

### What each level redacts

| Pattern category | minimal | standard | paranoid |
|-----------------|---------|----------|----------|
| API keys, tokens, passwords | yes | yes | yes |
| IPs, emails, container IDs, usernames | — | yes | yes |
| PII (names, SSN, phone, credit card) | — | yes | yes |
| Paths, hostnames, high-entropy strings | — | — | yes |
| Paranoid-only PII (IBAN, passport, DL) | — | — | yes |

`standard` is the privacy-forward default for sharing logs externally.
`minimal` is safe for internal tooling where structural identifiers are useful.

## redact CLI

Redact secrets and PII from a file or stdin.

```bash
# Stdin -> stdout (default level: minimal — secrets only)
echo "key=sk-ant-api03-ABCDEF..." | redact

# File input
redact path/to/logfile.txt

# Write to output file
redact input.txt --output redacted.txt

# Increase level
redact input.txt --level standard   # + IPs, emails, usernames, PII
redact input.txt --level paranoid   # + paths, hostnames, high-entropy

# Audit mode — report findings to stderr without redacting
redact input.txt --audit

# Custom secrets config (overrides bundled config)
redact input.txt --config ~/.config/obfsck/secrets.yaml
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--level <minimal\|standard\|paranoid>` | `minimal` | Obfuscation level |
| `--output <file>` / `-o` | stdout | Write redacted output to file |
| `--config <path>` / `-c` | bundled | Path to secrets YAML config |
| `--audit` | off | Report findings to stderr without redacting |
| `--pii-off` | off | Suppress PII patterns at standard+ levels |

## scan CLI (pre-commit)

Scans a unified diff for secrets using both obfsck patterns and gitleaks.

```bash
# Pipe a diff
git diff --staged | scan

# Or let scan capture the staged diff itself
scan --staged

# Skip gitleaks (obfsck patterns only)
scan --staged --no-gitleaks

# Set obfuscation level
scan --staged --level standard
```

### Pre-commit hook

Add to `.githooks/pre-commit` or your global hooks:

```bash
#!/bin/sh
git diff --staged | scan --level minimal
```

Or use `--staged` mode:

```bash
#!/bin/sh
scan --staged --level minimal
```

The allowlist at `~/.config/obfsck/allowlist` (one entry per line)
skips known false positives like test fixtures.

## obfsck-mcp (MCP server)

JSON-RPC server exposing two tools for IDE and agent integration:

- `audit` — scan text for secret patterns, returns labeled findings
- `generate-filters` — suggest log filter patterns from secret examples

```bash
# Build and install
cargo build --bin obfsck-mcp
cp target/release/obfsck-mcp ~/.local/bin/

# The server reads JSON-RPC from stdin and writes to stdout
```

## Alert Analyzer

Fetches alerts from Loki or VictoriaLogs, obfuscates them, and sends
to an LLM for analysis. Behind the `analyzer` feature flag.

```bash
cargo run --bin analyzer -- --last 1h --limit 5 --dry-run
```

Common options:

```text
-c, --config <path>            Configuration file path
-p, --priority <priority>      Filter by priority
-l, --last <duration>          Time range to query [default: 1h]
-n, --limit <n>                Maximum number of alerts [default: 5]
-d, --dry-run                  Skip LLM analysis, show obfuscated prompt
-b, --backend <backend>        Log backend (loki|vm|victorialogs)
```

## Custom config

The bundled `config/secrets.yaml` covers common secret patterns grouped
by category (`ai_apis`, `cloud`, `pii`, `paranoid`, etc.). Each group
supports:

```yaml
groups:
  my_group:
    enabled: true
    min_level: standard   # omit to apply at all levels
    patterns:
      - name: my_token
        pattern: '\bTOK_[A-Za-z0-9]{32}\b'
        label: MY-TOKEN
        paranoid_only: false  # true = only fires at paranoid
```

Lookup order: `--config` flag -> `~/.config/obfsck/secrets.yaml` ->
bundled config.

## Public API

```rust
use obfsck::{obfuscate_text, ObfuscationLevel, Obfuscator};

// One-shot function
let (redacted, map) = obfuscate_text(text, ObfuscationLevel::Standard);

// Stateful obfuscator with allowlist
let mut obfuscator = Obfuscator::new(ObfuscationLevel::Standard)
    .with_allowlist(vec!["10.0.0.1".into()]);
let redacted = obfuscator.obfuscate(text);
```

Exports:

- `obfuscate_text(text, level) -> (String, ObfuscationMapExport)`
- `obfuscate_alert(output, fields, level) -> (Option<String>,
  Option<HashMap<String, String>>, ObfuscationMapExport)`
- `Obfuscator::new(level)` — stateful, supports `.with_allowlist()`
- `ObfuscationLevel::parse("minimal|standard|paranoid")`

## Development

```bash
# check / build / test / lint / CI gate
just ci               # or: mise run ci

# individual steps
cargo check
cargo test
cargo clippy --all-targets -- -D warnings
cargo bench            # criterion benchmarks

# formatting
cargo fmt --all
```

## Example output

```text
Before: event_id=evt-001 user=alice src=10.1.1.5 dst=198.51.100.10
        email=alice@corp.example path=/var/lib/app/env.json

After:  event_id=evt-001 user=[USER-1] src=[IP-INTERNAL-1]
        dst=[IP-EXTERNAL-1] email=[EMAIL-1] path=/var/lib/app/[FILE].json
```
