# obfsck

## What it does

- Replaces secrets with labeled tokens (for example `[REDACTED-AWS-KEY]`)
- Obfuscates identifiers with stable mappings (same input => same token)
- Supports privacy levels based on how aggressive redaction should be

## Obfuscation levels

- `Minimal`: secret pattern redaction only
- `Standard`: adds IP, email, container ID, and user obfuscation
- `Paranoid`: adds path, hostname, and high-entropy token redaction

Path obfuscation supports Unix, Windows drive paths, and UNC paths. Sensitive system paths are preserved.

Preserved path segments include common roots like `home`, `usr`, `etc`, `windows`, `users`, and `programdata`.

## Run locally with `cargo` or use the `mise.toml`:

```bash
# check / build / test
mise run check
mise run build
mise run test

# formatting
mise run format
mise run format-check

# linting
mise run lint

# auto-fix clippy suggestions
mise run fix

# local CI bundle
mise run ci
```


## Examples

### Obfuscation alert

- Processed 250 records
- Max tokens in a single record: ips=2 users=1 emails=1

```text
Sample before: event_id=evt-0000 user=user0 src=10.1.1.1 dst=198.51.100.10 email=user0@corp.example host=service0.corp.example path=/var/lib/app0/env0.json

Sample after : event_id=evt-0000 user=[USER-1] src=[IP-INTERNAL-1] dst=[IP-EXTERNAL-1] email=[EMAIL-1] host=[HOST-1] path=/var/lib/app0/[FILE].json

```

```text
Obfuscated output: Some("incident=AUTH-48291 severity=high | actor=bob src=[IP-EXTERNAL-1] dst=[IP-INTERNAL-1] | email=[EMAIL-1] host=[HOST-1] | path=/home/bob/.aws/credentials | token=[REDACTED-GITHUB-TOKEN]")
Obfuscated fields keys: ["file_path", "workstation", "dst_ip", "notes", "jump_host", "src_ip", "contact", "host", "actor", "command"]
Token counts => ips: 3, users: 0, emails: 1, hosts: 4, containers: 0, secrets: 1
```

### Larger payloads

- Token totals => ips: 500, users: 120, emails: 120, hostnames: 15, secrets: 700

```
--- output preview ---
ts=2026-02-25T18:00:00Z level=info user=[USER-1] src=[IP-INTERNAL-1] dst=[IP-EXTERNAL-1] email=[EMAIL-1] host=[HOST-1] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
ts=2026-02-25T18:01:00Z level=info user=[USER-2] src=[IP-INTERNAL-2] dst=[IP-EXTERNAL-2] email=[EMAIL-2] host=[HOST-2] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
ts=2026-02-25T18:02:00Z level=info user=[USER-3] src=[IP-INTERNAL-3] dst=[IP-EXTERNAL-3] email=[EMAIL-3] host=[HOST-3] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
ts=2026-02-25T18:03:00Z level=info user=[USER-4] src=[IP-INTERNAL-4] dst=[IP-EXTERNAL-4] email=[EMAIL-4] host=[HOST-4] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
ts=2026-02-25T18:04:00Z level=info user=[USER-5] src=[IP-INTERNAL-5] dst=[IP-EXTERNAL-5] email=[EMAIL-5] host=[HOST-5] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
ts=2026-02-25T18:05:00Z level=info user=[USER-6] src=[IP-INTERNAL-6] dst=[IP-EXTERNAL-6] email=[EMAIL-6] host=[HOST-6] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
ts=2026-02-25T18:06:00Z level=info user=[USER-7] src=[IP-INTERNAL-7] dst=[IP-EXTERNAL-7] email=[EMAIL-7] host=[HOST-7] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
ts=2026-02-25T18:07:00Z level=info user=[USER-8] src=[IP-INTERNAL-8] dst=[IP-EXTERNAL-8] email=[EMAIL-8] host=[HOST-8] path=/home[REDACTED-PAGERDUTY-KEY]/[FILE].log secret=[REDACTED-AWS-KEY]
```

- Mappings => ips: 160, users: 80, emails: 80, hostnames: 7, secrets: 80

```text
--- output preview ---
ts=2026-02-25T17:00:00Z level=warn user=[USER-1] src=[IP-INTERNAL-1] dst=[IP-EXTERNAL-1] email=[EMAIL-1] host=[HOST-1] path=/[REDACTED-PAGERDUTY-KEY]payment/[FILE].yaml
ts=2026-02-25T17:01:00Z level=warn user=[USER-2] src=[IP-INTERNAL-2] dst=[IP-EXTERNAL-2] email=[EMAIL-2] host=[HOST-2] path=/[REDACTED-PAGERDUTY-KEY]payment/[FILE].yaml
ts=2026-02-25T17:02:00Z level=warn user=[USER-3] src=[IP-INTERNAL-3] dst=[IP-EXTERNAL-3] email=[EMAIL-3] host=[HOST-3] path=/[REDACTED-PAGERDUTY-KEY]payment/[FILE].yaml
ts=2026-02-25T17:03:00Z level=warn user=[USER-4] src=[IP-INTERNAL-4] dst=[IP-EXTERNAL-4] email=[EMAIL-4] host=[HOST-4] path=/[REDACTED-PAGERDUTY-KEY]payment/[FILE].yaml
ts=2026-02-25T17:04:00Z level=warn user=[USER-5] src=[IP-INTERNAL-5] dst=[IP-EXTERNAL-5] email=[EMAIL-5] host=[HOST-5] path=/[REDACTED-PAGERDUTY-KEY]payment/[FILE].yaml
```

## Benchmarks

Run benchmarks with Criterion:

```bash
cargo bench
```

## Public API

- `obfuscate_text(text, level) -> (String, ObfuscationMapExport)`
- `obfuscate_alert(output, output_fields, level) -> (Option<String>, Option<HashMap<String, String>>, ObfuscationMapExport)`
- `ObfuscationLevel::parse("minimal|standard|paranoid")`

`ObfuscationMapExport` includes generated mappings for IPs, hostnames, users, containers, paths, emails, plus `secrets_count`.

### Alert Analyzer (Rust)

This crate now includes a Rust alert analyzer under the `src/analyzer/` module with a CLI binary:

```bash
cargo run --bin analyzer -- --last 1h --limit 5 --dry-run
```

Common options:

```text
--config <path>
--priority <Critical|Error|Warning|Notice>
--last <15m|1h|7d>
--limit <n>
--dry-run
--store
--json
--backend <loki|vm|victorialogs>
--loki-url <url>
--victorialogs-url <url>
```
