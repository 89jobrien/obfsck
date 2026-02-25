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

Example (Windows paths):

```text
Input:  C:\Users\alice\notes.txt \\server\share\docs\config.yml
Output: C:\Users\alice\[FILE].txt \\server\share\docs\[FILE].yml
```

Example (Unix paths):

```text
Input:  /home/alice/notes.txt /opt/app/config.yml
Output: /home/alice/[FILE].txt /opt/app/[FILE].yml
```

## Public API

- `obfuscate_text(text, level) -> (String, ObfuscationMapExport)`
- `obfuscate_alert(output, output_fields, level) -> (Option<String>, Option<HashMap<String, String>>, ObfuscationMapExport)`
- `ObfuscationLevel::parse("minimal|standard|paranoid")`

`ObfuscationMapExport` includes generated mappings for IPs, hostnames, users, containers, paths, emails, plus `secrets_count`.

## Run locally with `cargo` or

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
