# Visual Demo Design — obfsck

**Date:** 2026-03-23
**Status:** Draft

## Overview

A data-driven Python demo script that showcases every redaction feature of the `obfsck` redact binary using `rich` for terminal formatting. Runs as a static showcase by default; accepts a positional file argument to pipe real data through the tool.

## CLI

```
uv run demo/demo.py [FILE] [--level minimal|standard|paranoid]
```

- No `FILE` → runs full showcase (all example groups, in order)
- `FILE` → skips showcase; pipes file through `target/release/redact` at the given level and shows before/after
- `--level` defaults to `standard` — intentionally richer than the binary's own default (`minimal`) so the showcase is more illustrative out of the box
- Designed to be safe in a for-loop: `for f in logs/*.log; do uv run demo/demo.py $f; done`
- In file mode: no banner, clean output per invocation

## File Structure

```
demo/
  demo.py                      # PEP 723 inline-metadata script (uv run)
  examples/
    00_levels.yaml              # Same input at minimal / standard / paranoid
    01_ai_apis.yaml
    02_cloud.yaml
    03_version_control.yaml
    04_communication.yaml
    05_payments.yaml
    06_databases.yaml
    07_package_managers.yaml
    08_monitoring.yaml
    09_generic.yaml             # JWT, private keys, bearer tokens, passwords
    10_paranoid_patterns.yaml   # paranoid_only: true patterns from config/secrets.yaml
    11_pii.yaml                 # SSN, credit card, phone — note: group disabled by default
    12_structural.yaml          # IPs, emails, containers, users, hostnames, paths
    13_log_block.yaml           # Realistic multi-line log with mixed secrets
```

Note: there are two distinct uses of "paranoid" in this codebase:
- `paranoid_only: true` in `config/secrets.yaml` — pattern-matched secrets gated behind `--level paranoid` (e.g. AWS secret key, Datadog API key, base64 blobs). Covered in `10_paranoid_patterns.yaml`.
- `ObfuscationLevel::Paranoid` structural features — paths, hostnames, high-entropy strings. Covered in `12_structural.yaml` with per-example level overrides.

## PEP 723 Header

```python
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "rich",
# ]
# ///
```

No `pyproject.toml` needed. `uv run demo/demo.py` handles dependency installation automatically.

## Example Fixture Format

```yaml
title: "AI APIs"
description: "API keys for AI services — matched at all levels"
level: minimal          # redact level for all examples in this file
disabled: false         # optional; true = group off by default, show notice (default: false)
examples:
  - label: "Anthropic key"
    type: kv            # single-line → side-by-side table row
    input: "ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxx"

  - label: "Mixed log block"
    type: block         # multi-line → sequential before/after panels
    input: |
      2024-01-15 INFO  server starting
      ANTHROPIC_API_KEY=sk-ant-api03-xxxxxxxxxxx
      OpenAI key: sk-proj-yyyyyyyyyyyyyyyyyy

  - label: "Paranoid-only example"
    type: kv
    level: paranoid     # per-example level override
    input: "token=base64encodedvalue..."
```

- `type: kv` — rendered as a row in a two-column rich Table (Original | Redacted)
- `type: block` — rendered as two stacked rich Panels (Input / Redacted)
- `level` can be set at file scope or overridden per example
- If a file has only `kv` examples, the block section is omitted entirely (no empty panels)
- If a file has only `block` examples, the kv table is omitted entirely (no empty table)

## Rich Rendering Layout

### Showcase mode

```
━━━━━━━━━━━━━━━━━━ obfsck demo ━━━━━━━━━━━━━━━━━━
  Redact secrets & PII before LLM analysis

╔═ AI APIs — API keys for AI services ════════════╗

  ┌──────────────────────────┬──────────────────────┐
  │ Original                 │ Redacted             │
  ├──────────────────────────┼──────────────────────┤
  │ ANTHROPIC_API_KEY=sk-ant…│ ANTHROPIC_API_KEY=[R…│
  └──────────────────────────┴──────────────────────┘

  ┌─ Input ──────────────────────────────────────────┐
  │ 2024-01-15 INFO  server starting                 │
  │ ANTHROPIC_API_KEY=sk-ant-api03-xxx               │
  └──────────────────────────────────────────────────┘
  ┌─ Redacted ───────────────────────────────────────┐
  │ 2024-01-15 INFO  server starting                 │
  │ ANTHROPIC_API_KEY=[REDACTED-ANTHROPIC-KEY]       │
  └──────────────────────────────────────────────────┘
```

- `[REDACTED-*]` tokens rendered in **bold red** in all views
- Each group rendered as a rich `Panel` with title + description as subtitle
- kv examples grouped into a single `Table` per group file, rendered before block examples
- kv table uses two equal-width flexible columns; each cell truncated with `…` if it exceeds its column width. Rich handles responsive resizing — no fixed widths.
- block examples rendered as individual `Panel` pairs (Input / Redacted) below the table

### Disabled-group notice (pii group)

When a fixture file sets `disabled: true` at the file scope, the demo renders the examples but adds a caption beneath the panel:

```
  ⚠  This group is disabled by default. Enable it in config/secrets.yaml under groups.pii.
```

This makes clear that identical before/after output is expected behaviour, not a bug.

### File mode

```
━━━━ demo.log  (level: standard) ━━━━

┌─ Input ──────────┐
│ ...              │
└──────────────────┘
┌─ Redacted ───────┐
│ ...              │
└──────────────────┘
```

No banner. One rule showing filename and level, then the panels.

## Redact Invocation

The script resolves the binary path relative to its own location (`demo/../target/release/redact`). If the binary does not exist, it prints a human-readable error and exits with code 1:

```
Error: binary not found at target/release/redact
Run `cargo build --release` first.
```

Subprocess call:

```python
import subprocess
from pathlib import Path
import sys

BINARY = Path(__file__).parent.parent / "target" / "release" / "redact"

def redact(text: str, level: str) -> str:
    if not BINARY.exists():
        print(f"Error: binary not found at {BINARY}\nRun `cargo build --release` first.", file=sys.stderr)
        sys.exit(1)
    result = subprocess.run(
        [str(BINARY), "--level", level],
        input=text,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Error: redact exited with code {result.returncode}\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    return result.stdout
```

## Obfuscation Level Coverage

### `00_levels.yaml` — three-level comparison

Shows the same realistic log line processed at all three levels. Rendered as three consecutive `kv` rows with per-example level overrides, grouped under a single explanatory Panel:

```yaml
title: "Obfuscation Levels"
description: "Same input at each level — showing what each adds"
examples:
  - label: "minimal  (secrets only)"
    type: kv
    level: minimal
    input: "user=alice ip=10.0.0.5 token=sk-ant-api03-xxx"

  - label: "standard (+IPs, emails, containers, users)"
    type: kv
    level: standard
    input: "user=alice ip=10.0.0.5 token=sk-ant-api03-xxx"

  - label: "paranoid (+paths, hostnames, high-entropy)"
    type: kv
    level: paranoid
    input: "user=alice ip=10.0.0.5 token=sk-ant-api03-xxx"
```

Level summary printed as a legend above the table:
- **minimal** — secrets patterns only (YAML config groups)
- **standard** — + IPs, emails, containers, users
- **paranoid** — + paths, hostnames, high-entropy strings; also unlocks `paranoid_only: true` patterns

### `10_paranoid_patterns.yaml` — paranoid-only secret patterns

All examples use `level: paranoid`. Covers all patterns across all **enabled** groups in `config/secrets.yaml` where `paranoid_only: true`, except those already in `11_pii.yaml` (passport, drivers_license_us). This spans multiple groups — for example, `telegram_bot_token` lives in the `communication` group and `ssh_public_key` in the `generic` group, but both are included here because they carry `paranoid_only: true`.

### `12_structural.yaml` — structural obfuscation features

All structural features require `standard` or higher; `minimal` activates no structural features. Uses per-example level overrides to demonstrate the level at which each feature activates:

- IPs (internal/external), emails, containers, users → `level: standard`
- Paths, hostnames, high-entropy strings → `level: paranoid`

### `11_pii.yaml` — PII patterns (disabled by default)

Sets `disabled: true` at file scope. Examples show SSN, credit card, phone, IBAN, passport, driver's license inputs. Output will be unredacted (pass-through) unless the user enables the group. The disabled-group notice is shown beneath the panel.

The `disabled: true` field is fixture-static and reflects the default config state. The demo does not inspect the live `config/secrets.yaml` at runtime — so if a user has enabled the `pii` group locally, the notice still appears. This is acceptable for a demo tool.
