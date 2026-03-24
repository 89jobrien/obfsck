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
- `--level` defaults to `standard`
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
    10_pii.yaml                 # SSN, credit card, phone — note: group disabled by default
    11_structural.yaml          # IPs, emails, containers, users, hostnames, paths
    12_log_block.yaml           # Realistic multi-line log with mixed secrets
```

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
- kv examples grouped into a single `Table` per group file
- block examples rendered as individual `Panel` pairs below the table

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

The script shells out to `target/release/redact`:

```python
import subprocess

def redact(text: str, level: str) -> str:
    result = subprocess.run(
        ["target/release/redact", "--level", level],
        input=text,
        capture_output=True,
        text=True,
    )
    return result.stdout
```

The binary is expected at `target/release/redact` relative to the repo root. The script resolves this relative to its own location (`demo/../target/release/redact`).

## Obfuscation Level Coverage

`00_levels.yaml` shows the same realistic log input processed at all three levels, with a brief explanation of what each level covers:

- **minimal** — secrets patterns only (YAML config groups)
- **standard** — + IPs, emails, containers, users
- **paranoid** — + paths, hostnames, high-entropy strings

## Notes

- `10_pii.yaml` includes a note that the `pii` group is disabled by default in `config/secrets.yaml` and must be enabled manually
- `00_levels.yaml` uses `standard` level but overrides per-example to show all three
- Long values in kv table cells are truncated with `…` to fit terminal width
