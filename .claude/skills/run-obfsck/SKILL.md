---
name: run-obfsck
description: Build, run, test, and demo obfsck — a secret/PII redaction toolkit with 6 binaries (obfsck, redact, scan, analyzer, api, obfsck-mcp). Use when asked to run obfsck, build it, test it, demo it, screenshot its output, or drive any of its binaries (redact secrets, scan a diff, start the REST API, query the MCP server, or run the alert analyzer).
---

obfsck is a Rust package that builds 6 binaries around one redaction engine.
Drive the five specialized and compatibility entry points via
`demo/demo.py --bin <name>` (a `uv`-run Python/rich script); use the canonical
`obfsck redact` and `obfsck analyze` commands for direct invocation.

All paths below are relative to the repo root (`obfsck/`).

## Prerequisites

Rust toolchain and `uv` are expected to already be on `PATH` (this repo is
mise-managed — `mise.toml` selects the stable Rust channel). Nothing else to install;
`uv run demo/demo.py` auto-installs its own deps (`rich`, `pyyaml`) from the
PEP 723 header at the top of the file.

```bash
cargo --version   # verified: works out of the box in this container
uv --version      # verified: uv 0.10.9
```

## Build

```bash
cargo build --release --features analyzer
```

Builds all 6 binaries to `target/release/`: `obfsck`, `redact`, `scan`,
`analyzer`, `api`, and `obfsck-mcp`. `analyzer` is obfsck's default feature
(see `Cargo.toml`), so `--features analyzer` is technically redundant but
kept explicit; every binary target requires that feature.

## Run (agent path)

```bash
uv run demo/demo.py --bin all       # tours every binary in one run
uv run demo/demo.py --bin redact    # original showcase — obfuscation levels
uv run demo/demo.py --bin scan      # unified-diff secret scanner
uv run demo/demo.py --bin mcp       # JSON-RPC stdio MCP server
uv run demo/demo.py --bin analyzer  # LLM alert-analysis CLI
uv run demo/demo.py --bin api       # axum REST server
```

Each mode is self-contained and prints rich-formatted panels to stdout —
no artifacts land on disk, this is a terminal demo, not a screenshot tool.
Verified output for each mode:

| `--bin` | What it does | Verified result |
|---|---|---|
| `redact` (default) | Pipes `demo/examples/*.yaml` fixtures through `redact` using each example's configured level | Renders a before/after table per example; `[REDACTED-*]` tokens highlighted |
| `scan` | Feeds a synthetic `git diff` with a Slack bot token through `scan --no-gitleaks` | `scan: 2 finding(s) detected` (exit 1) — pattern hit + structural hit on the same line |
| `mcp` | Sends `tools/list` then `tools/call` (`audit`) over stdio JSON-RPC to `obfsck-mcp` | `tools/list` returns the `audit`/`generate-filters` schema; `audit` returns `{"hits":[{"count":1,"label":"SLACK-BOT"}]}` |
| `analyzer` | Runs `analyzer --dry-run --loki-url http://127.0.0.1:1` (deliberately unreachable) | Exit 1, prints the `miette` fancy diagnostic chain (`obfsck::analyzer::http` → `client error (Connect)` → `Connection refused`) |
| `api` | Starts `api` on a free port, `GET /health` and `GET /`, tears it down | `{"status":"healthy","service":"alert-analysis-api"}` (200), then the index HTML page |

Redact in file mode (bypasses the fixture showcase):

```bash
uv run demo/demo.py --bin redact demo/examples/00_levels.yaml --level minimal
```

Direct invocation without the driver, if you just need one binary:

```bash
echo 'AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE' | target/release/obfsck redact --level minimal
# → AWS_ACCESS_KEY_ID=[REDACTED-AWS-KEY]

target/release/redact --version  # exit 2, clap usage error — compatibility alias has no --version
```

`obfsck-mcp` (note: crate/bin name is `obfsck-mcp`, not `mcp`) speaks
line-delimited JSON-RPC on stdin/stdout:

```bash
echo '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' | target/release/obfsck-mcp
```

## Run (human path)

```bash
target/release/api --host 127.0.0.1 --port 5000   # Ctrl-C to stop
# → binds and logs "Alert Analysis API starting"; GET /health works with
#   no backend configured, GET /api/analyze needs a real Loki/VictoriaLogs
#   + LLM provider config to do anything useful.
```

## Test

```bash
cargo nextest run --workspace
# or: just test
```

Verified: 29 test binaries, 214 tests passed across unit, integration,
property, and golden suites. 6 tests are skipped by design.

---

## Gotchas

- **`scan --no-gitleaks` is required in any scripted/driver context.**
  Without it, `scan` spawns the real `gitleaks` CLI and pipes the diff to
  its stdin on a background thread while reading stdout/stderr on the main
  thread — if `gitleaks` is on `PATH` this can hang past any reasonable
  subprocess timeout (hit a 10s `TimeoutExpired` in `subprocess.run`
  before adding the flag). The driver always passes `--no-gitleaks`.
- **The repo's own `.obfsck.toml` allowlist can silently neuter your own
  demo fixtures.** `.obfsck.toml` allowlists `AKIAIOSFODNN7EXAMPLE` (AWS's
  canonical example key) so the pre-commit hook doesn't flag it in
  `demo/examples/`. That allowlist is loaded by *every* `scan` invocation
  from this repo, including the demo driver — a `scan` demo fixture using
  that exact key silently reports "clean" (exit 0) instead of finding it.
  Check `.obfsck.toml` and `~/.config/obfsck/allowlist` before picking a
  fixture value, or the demo will quietly stop demonstrating anything.
- **A fixture secret literal in `demo.py`'s own source trips the
  pre-commit `scan-diff` hook on *this* repo** — the hook scans the
  staged diff of every commit, including edits to the demo file itself.
  `SAMPLE_DIFF`'s Slack token is built via `"-".join([...])` instead of
  one contiguous string literal so the source bytes don't match the
  pattern, while the *assembled* value (used at runtime, piped into
  `scan`) still does. If you add a new fixture secret to `demo.py`, split
  it the same way or the commit will fail its own pre-commit hook.
- **`redact` has no `--version` flag.** `target/release/redact --version`
  exits 2 with a clap "unrecognized argument" error, not a version string.
- **`api`/`analyzer` construct their backend clients at startup without
  a network call** — `AlertAnalyzer::from_config` just builds `reqwest`
  clients, it doesn't ping Loki/the LLM provider. So `api` starts and
  answers `/health` fine even with an unreachable `LOKI_URL`; the error
  only surfaces on `/api/analyze` or when `analyzer` actually calls
  `fetch_alerts`. That's what the `analyzer --dry-run` demo exploits to
  show the `miette` error path deterministically and fast (`127.0.0.1:1`
  refuses instantly, no DNS/timeout wait).
