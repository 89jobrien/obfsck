# obfsck

Rust crate for obfuscating/redacting sensitive data in log text before LLM analysis.

## Commands

```bash
mise run check          # cargo check
mise run build          # cargo build
mise run test           # cargo test
mise run lint           # clippy -D warnings
mise run fix            # cargo clippy --fix
mise run ci             # lint + test + build
mise run format         # cargo fmt --all
mise run format-check   # fmt check only
cargo bench             # criterion benchmarks
```

## Architecture

- `src/lib.rs` — public API: redaction functions, `Obfuscator`, and pattern types
- `src/patterns/mod.rs` — `Pattern`, `PatternSet`, and pattern diagnostics
- `config/secrets.yaml` — authoritative bundled secret definitions compiled by `build.rs`
- `src/cli.rs` — canonical `obfsck redact` / `obfsck analyze` routing
- `src/helpers.rs` — path/entropy utilities
- `src/analyzer/` — alert fetching + LLM analysis (behind `analyzer` feature)
- `src/api/` — axum REST server (behind `analyzer` feature)
- `src/clients/` — Loki / VictoriaLogs backends (behind `analyzer` feature)
- `src/schema.rs` — BAML schema for structured LLM output
- `src/bin/obfsck.rs` — canonical CLI entry point
- `src/bin/redact.rs` — deprecated redaction compatibility alias
- `src/bin/analyzer.rs` — deprecated analyzer compatibility alias
- `src/bin/scan.rs` — unified-diff secret scanner
- `src/bin/api.rs` — HTTP API server
- `src/bin/mcp.rs` — MCP JSON-RPC server (`obfsck-mcp`)

## Features

- `analyzer` (default) — enables all binaries and the axum server
- `legacy-user-scan` — alternate user scanning heuristic
- `path-policy-home-user-redact` — redact home-dir user segments
- `path-policy-non-allowlisted-redact` — redact all non-allowlisted path segments

**Gotcha:** `path-policy-home-user-redact` and `path-policy-non-allowlisted-redact` are
mutually exclusive — enabling both is a compile error.

## Environment Variables

Copy `.envrc.example` → `.envrc`. Key vars:

```
RUST_LOG=obfsck=info,tower_http=debug   # log level
LOG_FORMAT=pretty|json                  # pretty for dev, json for prod sim
LOG_DIR=~/logs/obfsck                   # enable file logging
ANTHROPIC_API_KEY=...                   # required for analyzer LLM calls
LOKI_URL=http://localhost:3100          # log backend
VICTORIALOGS_URL=http://localhost:9428  # alternate backend
```

## Running Binaries

```bash
cargo run --bin obfsck -- redact --level standard < input.txt
obfsck redact input.txt                    # installed canonical binary
obfsck redact input.txt -o redacted.txt    # file → file
cat input.txt | obfsck redact              # stdin → stdout
cargo run --bin obfsck -- analyze --last 1h --limit 5 --dry-run
mise run logs           # API server with pretty logs
mise run baml:dry-run   # Analyzer without LLM calls (inspect prompt)
```

## Pattern Sources — Critical Dual-Location Gotcha

Secret patterns live in **one place**: `config/secrets.yaml`. `build.rs` generates Rust into
Cargo's `OUT_DIR` and `src/lib.rs` includes it at compile time — do not edit generated output.

`~/.config/obfsck/secrets.yaml` replaces the YAML selected for the CLI pattern pass, but
`Obfuscator` currently applies compiled bundled definitions afterward. Custom config therefore
does not disable bundled library patterns until the shared pattern-engine migration is complete.

## Issue Tracking

Work items are tracked in `.ctx/HANDOFF.obfsck.obfsck.yaml` and
`.ctx/godmode/tasks.yaml`. Check dependency fields before starting chained work.

## Pre-commit Hook

The global git hook scans a filtered staged diff with `obfsck-scan` when available; its fallbacks
extract added lines and use `obfsck redact --level minimal`, then the deprecated `redact` binary.
Fake test tokens (e.g. `ghp_aaa...`) trigger it — add them to
`~/.config/obfsck/allowlist` (one per line).

## Pattern Sources — Audit Pass

`SECRET_PATTERN_DEFS` (compiled from `config/secrets.yaml` via `build.rs`) is the authoritative
pattern set. Do NOT also iterate YAML config groups in the same audit pass — that double-counts
every hit.

## MCP Binary

The MCP server binary is `obfsck-mcp` (not `mcp`): `cargo build --bin obfsck-mcp`.
Install to PATH for `mcpipe --scan` auto-discovery (`PathBinaryScanner` in mcpipe).

## devloop / Standup Notes

- `devloop git analyze` requires an InsightProvider not yet wired in the CLI — returns error.
  Synthesize standups from `git log` directly.
- `op run --env-file=$HOME/.secrets` does not expand `$HOME` — use literal path
  `/Users/joe/.secrets`.

**sccache gotcha:** `cargo build` may report `(0 crates compiled)` even when it recompiled via cache hit — don't treat this as a no-op. Check `strings target/release/redact | grep <pattern>` to verify embedded content.

## Pattern Development Workflow

```bash
just audit-levels           # smoke-test all three levels against mixed_sample.txt
just probe-pii-minimal      # assert PII is NOT redacted at minimal
just probe-pii-standard     # assert PII IS redacted at standard
just probe-paranoid         # assert paranoid_only patterns fire only at paranoid
```

**`just` preferred over `mise run`** — has additional recipes (`audit-levels`, `probe-*`,
`test-golden`, `update-goldens`, `redact-stdin`). Run `just --list` to see all.

## Pattern Regex Gotchas

- `\w` does NOT match base64 `+` or `/` — use `[A-Za-z0-9+/_-]` for base64-encoded tokens
  (e.g. HashiCorp Vault `hvs.`/`hvb.` tokens).
- Context-anchored patterns (keyword + generic N-char payload) carry high FP risk — prefer
  prefix-anchored patterns. Mark context-only patterns `paranoid_only: true` or put them in
  the disabled `code_context` group.

## Scanning Claude Session Files

Session `.jsonl` files live at `~/.claude/projects/-Users-joe-dev-obfsck/*.jsonl`.
Scan them for leaked secrets: `obfsck redact --level paranoid --audit <file>`.
`[REDACTED-*]` placeholders in output mean the pre-commit hook already caught them — expected.
