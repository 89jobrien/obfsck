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

- `src/lib.rs` — public API: `obfuscate_text`, `obfuscate_alert`, `ObfuscationLevel`
- `src/secrets.rs` — secret pattern matching (loaded from `config/secrets.yaml`)
- `src/helpers.rs` — path/entropy utilities
- `src/analyzer/` — alert fetching + LLM analysis (behind `analyzer` feature)
- `src/api/` — axum REST server (behind `analyzer` feature)
- `src/clients/` — Loki / VictoriaLogs backends (behind `analyzer` feature)
- `src/schema.rs` — BAML schema for structured LLM output
- `src/bin/redact.rs` — CLI: pipe text through obfuscation
- `src/bin/analyzer.rs` — CLI: fetch + analyze alerts
- `src/bin/api.rs` — HTTP API server

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
cargo run --bin redact -- --level standard < input.txt
redact input.txt                          # installed binary (after cp target/release/redact ~/.local/bin/)
redact input.txt -o redacted.txt          # file → file
cat input.txt | redact                    # stdin → stdout
cargo run --bin analyzer -- --last 1h --limit 5 --dry-run
mise run logs           # API server with pretty logs
mise run baml:dry-run   # Analyzer without LLM calls (inspect prompt)
```

## Pattern Sources — Critical Dual-Location Gotcha

Secret patterns live in **one place**: `config/secrets.yaml`. `src/secrets.rs` is generated
from it at compile time via `build.rs` — do not edit `src/secrets.rs` directly.

`~/.config/obfsck/secrets.yaml` silently overrides the bundled config entirely — if it exists and is non-empty, the bundled config is ignored. Delete it to restore bundled defaults.

## Issue Tracking

Issues are tracked in `HANDOFF.obfsck.workspace.yaml` (not GitHub). Issue IDs use the format
`obfsck-N`. Check `blocked_by` / `unblocks` fields for dependency chains.

## Pre-commit Hook

The global git hook pipes the staged diff through `obfsck --level minimal`. Fake test tokens
(e.g. `ghp_aaa...`) trigger it — add them to `~/.config/obfsck/allowlist` (one per line).

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
