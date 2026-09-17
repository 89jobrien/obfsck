# Feature Roadmap

Evidence-backed opportunities identified from the current repository. Status values are
`queued`, `designing`, `implementing`, `blocked`, or `done`.

## Quick Wins

| Priority | Status | Feature | Evidence |
| --- | --- | --- | --- |
| Q1 | queued | Fix cache deduplication counts | `src/api/mod.rs` exposes `dedup_count`, but cache hits do not update it. |
| Q2 | queued | Add a code-sharing privacy profile | `docs/garble-style-obfuscation-idea.md` proposes redacting internal hosts, paths, projects, and URLs. |
| Q3 | queued | Add benchmark smoke checks | `.github/workflows/ci.yml` exercises both path-policy feature combinations but does not run the Criterion benches registered in `Cargo.toml`. |

## Medium

| Priority | Status | Feature | Evidence |
| --- | --- | --- | --- |
| M1 | queued | Emit structured, non-mutating audit findings | `src/cli.rs` contains `TODO(roadmap-audit)`; current audit mode still writes transformed output. |
| M2 | queued | Scan files and repositories recursively | `src/bin/scan.rs` contains `TODO(roadmap-scan-path)` and currently accepts unified diffs only. |
| M3 | queued | Complete the level-aware MCP contract | `src/mcp/mod.rs` contains `TODO(roadmap-mcp)`; MCP tools do not accept level, PII, allowlist, or custom pattern settings. |
| M4 | queued | Support configurable analyzer queries and labels | `src/analyzer/mod.rs` contains `TODO(roadmap-query)` and constructs fixed backend queries. |
| M5 | queued | Move remaining binaries under the canonical CLI | `src/cli.rs` exposes `redact` and `analyze`, while `scan`, `api`, and `obfsck-mcp` remain separate binaries. |

## Large

| Priority | Status | Feature | Evidence |
| --- | --- | --- | --- |
| L1 | done | Share one configurable pattern engine | `PatternSet` now supplies generated group provenance and one configurable matching path for the library, CLI, scanner, and MCP. |
| L2 | queued | Add secure API deployment modes | `src/api/mod.rs` contains `TODO(roadmap-secure-api)` for authentication, restrictive CORS, limits, and redacted-only caches. |
| L3 | queued | Build a unified provider pipeline | `src/analyzer/providers.rs` contains `TODO(roadmap-providers)`; providers duplicate request handling and batches run sequentially. |
| L4 | queued | Introduce region-aware redaction | `fuzz/fuzz_targets/fuzz_level_monotonicity.rs` documents that ordered destructive passes prevent a hard monotonicity invariant. |

## Completed Work

- **L1 Shared configurable pattern engine**: the public immutable `Pattern` and cloneable
  `PatternSet` now preserve group provenance and drive every pattern consumer. See
  `docs/designs/2026-09-07-shared-pattern-engine-design.md`.
