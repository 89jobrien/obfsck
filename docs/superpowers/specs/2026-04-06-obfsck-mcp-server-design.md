# obfsck MCP Server — Design Spec

**Date:** 2026-04-06
**Status:** Approved
**Scope:** coursers-11

---

## Overview

Add a stdio MCP server binary to obfsck exposing two tools: `audit` and `generate-filters`.
The server is consumed by `crs discover` via mcpipe to generate project-local redaction filter
configs at `.ctx/obfsck-filters.yaml`.

---

## Architecture

```
obfsck/
  src/bin/obfsck-mcp.rs         new stdio MCP binary (behind `mcp` feature flag)
  src/mcp/
    mod.rs                       module root, re-exports
    protocol.rs                  JSON-RPC 2.0 stdin/stdout loop
    tools/
      mod.rs
      audit.rs                   `audit` tool — structured hit report
      generate_filters.rs        `generate-filters` tool — SecretsConfig YAML output

coursers/
  crates/crs/src/main.rs         extend cmd_discover() with obfsck-mcp detection + call
  .ctx/obfsck-filters.yaml       generated output (passed to redact via --config)
```

**Data flow:**

```
crs discover
  └─ detect obfsck-mcp on PATH
       └─ mcpipe --stdio obfsck-mcp generate-filters --examples "[...]"
            └─ obfsck-mcp (JSON-RPC loop)
                 ├─ match examples against built-in groups  (SecretsConfig)
                 └─ generate custom regex for unmatched examples
                      └─ return SecretsConfig YAML fragment
  └─ write .ctx/obfsck-filters.yaml
  └─ obfsck_audit(.ctx/obfsck-filters.yaml)
```

---

## Feature Flag

New feature `mcp` in `obfsck/Cargo.toml`. Building without it produces no MCP binary and
compiles no `src/mcp/` module. The `mcp` feature does not depend on `analyzer` — it is
standalone and adds no axum or tokio dependencies.

---

## MCP Protocol

- Transport: stdio, newline-delimited JSON-RPC 2.0
- Synchronous read/dispatch/write loop — no async runtime
- Each request fully processed before reading the next
- Implements: `initialize`, `tools/list`, `tools/call`
- `initialize` response: `{ name: "obfsck-mcp", version: "<crate version>", tools: [...] }`

Error codes:
| Code    | Meaning              | When used                          |
|---------|----------------------|------------------------------------|
| -32700  | Parse error          | Malformed JSON on stdin            |
| -32601  | Method not found     | Unknown method name                |
| -32602  | Invalid params       | Wrong/missing tool params          |

EOF on stdin → exit 0.

---

## Tools

### `audit`

**Purpose:** Pipe content through the obfsck library, return per-pattern hit counts as JSON.
Equivalent to `redact --audit` but structured.

**Input schema:**
```json
{
  "content": "<string>",
  "level":   "minimal | standard | paranoid"   // default: minimal
}
```

**Output schema:**
```json
{
  "hits": [
    { "pattern": "anthropic_api_key", "label": "ANTHROPIC-KEY", "count": 2 }
  ],
  "clean": false
}
```

**Behaviour:**
- Calls obfsck library directly — no subprocess
- Empty content → `{ "hits": [], "clean": true }` (not an error)
- Invalid `level` → JSON-RPC error `-32602`, message lists valid values

---

### `generate-filters`

**Purpose:** Given a list of example secret strings, produce a `SecretsConfig`-format YAML
fragment ready to write to `.ctx/obfsck-filters.yaml` and pass to `redact --config`.

**Input schema:**
```json
{
  "examples": ["sk-ant-api03-...", "ghp_abc123", "my-custom-token-xyz"]
}
```

**Output schema:** YAML string in `SecretsConfig` format (deserializable by obfsck's
`yaml_config::SecretsConfig`):
```yaml
groups:
  ai_apis:
    enabled: true
    patterns:
      - name: anthropic_api_key
        pattern: '\bsk-ant-(?:api\d{2}-)?[A-Za-z0-9_-]{32,}\b'
        label: ANTHROPIC-KEY
        paranoid_only: false
  # only groups with at least one matching pattern are emitted
custom:
  - name: generated_my_custom_token
    pattern: '\bmy-custom-[A-Za-z0-9_-]{10,}\b'
    label: CUSTOM-TOKEN
    paranoid_only: false
```

**Logic:**
1. For each example, test against every built-in group's compiled patterns
2. Matched → include that group entry (only matched patterns, not full group)
3. Unmatched → attempt regex generation:
   - Extract literal prefix: longest run of non-alphanumeric-varying chars (e.g. `ghp_`, `sk-ant-`)
   - Classify remaining chars: `[A-Za-z0-9]`, `[A-Za-z0-9_-]`, `[A-Za-z0-9/+=]`
   - Emit pattern only if: prefix ≥ 4 chars OR (no prefix AND remaining length ≥ 20)
   - Anchor with `\b`, add `{N,}` length bound from example length
4. Skip examples that produce no viable pattern (too short, no prefix, generic chars)
5. Empty `examples` → `groups: {}\ncustom: []\n` (not an error)
6. Example matches multiple groups → include all matched groups

**Emit rule for unmatched examples (quality gate):**
- Require literal prefix ≥ 4 chars, OR
- Remaining segment uses entropy-indicating char class (`[A-Za-z0-9/+=]` or `[A-Za-z0-9_-]`)
  AND length ≥ 20
- Otherwise: skip — do not emit a garbage regex

---

## crs discover Integration

After writing `HANDOFF.tools.yaml`, `cmd_discover` checks:

1. Is `obfsck-mcp` on PATH? (`which obfsck-mcp`)
2. Is `.ctx/` present?
3. (Always proceed if both true — the unhandled list may contain sensitive stems)

Then:
```
mcpipe --stdio obfsck-mcp generate-filters --examples '<json array of unhandled stems>'
```

On success → write `.ctx/obfsck-filters.yaml` → pass through `obfsck_audit`.

**Failure handling:**
- `obfsck-mcp` not on PATH → skip silently (same pattern as `rtk` detection)
- mcpipe call fails (non-zero exit) → `eprintln!("warn: obfsck-mcp call failed: ...")`, continue
- `.ctx/obfsck-filters.yaml` already exists → overwrite

---

## Testing

### Unit tests (in `src/mcp/tools/`)

- `audit`: call with known secret string at each level, assert hit counts match
- `audit`: empty content → clean result
- `audit`: invalid level param → correct error struct returned
- `generate-filters`: known prefix (e.g. `sk-ant-...`) → matches `ai_apis` group
- `generate-filters`: unknown prefix ≥ 4 chars → custom pattern emitted with correct anchor
- `generate-filters`: too-short/generic example → skipped, no pattern emitted
- `generate-filters`: empty examples → empty YAML returned

### Integration tests (in `tests/`)

- Spawn `obfsck-mcp` as child process
- Send `initialize` → assert tool list contains `audit` and `generate-filters`
- Send `tools/call audit` with secret content → assert structured hits
- Send `tools/call generate-filters` → assert valid YAML, parseable as `SecretsConfig`
- Send unknown method → assert `-32601` error response
- Send malformed JSON → assert `-32700` error response

---

## Out of Scope

- Auto-loading `.ctx/obfsck-filters.yaml` inside obfsck at startup — consumed via `--config` only
- LLM-assisted pattern generation — pure heuristic regex derivation only
- mcpipe changes — existing stdio transport is sufficient
- HTTP/SSE transport — stdio only

---

## Open Questions

None. All design decisions resolved.
