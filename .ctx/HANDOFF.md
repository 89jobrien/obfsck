# Handoff — obfsck (2026-05-23)

**Branch:** main | **Build:** unknown | **Tests:** unknown

## Items

| ID | P | Status | Title |
|---|---|---|---|

## Log

- 20260422:215703: Released v0.1.0. Added richer error messages (line numbers in findings, invalid pattern warnings). Wired obfsck-scan into pre-commit hook (local .githooks + global ~/.config/git/hooks). Added two CLI integration tests. Moved handoff SQLite DB to ~/.ctx/handoff.db.
- 20260419:180000: Merged refactor/pattern-source-port into main. All items closed (obfsck-12/13/14/15/16/17). Committed Send+Sync bounds on LlmProvider trait.
- 20260419:162232: handup sweep — workspace HANDOFF pruned (obfsck-7/8/9 were fixed 2026-04-13; removed done items). Migrated to HANDOFF.obfsck.obfsck.yaml.
- 20260418:000000: handjobs triage — closed GH #1/2/3/4/6/7/9 (all fixed). 2 open items remain (obfsck-13, obfsck-15). Design sketches proposed for obfsck-12/14/16/17.
- 20260413:000000: Fixed path traversal (obfsck-7), YAML parser silent drop (obfsck-8), allowlist bypass (obfsck-9).
