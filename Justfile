# Justfile for obfsck — commands designed for AI agent use.
# Run `just` to list all recipes with descriptions.

# Default: list all recipes
default:
    @just --list

# ---------------------------------------------------------------------------
# Build & check
# ---------------------------------------------------------------------------

# Type-check the workspace (fast, no codegen side-effects)
check:
    cargo check --workspace

# Regenerate src/secrets.rs from config/secrets.yaml via build.rs
codegen:
    cargo build -p obfsck 2>&1 | grep -E 'Compiling|Finished|error' || true

# Build all targets (triggers codegen if secrets.yaml changed)
build:
    cargo build --workspace

# Build release binary
build-release:
    cargo build --release

# ---------------------------------------------------------------------------
# Test
# ---------------------------------------------------------------------------

# Run the full test suite
test:
    cargo test --workspace

# Run only the golden/snapshot tests (requires analyzer feature)
test-golden:
    cargo test --test golden_tests --features analyzer

# Regenerate all golden fixture files (commit the results)
update-goldens:
    UPDATE_GOLDENS=1 cargo test --test golden_tests --features analyzer

# Run only unit tests (no integration tests)
test-unit:
    cargo test --lib

# Run a specific test by name substring
test-one NAME:
    cargo test '{{NAME}}'

# ---------------------------------------------------------------------------
# Lint & format
# ---------------------------------------------------------------------------

# Run clippy on both mutually-exclusive path-policy feature sets
lint:
    cargo clippy --all-targets --features analyzer,legacy-user-scan,path-policy-home-user-redact -- -D warnings
    cargo clippy --all-targets --features analyzer,legacy-user-scan,path-policy-non-allowlisted-redact -- -D warnings

# Apply clippy auto-fixes
fix:
    cargo clippy --fix --allow-dirty --allow-staged --all-targets \
        --features analyzer,legacy-user-scan,path-policy-home-user-redact
    cargo clippy --fix --allow-dirty --allow-staged --all-targets \
        --features analyzer,legacy-user-scan,path-policy-non-allowlisted-redact

# Check formatting (non-destructive)
fmt-check:
    cargo fmt --all -- --check

# Apply formatting
fmt:
    cargo fmt --all

# ---------------------------------------------------------------------------
# Gates (mirrors minibox pattern)
# ---------------------------------------------------------------------------

# Pre-commit gate: fmt-check + lint
pre-commit: fmt-check lint

# Pre-push gate: fmt-check + lint + test
prepush: fmt-check lint test

# Wire .git/hooks to call just — run once after cloning
init:
    #!/usr/bin/env bash
    set -euo pipefail
    printf '#!/bin/sh\necho "Running pre-commit checks..."\njust pre-commit\n' > .git/hooks/pre-commit
    printf '#!/bin/sh\necho "Running pre-push checks..."\njust prepush\n' > .git/hooks/pre-push
    chmod +x .git/hooks/pre-commit .git/hooks/pre-push
    echo "hooks wired: .git/hooks/pre-commit + pre-push → just"

# Install all git hooks (pre-commit, pre-push, commit-msg)
install-hooks:
    #!/usr/bin/env sh
    printf '#!/bin/sh\njust pre-commit\n' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
    printf '#!/bin/sh\njust prepush\n' > .git/hooks/pre-push && chmod +x .git/hooks/pre-push
    printf '#!/bin/sh\ncommit_regex="^(feat|fix|docs|style|refactor|perf|test|chore|ci|build|revert)(\\(.+\\))?: .+"\nif ! grep -qE "$commit_regex" "$1"; then\n  echo "warning: commit message does not follow conventional commits (non-blocking)"\nfi\n' > .git/hooks/commit-msg && chmod +x .git/hooks/commit-msg
    echo "hooks installed: pre-commit, pre-push, commit-msg"

# ---------------------------------------------------------------------------
# CI gate
# ---------------------------------------------------------------------------

# Full local CI: lint + test + build (mirrors mise run ci)
ci: lint test build

# ---------------------------------------------------------------------------
# Level invariant probes — quick manual checks for the PII gating invariant
# ---------------------------------------------------------------------------

# Verify PII is NOT redacted at --level minimal
probe-pii-minimal:
    @echo "--- PII probe at minimal (expect: names/SSN/phone/card unchanged) ---"
    cargo run --bin redact -- --level minimal tests/fixtures/inputs/pii_sample.txt

# Verify PII IS redacted at --level standard
probe-pii-standard:
    @echo "--- PII probe at standard (expect: [REDACTED-*] tokens present) ---"
    cargo run --bin redact -- --level standard tests/fixtures/inputs/pii_sample.txt

# Verify paranoid_only patterns fire only at --level paranoid
probe-paranoid:
    @echo "--- Paranoid probe (expect: IBAN/passport redacted only at paranoid) ---"
    @echo "=== minimal ===" && cargo run --bin redact -- --level minimal \
        tests/fixtures/inputs/paranoid_sample.txt
    @echo "=== standard ===" && cargo run --bin redact -- --level standard \
        tests/fixtures/inputs/paranoid_sample.txt
    @echo "=== paranoid ===" && cargo run --bin redact -- --level paranoid \
        tests/fixtures/inputs/paranoid_sample.txt

# Redact a specific file at a given level: just redact <file> <level>
redact FILE LEVEL="minimal":
    cargo run --bin redact -- --level {{LEVEL}} {{FILE}}

# Redact stdin at a given level: echo "text" | just redact-stdin standard
redact-stdin LEVEL="minimal":
    cargo run --bin redact -- --level {{LEVEL}}

# ---------------------------------------------------------------------------
# Secrets config
# ---------------------------------------------------------------------------

# Show which patterns are active at each level (dry-run via audit flag)
audit-levels:
    @echo "=== minimal ===" && cargo run --bin redact -- --level minimal --audit \
        tests/fixtures/inputs/mixed_sample.txt > /dev/null
    @echo "=== standard ===" && cargo run --bin redact -- --level standard --audit \
        tests/fixtures/inputs/mixed_sample.txt > /dev/null
    @echo "=== paranoid ===" && cargo run --bin redact -- --level paranoid --audit \
        tests/fixtures/inputs/mixed_sample.txt > /dev/null

# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

# Print current git state (branch + dirty files)
status:
    git branch --show-current
    git status --short

# Show recent commits
log:
    git log --oneline -10
