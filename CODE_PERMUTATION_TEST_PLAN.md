# Code Permutation Test Plan (obfsck)

This plan turns implementation choice into a repeatable experiment with hard quality gates.

## 1) Scope and Goal

- **Primary experiment target:** `src/helpers.rs::obfuscate_path_value` (Paranoid mode path policy)
- **Pipeline context:** `src/lib.rs::Obfuscator::obfuscate` runs
  1. secrets
  2. standard obfuscation (ip/email/container/user)
  3. paranoid-only obfuscation (paths/hostnames/high-entropy)
- **Reason to start here:** highest privacy risk with deterministic validation; current behavior can preserve user-identifying path segments.

## 2) Permutations Under Test

Evaluate a maximum of **3** alternatives for this first experiment.

- **P0 (Baseline):** current path logic in `obfuscate_path_value`
- **P1 (Targeted hardening):** redact home-directory user segment only
  - examples to protect: `/home/<name>/...`, `C:\Users\<name>\...`
- **P2 (Broader hardening):** redact all non-allowlisted path segments while preserving known root/system structure

## 3) Hard Gates (must pass before scoring)

If any gate fails, reject the permutation regardless of score.

1. **No home-user leakage**
   - output must not contain original username segment for `/home/<name>/...` and `C:\Users\<name>\...`
2. **Preserve sensitive path behavior**
   - `is_sensitive_path()` protected values (e.g., `/etc/passwd`, `/.aws/credentials`, Windows SAM paths) must remain unchanged where required by current behavior
3. **No regression in obfuscation invariants**
   - existing unit tests must pass, especially stable token mapping and level semantics
4. **Performance guardrail**
   - no >10% regression in paranoid/large benchmark vs baseline unless privacy gain is material and documented

## 4) Weighted Decision Matrix

Score each criterion from 1-5 after gates pass.

| Criterion | Weight | Notes |
|---|---:|---|
| Privacy leakage reduction | 35 | No residual path identity leakage in corpus |
| Signal preservation / analyst utility | 20 | Keep useful path structure and readable output |
| Correctness & determinism | 15 | Stable mappings and current semantics retained |
| Reliability / failure modes | 15 | Avoid brittle transformations and accidental redaction interactions |
| Maintainability | 10 | Minimal complexity and branch explosion |
| Performance (practical) | 5 | Only count improvements that are consistent and meaningful |

**Weighted score formula:**

`score = Σ(weight * (criterion_score / 5.0))`

## 5) Corpus Definition

Use fixed, repeatable inputs from existing repo artifacts:

1. `tests/obfuscation.rs` path and paranoid-mode cases
2. `benches/full_obfuscation.rs` short/medium/large strings
3. README-style mixed secrets + paths examples
4. Explicit edge cases:
   - Unix user paths: `/home/alice/.config/app/settings.yaml`
   - Windows user paths: `C:\Users\alice\Documents\notes.txt`
   - UNC paths: `\\server\share\team\ops\secrets.txt`
   - secret token in path-like string

## 6) Runbook (Exact Commands)

Run in repo root.

### 6.1 Baseline snapshot (P0)

```bash
cargo test --test obfuscation
cargo bench --bench user_obfuscation -- --quick
cargo bench --bench full_obfuscation -- --quick
```

### 6.2 Candidate evaluation (repeat for P1 then P2)

```bash
# P1
cargo test --test obfuscation --features path-policy-home-user-redact
cargo bench --bench full_obfuscation --features path-policy-home-user-redact -- --quick

# P2
cargo test --test obfuscation --features path-policy-non-allowlisted-redact
cargo bench --bench full_obfuscation --features path-policy-non-allowlisted-redact -- --quick
```

Notes:

- `path-policy-home-user-redact` and `path-policy-non-allowlisted-redact` are mutually exclusive.
- Baseline keeps both features disabled.

### 6.3 Optional stricter performance pass (for finalists only)

```bash
cargo bench --bench full_obfuscation
```

## 7) Decision Rules

1. Reject permutations failing any hard gate.
2. If two passing candidates are within **5 weighted points**, choose simpler implementation.
3. Require at least **+10 weighted points** over baseline to justify adoption.
4. If no candidate clears threshold, keep baseline and move to next hotspot.

## 8) Score Sheet Template

Fill one row per permutation after test/bench runs.

| Permutation | Gates Passed (Y/N) | Privacy (35) | Utility (20) | Correctness (15) | Reliability (15) | Maintainability (10) | Performance (5) | Weighted Total | Decision |
|---|---|---:|---:|---:|---:|---:|---:|---:|---|
| P0 Baseline |  |  |  |  |  |  |  |  |  |
| P1 Home-user redact |  |  |  |  |  |  |  |  |  |
| P2 Non-allowlisted segment redact |  |  |  |  |  |  |  |  |  |

## 9) Next Permutation Queue (after path policy)

Prioritized by impact and existing coverage:

1. `src/secrets.rs` pattern strategy permutations (false-positive/false-negative trade-off)
2. `src/lib.rs` user-obfuscation strategy permutations (`legacy-user-scan` vs single-regex evolution)
3. `src/lib.rs` high-entropy threshold tuning (`shannon_entropy` threshold and minimum length)
4. `src/analyzer/mod.rs` parse fallback behavior permutations (strictness vs robustness)

## 10) Exit Criteria for This Experiment

Experiment is complete when:

- all three permutations (P0/P1/P2) have gate results,
- score sheet is filled,
- one winning approach (or no-change decision) is recorded with rationale,
- benchmark and test evidence is attached to the decision record.
