---
# Rule: Testing Mandate — Deterministic Regression Coverage

## The Law

Every functional change to a crate under `crates/` MUST be accompanied by a
corresponding `#[test]` in the same commit. For detectors, a new entry in the
`crates/crucible` Threat Gallery is mandatory.

Every new or modified detection path MUST ship with at least one `#[test]`
in the same PR. No exceptions. Tests must be deterministic: no network
calls, no filesystem side-effects, no `thread::sleep`.

See `.claude/skills/crucible-enforcement/SKILL.md` for the enforced TDD cycle.

## Scope

This rule applies to all code under:
- `crates/forge/src/` — slop detection, hashing, clone detection
- `crates/anatomist/src/` — manifest scanning, language dispatch
- `crates/common/src/policy.rs` — policy evaluation, agentic/automation detection
- `crates/reaper/src/` — safe deletion, liveness tracking, audit log

## Minimum test surface per detection type

| Detection path | Required test coverage |
|----------------|----------------------|
| New `find_slop()` antipattern rule | At least: true-positive fixture + true-negative fixture |
| New `check_*()` function in `slop_hunter.rs` | At least one finding + one clean case |
| New policy predicate (`is_*` in `policy.rs`) | All branches covered (true/false) |
| New manifest scanner in `anatomist/manifest.rs` | Synthetic lockfile fixture round-trip |
| New `ByteLatticeAnalyzer` rule | AnomalousBlob + ProbableCode fixture |
| New `CommentScanner` pattern | Matching + non-matching comment fixture |

## Ghost Attack self-test

The `janitor self-test` command (`crates/cli/src/main.rs::cmd_self_test`) runs
Ghost Attack A (cryptominer string) and Ghost Attack B (version silo injection)
against synthetic fixtures. Any new critical-severity detection path MUST be
added to the self-test suite and verified by `janitor self-test` before merge.

## Enforcement

`just audit` runs `cargo test` — all `#[test]` blocks must pass.
A PR that introduces a detection rule with zero associated tests is a
violation of this mandate, equivalent to a `slop_score > 0` block.

## Prohibited patterns in tests

- `#[ignore]` without a documented reason (unstable CI resource only).
- `unwrap()` / `expect()` in test bodies that could produce silent `Ok(())` on failure.
- Any test that passes by catching a panic (`std::panic::catch_unwind`) where
  the production code path should not panic.
