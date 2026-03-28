# Rule: Constitutional Evolution — Structural Gate Mandate

When a bug or API regression is identified, you MUST propose a deterministic
structural gate to prevent its recurrence. Favor AhoCorasick patterns and AST
invariants over manual fixes.

## The Law

A bug fixed without a gate is a bug deferred. Every identified failure mode
must be converted into a machine-checkable invariant — a detector that would
have caught it on the first occurrence, not the second.

## Gate hierarchy (prefer higher tiers)

| Tier | Mechanism | When to use |
|------|-----------|-------------|
| 1 — AST invariant | tree-sitter query in `slop_hunter.rs` | Language-specific structural patterns (unsafe calls, dangerous constructs) |
| 2 — AhoCorasick pattern | `migration_guard.rs` or `slop_hunter.rs` | String-level API patterns, version-conditioned regressions |
| 3 — Manifest analysis | `anatomist/manifest.rs` | Dependency-level issues (zombie deps, version silos) |
| 4 — Heuristic gate | `agnostic_shield.rs` or `metadata.rs` | Cross-language patterns (entropy anomalies, comment violations) |

## Protocol

1. **Identify the failure class** — is it an API change, an unsafe call, a
   configuration error, or a structural pattern?
2. **Select the highest applicable tier** — AST queries beat string matching;
   manifest analysis beats heuristics.
3. **Write the gate** — add the detector to the appropriate module.
4. **Add a Crucible entry** — add a true-positive fixture AND a true-negative
   fixture to `crates/crucible/src/main.rs`.
5. **Run `cargo run -p crucible`** — must exit `0` (SANCTUARY INTACT).
6. **Run `just audit`** — must exit `0`. Gate is not active until both pass.

## Example: DepMigrationRule (v8.0.4)

A ureq 2→3 API break was identified.  Rather than adding a doc comment warning,
a `DepMigrationRule` was implemented in `crates/forge/src/migration_guard.rs`:
- AhoCorasick scans added `.rs` lines for `.set(`, `.timeout(`, `Error::Status`
- Gate activates ONLY when `Cargo.toml`/`Cargo.lock` shows the 2→3 version bump
- Fires at `Critical` severity (50 pts) — compile-breaking regressions are
  equivalent to `gets()` or an open CIDR rule in impact

## Extension

When adding a new `DepMigrationRule`:
1. Append to `MIGRATION_RULES` in `migration_guard.rs`.
2. Add a Crucible entry (bump-detected + clean case).
3. Update the active-rules table in `migration_guard.rs` module doc.
4. Bump the workspace version — rule changes affect audit log semantics.
