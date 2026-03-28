---
# Rule: Logic Guardian — Branch Density Preservation (v8.0.1 Mandate)

Branch density is a structural proxy for decision coverage. Reducing it
without explicit justification is an architecture defect, not a refactor.

## Hard constraint

You MUST NOT reduce branch density (count of `if`, `match`, `switch`,
`case`, `guard`, `elif`, `elsif`, `else if` keywords) by more than **20%**
in any single diff without providing an explicit architectural justification.

This threshold is enforced by `check_logic_regression` in
`crates/forge/src/slop_hunter.rs`. The engine fires
`architecture:logic_erasure` at `Severity::Critical` when:

- base branch count ≥ 3
- branch reduction > 20%
- diff is volume-neutral (|Δlines| ≤ base_lines / 10)

## When the constraint fires

1. Stop. Do not proceed with the change.
2. Read the `antipattern_details` from `janitor_bounce`.
3. Either:
   - **Justify**: explain in the PR description *why* the removed branches
     were redundant and which invariant makes them unreachable.
   - **Restore**: add back the equivalent decision logic in a different form.
4. Re-run `janitor_bounce` until `slop_score == 0`.

## Acceptable justifications

- Upstream API change eliminated an entire error variant (cite the dep PR).
- Compile-time guarantee now covers the removed runtime check (cite the
  type or const expression).
- The removed branches were dead code proved by a prior `/scan` run.

## Unacceptable justifications

- "Simplification" with no structural proof.
- "The tests still pass."
- "LLM suggested it."

---

## Version Silo Unification (Audit Mandate)

Transitive version silos must be analyzed during `/audit` whenever `Cargo.lock`
or any `Cargo.toml` is modified. Run `/dep-check` (`janitor_dep_check` MCP) to
enumerate the current silo count before finalizing any dependency change.

**Rule**: If a silo **can** be unified by a version bump in our direct manifest
(workspace `Cargo.toml` or a crate-level `Cargo.toml`), it **MUST** be unified
as part of the same PR that introduces or touches that dependency.

**Unfixable silos** are those anchored by a semver-incompatible split in the
transitive ecosystem (e.g., `getrandom 0.2` anchored by `rand 0.8` vs
`getrandom 0.4` required by `uuid`/`tempfile`). These are acceptable if
documented with the anchoring crate named explicitly.

**Silo target**: < 5 unique version-split pairs in `cargo tree -d` output.
Crossing this threshold without resolving fixable silos is a hard block on
merge, equivalent to a non-zero `slop_score`.
