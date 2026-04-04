---
# Rule: Agentic Actor Detection — Metrics & Penalty Invariants

`is_agentic_actor()` and `is_author_impersonation()` in
`crates/common/src/policy.rs` classify PRs authored or co-authored by
autonomous AI coding agents (Copilot as of v8.0.1).

## Detection layers

**Layer 1 — Author handle (zero-allocation, case-insensitive match):**
- `copilot[bot]`
- `github-copilot[bot]`
- `app/copilot`
- `app/github-copilot`

**Layer 2 — PR body trailer scan:**
- Lines matching `co-authored-by: *copilot*` (case-insensitive)
- Fires `is_author_impersonation()` when trailer present but author handle
  does NOT match Layer 1 (human PR with agentic commits injected).

## Penalty invariants (never change without version bump)

| Condition | `SlopScore.agentic_origin_penalty` | `agentic_pct` |
|-----------|-----------------------------------|---------------|
| `is_agentic_actor()` = true | 50 points | 100.0 |
| `is_agentic_actor()` = false | 0 points | 0.0 |
| Author impersonation detected | 50 points | 100.0 |

- The 50-point penalty is **additive** to the existing slop score formula.
  It is not capped and is not suppressed by `allowed_zombies` or domain bypasses.
- `agentic_pct` maps to column 17 of the CSV export
  (`Agentic_Contribution_Pct`) — do not change column position.

## Distinction from `is_automation_account`

```
                        | dependabot[bot] | copilot[bot]
is_automation_account   | true            | true
is_agentic_actor        | false           | true
```

Automation accounts (Dependabot, Renovate) receive the automation bypass
path. Agentic actors do not — the 50-point penalty fires regardless of
automation account status.

## Extension protocol

When adding a new agentic actor pattern:
1. Add the handle or trailer pattern to `is_agentic_actor()`.
2. Add a deterministic `#[test]` covering the new pattern (true + false case).
3. Update this file's detection layer table.
4. Bump the workspace version (penalty changes affect audit log semantics).
