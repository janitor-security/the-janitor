# janitor.toml — Governance Documentation

Policy-as-code for The Janitor. A `janitor.toml` at the repository root
overrides the engine's global defaults. It is version-controlled, reviewable,
and diffable by the entire team.

## Quick Start

```toml
# janitor.toml — place at repository root

# Slop score threshold. PRs with a raw score above this value fail the gate.
min_slop_score = 100

# Require every PR to reference a GitHub issue (#N) in the body.
require_issue_link = false

# Downgrade zombie-symbol vetoes to warnings for active refactor cycles.
allowed_zombies = false

# Raise the gate by this amount for PRs tagged [REFACTOR] or [FIXES-DEBT].
refactor_bonus = 0

# Require a PQC attestation bond (ML-DSA-65 / CycloneDX v1.5) — needs Sentinel.
pqc_enforced = false

# Paths to custom .scm tree-sitter query files that define project-specific antipatterns.
custom_antipatterns = []

# Handles exempt from the unlinked-PR penalty (not bots — use [forge] for that).
trusted_bot_authors = []

[forge]
# Ecosystem accounts that lack the [bot] suffix but are non-human contributors.
automation_accounts = []
```

## Field Reference

### Top-level fields

| Field | Type | Default | Description |
|---|---|---|---|
| `min_slop_score` | `u32` | `100` | Raw slop score ceiling. PRs above this threshold fail the gate. Lower = stricter. |
| `require_issue_link` | `bool` | `false` | When `true`, PRs with no `#<digits>` reference in the body are blocked, regardless of score. |
| `allowed_zombies` | `bool` | `false` | When `true`, zombie-symbol re-introductions are downgraded to a Warning instead of a hard Veto. Set only during active symbol-resurrection refactors. |
| `refactor_bonus` | `u32` | `0` | Points added to `min_slop_score` for PRs tagged `[REFACTOR]` or `[FIXES-DEBT]`. Raises the effective gate for intentional cleanup. |
| `pqc_enforced` | `bool` | `false` | When `true`, blocks PRs where the ML-DSA-65 / CycloneDX v1.5 Integrity Bond could not be issued. Requires Janitor Sentinel. |
| `custom_antipatterns` | `[String]` | `[]` | Paths to custom `.scm` tree-sitter query files (relative to repo root). Each `@slop`-capturing pattern adds +50 to the score per match. |
| `trusted_bot_authors` | `[String]` | `[]` | Handles exempt from the unlinked-PR penalty. Case-insensitive exact match. For accounts without `[bot]` suffix. |

### `[forge]` sub-table

| Field | Type | Default | Description |
|---|---|---|---|
| `automation_accounts` | `[String]` | `[]` | Ecosystem automation accounts exempt from the unlinked-PR penalty. Example: `["r-ryantm", "app/nixpkgs-ci"]`. Full slop analysis still runs; only the issue-link check is bypassed. Case-insensitive exact match. |

## Automation Shield

The engine automatically detects bot authors via four layers (evaluated in order,
all zero-allocation):

1. **`app/` prefix** — any author starting with `app/` is a GitHub App
   installation (e.g. `app/dependabot`, `app/renovate`, `app/github-actions`).
   No configuration required.
2. **`[bot]` suffix** — any author ending with `[bot]` is automatically detected
   (e.g. `dependabot[bot]`, `renovate[bot]`). No configuration required.
3. **`trusted_bot_authors`** — handles listed at the top level of `janitor.toml`.
   Backward-compatible with existing manifests.
4. **`[forge].automation_accounts`** — handles listed in the `[forge]` sub-section.
   Designed for ecosystem accounts without the `[bot]` suffix (e.g. `r-ryantm`).

When detected, the account is exempt from the unlinked-PR penalty (+20 pts). All
other detection (dead symbols, logic clones, antipatterns) still runs.

## pqc_enforced

Setting `pqc_enforced = true` requires **Janitor Sentinel** (the GitHub App SaaS
layer). The Sentinel generates a persistent ML-DSA-65 key (`governor.key`) on first
run and signs every CycloneDX v1.5 CBOM bond.

When this flag is set and the bond cannot be issued (e.g. the Governor is
unreachable), the PR is blocked:

```
BLOCKED by repository-defined governance policy (janitor.toml).
Reason: pqc_enforced = true. The ML-DSA-65 Integrity Bond could not be issued.
```

## Custom Antipatterns

Point `custom_antipatterns` at `.scm` files containing tree-sitter queries:

```toml
custom_antipatterns = [
    "tools/queries/no_global_state.scm",
    ".janitor/queries/no_direct_sql.scm",
]
```

Each file must contain patterns with an `@slop` capture. Every match scores +50
against the composite slop score.

## Effective Gate Formula

```
effective_gate = min_slop_score + (refactor_bonus IF [REFACTOR] or [FIXES-DEBT] in body)
PR passes      = raw_slop_score < effective_gate
```

The `refactor_bonus` floors at `min_slop_score` — the gate never goes below the
configured threshold even for tagged PRs.
