# Skill: Documentation Integrity (Auto-Invoked)

**Trigger:** Before finalizing any commit that modifies files in the
Mapping Matrix below.

## Mapping Matrix

| Changed path pattern | Document to audit |
|----------------------|-------------------|
| `crates/**` | `SOVEREIGN_BRIEFING.md` |
| `justfile` | `RUNBOOK.md` |
| Any new or modified CLI flag | `RUNBOOK.md` |
| `action.yml` | `docs/setup.md` |

## Protocol

1. **Scan the staged diff** for files matching the Mapping Matrix patterns:
   - `git diff --name-only HEAD` (or the staged patch)

2. **For each triggered document**, verify that it reflects the new functional
   reality of the code change:

   | Trigger | Verification checklist |
   |---------|----------------------|
   | `crates/**` changed | Does `SOVEREIGN_BRIEFING.md` reflect the new module, struct, or public API? |
   | `justfile` changed | Does `RUNBOOK.md` list the new/modified recipe with correct syntax? |
   | CLI flag added/renamed | Does `RUNBOOK.md` show the updated flag name and description? |
   | `action.yml` changed | Does `docs/setup.md` show the new input, step, or behavior? |

3. **If the document is stale** (code changed, doc not updated):
   - Report the specific gap: which document, which section, what is missing.
   - Update the document **in the same commit** as the code change.
   - Re-run the pre-commit gate after the update.

4. **If the document is current**: proceed to commit.

## Abort conditions

| Condition | Action |
|-----------|--------|
| Mapping Matrix triggered, document not updated | Block commit, report gap, update document |
| Document updated but factually incorrect | Block commit, correct the content |

## Scope

This skill audits for **functional accuracy** — command names, flag names,
API shapes, and module names.  It does not enforce prose style or completeness
of prose explanations.

## Notes

- `SOVEREIGN_BRIEFING.md` is the sole technical architecture specification.
  No other architecture document should exist at the root.
- `RUNBOOK.md` is the sole command manual.
  No other operations manual should exist at the root.
- If a new crate or tool is added, a corresponding section in
  `SOVEREIGN_BRIEFING.md` is mandatory before the commit is finalized.
