# Skill: Dependency Guard (Auto-Invoked)

**Trigger:** Whenever a proposed change modifies ANY of the following files:
- `Cargo.lock` — Rust workspace lockfile
- `Cargo.toml` — Any workspace or crate manifest (direct dep change = potential silo)
- `package-lock.json` — npm lockfile
- `package.json` — npm manifest (dep version change may introduce silos)
- `yarn.lock` — Yarn lockfile
- `poetry.lock` — Python lockfile
- `go.sum` — Go module checksum database

**Fail-closed**: This skill is an admission gate, not an advisory. A detected
version silo with no documented resolution BLOCKS the change from proceeding.
"It works anyway" is not a resolution.

## Protocol

1. **Detect trigger file** in the staged diff or proposed patch:
   - Check `git diff HEAD` or the active patch for any path matching the
     trigger list above.
   - If no trigger file is modified, this skill is dormant — do nothing.

2. **Run `janitor_silo_audit` (MCP)** against the workspace blobs:
   - Pass the diff blobs so the tool can delta-subtract pre-existing silos
     already on `main`.
   - Capture the full `silo_findings` list from the response.

3. **Enforce the silo target** before any merge recommendation:

   | Outcome | Action |
   |---------|--------|
   | Zero new silos | State "Dependency Guard: clean." and proceed. |
   | New silos found | List each silo (crate, conflicting versions, introducing dep). **BLOCK** until resolved or documented. |
   | `janitor_silo_audit` returns an error | **ABORT** — do not silently skip; surface the error. |

4. **Resolution requirements** (one of):
   - The silo-introducing dep is pinned to a version that collapses the split.
   - A `[silo.exceptions]` entry in `janitor.toml` names the anchoring crate
     and explains why the split is irreducible (e.g., `"getrandom: rand@0.8
     anchors v0.2; uuid@1.10 requires v0.4 — unfixable without rand upgrade"`).

5. **Silo target enforcement**: If the total silo count (new + pre-existing)
   exceeds **5 unique version-split pairs**, flag this as a hard block
   regardless of whether the new silos were introduced by this PR.

## Hard abort conditions

| Condition | Action |
|-----------|--------|
| New silo with no resolution or documented exception | Block — do not proceed |
| `janitor_silo_audit` tool error | Block — surface error, do not skip |
| Silo count > 5 pairs post-merge | Block — require remediation plan |

## Notes

- This skill fires on **every** manifest or lockfile touch, including
  automated Dependabot / Renovate PRs.
- The operator may NOT bypass this gate by saying "it's just a bump",
  "it's automated", or "the tests pass."
- The unfixable `getrandom 0.2/0.4` silo (anchored by `rand 0.8`) is a
  documented exception — it does not consume one of the 5 allowed pairs.
