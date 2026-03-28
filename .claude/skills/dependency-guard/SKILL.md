# Skill: Dependency Guard (Auto-Invoked)

**Trigger:** Whenever a proposed change modifies a lockfile (`Cargo.lock`,
`package-lock.json`, `yarn.lock`, `poetry.lock`, `go.sum`).

## Protocol

1. **Detect lockfile modification** in the staged diff or proposed patch:
   - Check `git diff HEAD` or the active patch for any path matching
     `**/Cargo.lock`, `**/package-lock.json`, `**/yarn.lock`,
     `**/poetry.lock`, or `**/go.sum`.
   - If no lockfile is modified, this skill is dormant — do nothing.

2. **Run `janitor_silo_audit` (MCP)** against the workspace blobs:
   - Pass the diff blobs so the tool can delta-subtract pre-existing silos.
   - Capture the full `silo_findings` list from the response.

3. **Report findings before any merge recommendation:**

   | Outcome | Action |
   |---------|--------|
   | Zero new silos | State "Dependency Guard: clean — no new silos introduced." and proceed. |
   | New silos found | List each silo (crate name, conflicting versions, introducing dep). **Block** the merge recommendation until each silo is either resolved or explicitly documented with a justification comment in `janitor.toml`. |

4. **Resolved = one of:**
   - The silo-introducing dep is pinned to a compatible version that
     collapses the split.
   - A `[silo.exceptions]` entry is added to `janitor.toml` with a
     rationale string (e.g., `"transitive: proc-macro-error requires syn@1"`).

## Abort conditions

| Condition | Action |
|-----------|--------|
| New silo with no resolution | Block merge, list unresolved silos |
| `janitor_silo_audit` tool error | Abort and surface the error — do not silently skip |

## Notes

- This skill fires on **every** lockfile-touching change, including
  automated Dependabot / Renovate PRs.
- Pre-existing silos present on `main` before this PR are excluded by the
  delta-subtraction logic in `find_version_silos_from_lockfile`.
- The operator may not bypass this gate by saying "it's just a bump."
