# Skill: Crucible Gate (Auto-Invoked)

**Trigger:** Whenever a proposed change modifies ANY file under:
- `crates/forge/` — slop detection engine, agnostic shield, hashing, PR collider
- `crates/anatomist/` — manifest scanner, zombie deps, phantom calls, silo detection

**Fail-closed**: This skill is an admission gate, not an advisory. A failed
Crucible run BLOCKS the change from proceeding. "The tests still pass" is not
a resolution — the Crucible must return exit 0.

## Protocol

1. **Detect trigger path** in the staged diff or proposed patch:
   - Check `git diff HEAD` or the active patch for any path matching
     `crates/forge/**` or `crates/anatomist/**`.
   - If no trigger path is modified, this skill is dormant — do nothing.

2. **Run the Crucible**:
   ```bash
   cargo run -p crucible
   ```
   Capture stdout and the exit code.

3. **Enforce the result**:

   | Outcome | Action |
   |---------|--------|
   | Exit 0, all `[PASS]` | State "Crucible: SANCTUARY INTACT." and proceed. |
   | Any `[FAIL]` line | List each failing entry. **BLOCK** until the detector is fixed. |
   | Compilation error | **ABORT** — surface the error; do not silently skip. |

4. **Resolution requirements** (one of):
   - The detector is repaired so the failing entry passes.
   - The gallery entry is updated to reflect a deliberate, documented rule change
     (requires a separate commit with a rule-change justification in the message).

5. **Gallery coverage rule**: If you add a new detection rule to `find_slop`,
   `check_logic_regression`, `detect_recursive_boilerplate`, or any manifest
   scanner, you MUST add a corresponding gallery entry to `crates/crucible/src/main.rs`
   BEFORE the implementation commit. Red-to-green: gallery entry first, then detector.

## Hard abort conditions

| Condition | Action |
|-----------|--------|
| Any `[FAIL]` with no resolution | Block — do not commit |
| Crucible fails to compile | Block — surface error |
| Gallery entry added without corresponding detector test | Block — testing mandate |

## Notes

- The Crucible also runs as a `#[test]` block inside `cargo test --workspace`
  (part of `just audit`). The skill enforces it explicitly for CI pre-flight
  and for any manual forge/anatomist edits within a session.
- "It compiles" is not equivalent to "it detects". The Crucible is the proof.
