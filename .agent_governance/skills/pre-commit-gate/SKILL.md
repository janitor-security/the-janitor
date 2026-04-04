# Skill: Pre-Commit Gate (Auto-Invoked)

**Trigger:** Whenever the user asks to commit, stage files, or finalize changes.

## Protocol

1. **Run `janitor_bounce` (MCP)** against the current diff:
   - Input: output of `git diff HEAD` (or the staged patch)
   - If `slop_score > 0`:
     - Read `antipattern_details` from the response
     - Report each violation to the user
     - **ABORT** — do not proceed with the commit
     - Ask the user to remediate each finding and re-invoke

2. **If `slop_score == 0`**, proceed to:
   - Run `just audit` (or confirm it has already passed in this session)
   - Only then finalize the commit

## Abort conditions

| Condition | Action |
|-----------|--------|
| `slop_score > 0` | Abort, report violations, request remediation |
| `just audit` fails | Abort, report failing check, do not commit |

## Notes

- This skill fires on every commit request without exception.
- The user may not bypass this gate by saying "skip the check" or "just commit."
- After remediation, re-run the full gate from Step 1.
