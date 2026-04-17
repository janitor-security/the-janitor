# Rule: Symmetric Failure — Shell Script Discipline

Every shell script MUST open with `set -euo pipefail`. No exceptions.

Silent failure is a defect. Unset variables must cause immediate abort.

## Scope

This applies to:
- All files under `tools/`
- `action.yml` run blocks
- Any inline shell steps in CI workflows
- Any bash heredoc executed at runtime

## Enforcement checklist

- [ ] Script opens with `set -euo pipefail` on the first non-comment line
- [ ] No unquoted variable expansions that could silently expand to empty
- [ ] Pipe failures propagate (`pipefail` is set)
- [ ] Exit codes from sub-commands are checked where the result matters
