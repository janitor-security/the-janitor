# Hunt Report: freedomofpress/securedrop-client

**Sprint**: Batch 95
**Date**: 2026-05-02
**Commit depth**: --depth 1

## Result: no_billable_findings

securedrop-client is a desktop Qt application for journalists.

### subprocess_shell_injection — client/scripts/verify-mo.py:112
- **Triage**: Identical pattern to securedrop main repo: `shell=True` in a
  devops verify-mo.py script for diffoscope, with explicit `# nosemgrep` /
  `# noqa: S602` suppression and documented rationale (inherit Python venv).
  Desktop application — not a remotely accessible service.
- **Approval %**: <10% — devops script, intentional design, requires local
  developer machine access.
- **Logged to BOUNTY_LEDGER**: No.
