---
# Command: /publish-audit

Execute a full forensic strike and publish the evidence to the public
`janitor-security` GitHub organization.

## Usage

```
/publish-audit <owner/repo>
```

## Mapped script

```bash
tools/publish_forensic_strike.sh <owner/repo>
```

## Description

Executes four atomic operations in sequence:

1. **Strike** — Runs `just strike <repo> 1000` to produce 7 evidence
   artifacts in `strikes/<repo_name>/`:
   - `gauntlet_intelligence_report.pdf`
   - `gauntlet_export.csv`
   - `gauntlet_report.json`
   - `<repo>_cbom.json` (CycloneDX v1.5)
   - `<repo>_intel.json`
   - `<repo>_vex.json`
   - `case-study.md`

2. **Provision** — Creates a new public GitHub repository at
   `janitor-security/<repo_name>-audit-<YYYY>` via the `gh` CLI.

3. **Publish** — Initializes a fresh git history from the artifacts
   (`case-study.md` → `README.md`), commits, and force-pushes.

4. **Index** — Appends a markdown link to `docs/intelligence.md` on the
   main website for the Intelligence Reports index.

## Environment overrides

| Variable | Default | Purpose |
|----------|---------|---------|
| `PR_LIMIT` | `1000` | Number of PRs to scan |
| `STRIKES_DIR` | `./strikes` | Output directory |
| `AUDIT_ORG` | `janitor-security` | GitHub org for published repo |
| `SKIP_STRIKE` | unset | Set to `1` to reuse existing artifacts |

## Prerequisites

`gh` CLI (authenticated), `git`, `jq`, `bc`, `pandoc`, `texlive` in PATH.
Run inside the Nix devShell (`just shell`) to satisfy all prerequisites.
