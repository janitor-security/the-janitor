---
# Command: /generate-client

Run a single-repo forensic audit and produce a self-contained client
package with PDF report, CSV data, and CycloneDX SBOM.

## Usage

```
/generate-client <owner/repo>
```

## Mapped script

```bash
tools/generate_client_package.sh <owner/repo>
```

## Description

Produces a self-contained client package directory containing 7 artifacts:

- `gauntlet_intelligence_report.pdf` — Narrative threat report with
  executive summary, threat distribution, and top-10 findings table
- `gauntlet_export.csv` — Full 17-column per-PR data export
- `gauntlet_report.json` — Machine-readable bounce log (NDJSON)
- `<repo>_cbom.json` — CycloneDX v1.5 Code Bill of Materials
- `<repo>_intel.json` — Structured intelligence summary
- `<repo>_vex.json` — Vulnerability Exploitability Exchange document
- `case-study.md` — Human-readable case study narrative

The package is zero-upload: all analysis runs locally via the Janitor binary.
No source code or PR content leaves the machine.

## Prerequisites

`pandoc`, `texlive` (with `titlesec`, `tocloft`, `xfp`, `framed` packages),
`jq`, `bc` in PATH. Run inside the Nix devShell (`just shell`).
