---
# Command: /scan

Run a full dead-symbol scan of the workspace.

## Usage

```
/scan [path]
```

## Mapped tool

`janitor_scan` (MCP)

## Description

Executes the 6-stage dead-symbol pipeline via the Anatomist crate:

1. Grammar dispatch — routes each file to its tree-sitter parser
2. Symbol extraction — builds a `SymbolRegistry` of all definitions
3. Reference resolution — marks each symbol as live or dead
4. Manifest cross-check — correlates against `Cargo.toml` declarations
5. Protection evaluation — applies `JanitorPolicy` exemptions
6. Report generation — emits findings as `Entity` records

Results are written to `.janitor/symbols.rkyv` for dashboard consumption.
Run this after a large deletion pass to confirm no live symbols were
orphaned.
