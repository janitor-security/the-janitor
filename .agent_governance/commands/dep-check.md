---
# Command: /dep-check

Run the dependency health audit against the workspace manifest.

## Usage

```
/dep-check [path]
```

## Mapped tool

`janitor_dep_check` (MCP)

## Description

Audits `Cargo.toml` (and any nested workspace members) for:

- Zombie dependencies: declared but never imported in any source file
- Phantom calls: symbols imported from a dep that has no corresponding
  `use` path reachable from a public API
- Version silos: multiple incompatible versions of the same crate
  co-resident in the dependency graph

Output is a structured finding list per crate. Zombie deps are safe to
remove; silo findings require resolution or explicit documentation.
