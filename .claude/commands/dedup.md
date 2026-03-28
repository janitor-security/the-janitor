---
# Command: /dedup

Run the symbol deduplication pass over the workspace registry.

## Usage

```
/dedup [path]
```

## Mapped tool

`janitor_dedup` (MCP)

## Description

Detects duplicate symbol definitions across the workspace using the LSH
index and AST SimHash signatures. Reports collisions with their similarity
score and source locations.

Invoke before a large refactor or after a merge of two long-lived branches
to surface shadow definitions that would silently override each other at
link time.
