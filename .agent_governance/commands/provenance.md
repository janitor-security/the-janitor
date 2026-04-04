---
# Command: /provenance

Run the Gatekeeper Provenance zero-upload proof ledger.

## Usage

```
/provenance <path>
```

## Mapped tool

`janitor_provenance` (MCP)

## Description

Generates a cryptographic provenance manifest for a file or directory tree.
Each entry is a SHA-256 content digest bound to a monotonic timestamp and
the current policy hash. The result is a tamper-evident audit chain that
proves the codebase state at review time without uploading any content.

Use this before a release cut or compliance snapshot to produce an
unforgeable record of what was shipped.
