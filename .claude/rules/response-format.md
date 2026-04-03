# Rule: Mandatory Response Format

Every response to an operator directive MUST follow the four-section structure
below. No other top-level structure is acceptable.

## The Law

All substantive responses (implementation, release, audit, research) must be
organized into the following four named sections, in order:

```
## [EXECUTION STATUS]
Pass / Fail summary of the directive. One sentence per task. Mark each
sub-task with ✓ (completed), ✗ (failed), or ⏳ (pending / in-progress).

## [CHANGES COMMITTED]
Table of all files modified, created, or deleted in this session.

| File | Action | Description |
|------|--------|-------------|
| path/to/file | modified | brief description |

If no code was committed (research-only session), state "No code committed."

## [TELEMETRY]
CT findings logged this session. Format:
- CT-NNN: <one-line summary> (location, priority)
If none: <!-- no telemetry findings this session -->

## [NEXT RECOMMENDED ACTION]
The single highest-priority actionable item from `docs/INNOVATION_LOG.md`.
State: the IDEA/VULN/CT ID, the file to modify, the function to change, and
the exact command to begin. No vague "consider" language — name the action.
```

## Enforcement

- Conversational responses (e.g., "what does X do?") are exempt from this
  structure.
- Directive responses (any session that modifies files or runs commands) are
  NOT exempt. The format is non-negotiable.
- The `[NEXT RECOMMENDED ACTION]` section MUST cite a specific entry from
  `docs/INNOVATION_LOG.md` — it is not a free-form opinion.
