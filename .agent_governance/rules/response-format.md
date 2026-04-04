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

## Anti-Recency-Bias Law (mandatory for `[NEXT RECOMMENDED ACTION]`)

You MUST scan the **entire** `docs/INNOVATION_LOG.md` — P0, P1, and P2 — before
selecting the next action.  Do NOT default to the section you just edited or the
last file you touched.

**Selection criterion:** the single entry with the highest commercial Total
Economic Impact (TEI) or the most critical enterprise compliance upgrade.
TEI is assessed as: (detection severity × addressable language market share ×
number of open CVEs in class).  A KevCritical rule in Go or Python outranks a
P2 ergonomics fix in every scenario.

**Hard rule:** if the current session touched a P1 or P2 item, the next action
MUST still be the highest-value P0 entry unless all P0 entries are marked
`[COMPLETED]`.  Recency is not a selection criterion.
