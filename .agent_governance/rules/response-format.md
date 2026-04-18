# Rule: Mandatory Response Format

Every response to an operator directive MUST follow the five-section structure
below. No other top-level structure is acceptable.

## The Law

During active execution (reading files, compiling, fixing bugs, waiting on
tests, or patching), agents MAY use natural, concise status updates such as
`Running tests...`, `Failed on line 12. Patching...`, or `Release push in
progress.`  These interim updates must stay brief and operational.

The five-section structure below is reserved strictly for the **final summary**
after the directive is complete and any requested `/release` has been triggered.
Do **not** use it for intermediate execution updates.

All final substantive summaries (implementation, release, audit, research) must
be organized into the following five named sections, in order:

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
Direct-triage backlog changes logged this session. Format:
- P0/P1/P2 item created, compacted, or completed with one-line rationale
If none: <!-- no triage changes this session -->

## [NEXT RECOMMENDED ACTION]
The single highest-priority actionable item from `.INNOVATION_LOG.md`.
State: the P0/P1/P2 ID, the file to modify, the function to change, the exact
command to begin, and the commercial justification. No vague "consider"
language — name the action and quantify the TAM / TEI expansion unlocked.
The Next Recommended Action MUST exclusively propose the next logical P0 or P1
implementation task directly from `.INNOVATION_LOG.md`, providing the file
paths and a brief commercial justification.
Explicitly forbid manual operator shell guidance in this section. Do not
suggest manual git commands, staging, signing, `/compact`, or other workflow
rituals. The section is for implementation sequencing only.

## [SOVEREIGN TRANSLATION]
A terminal-only operator brief. Never write this section into markdown logs or
backlog files. It must explain the implementation in layman's executive terms
and explicitly answer:
1. What did we just build?
2. Why does the CISO care?
3. How does this make money or crush competitors?
```

## Enforcement

- Conversational responses (e.g., "what does X do?") are exempt from this
  structure.
- Interim execution updates during an active directive are exempt and should
  use concise natural language.
- Final directive summaries (any session that modifies files or runs commands)
  are NOT exempt. The format is non-negotiable.
- The `[NEXT RECOMMENDED ACTION]` section MUST cite a specific entry from
  `.INNOVATION_LOG.md` and state the commercial justification — it is not
  a free-form opinion.
- The `[NEXT RECOMMENDED ACTION]` section MUST NOT recommend manual git
  commands, release commands, or operator housekeeping steps.
- The `[SOVEREIGN TRANSLATION]` section is mandatory for final directive
  summaries and must remain terminal-only.

## Anti-Recency-Bias Law (mandatory for `[NEXT RECOMMENDED ACTION]`)

You MUST scan the **entire** `.INNOVATION_LOG.md` — P0, P1, and P2 — before
selecting the next action.  Do NOT default to the section you just edited or the
last file you touched.

**Selection criterion:** the single entry with the highest commercial Total
Addressable Market (TAM) expansion, Total Economic Impact (TEI), or most
critical enterprise compliance upgrade. TEI is assessed as:
(detection severity × addressable language market share × number of open CVEs
in class). A KevCritical rule in Go or Python outranks a P2 ergonomics fix in
every scenario unless the P2 item unlocks materially larger market access.

**Hard rule:** if the current session touched a P1 or P2 item, the next action
MUST still be the highest-value P0 entry unless all P0 entries are marked
`[COMPLETED]`.  Recency is not a selection criterion.
