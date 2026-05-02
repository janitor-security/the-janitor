# Rule: Mandatory Response Format

Every final response to an operator directive MUST follow the strict four-part
summary plus terminal-only translation structure below. No other top-level
structure is acceptable.

## The Law

During active execution (reading files, compiling, fixing bugs, waiting on
tests, or patching), agents MAY use natural, concise status updates such as
`Running tests...`, `Failed on line 12. Patching...`, or `Release push in
progress.`  These interim updates must stay brief and operational.

Long-running command discipline is mandatory. After starting a known long
command (`just audit`, `cargo test --workspace`, `/release`, `/strike`, or any
build/test expected to exceed 60 seconds), agents MUST NOT repeatedly poll at
short intervals and stream incremental command output. Use long waits of at
least 60 seconds between status reads, emit at most one concise human status
update per wait cycle, and summarize the final result only after the process
exits. Constant polling is token waste and is a governance violation.

The four-part structure below is reserved strictly for the **final summary**
after the directive is complete and any requested `/release` has been triggered.
Do **not** use it for intermediate execution updates.

You are mathematically forbidden from emitting raw tool-call artifacts (e.g.,
`::git-stage`, `::git-commit`, `<function_calls>`) in the final terminal
output. Translate all tool results into human-readable telemetry.

All final substantive summaries (implementation, release, audit, research) must
be organized into the following named sections, in order:

```
[EXECUTION STATUS]
Pass / Fail summary of the directive. One sentence per task. Mark each
sub-task with ✓ (completed), ✗ (failed), or ⏳ (pending / in-progress).

[CHANGES STAGED]
Table of all files modified, created, staged, or committed in this session.

| File | Action | Description |
|------|--------|-------------|
| path/to/file | modified | brief description |

If no code was staged or committed (research-only session), state "No code
staged."

[TELEMETRY]
Direct-triage backlog changes logged this session. Format:
- P0/P1/P2 item created, compacted, or completed with one-line rationale
If none: <!-- no triage changes this session -->

[NEXT RECOMMENDED ACTION]
TWO distinct, high-priority actionable items from `.INNOVATION_LOG.md`.
Item 1 must be the absolute highest commercial-priority frontier (highest
TAM × severity × addressable language market share). Item 2 must be
orthogonally related or synergistic — implementable in the same sprint to
maximize context-window token efficiency.

For each item state: the P0/P1/P2 ID, the file to modify, the function to
change, the exact command to begin, and the commercial justification. No vague
"consider" language — name the action and quantify the TAM / TEI expansion
unlocked.
Both items MUST be drawn directly from `.INNOVATION_LOG.md`, providing the
file paths and brief commercial justification.
Explicitly forbid manual operator shell guidance in this section. Do not
suggest manual git commands, staging, signing, `/compact`, or other workflow
rituals. The section is for implementation sequencing only.

**Pre-flight — Absolute Eradication Law**: before writing this section,
verify `.INNOVATION_LOG.md` contains ZERO completion markers
(`[COMPLETED]`, `[COMPLETE]`, `[RESOLVED]`, `[DONE]`, `[SHIPPED]`,
`[FIXED]`, `[LANDED]`, or `~~strikethrough~~`). If any remain from the
current session's shipped work, physically delete those blocks first,
then re-read the log to select the true highest-value frontier. See
`.agent_governance/rules/log_hygiene.md`. By construction, every entry
still in the log is unbuilt — the NRA selects from open frontiers only.

[SOVEREIGN TRANSLATION]
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
- Final directive summaries MUST NOT contain raw tool-call artifacts, function
  call XML, app directives, git UI directives, or machine-control sentinels.
- The `[NEXT RECOMMENDED ACTION]` section MUST cite a specific entry from
`.INNOVATION_LOG.md` and state the commercial justification — it is not
a free-form opinion.
- The `[NEXT RECOMMENDED ACTION]` section MUST NOT recommend manual git
commands, release commands, or operator housekeeping steps.
- The 8GB Law: The operator runs an 8GB Dell Inspiron. You are
  mathematically forbidden from recommending or implementing P2-4 Tier 3
  (Headless Ghidra), JVM subprocesses, or massive ML inference (e.g., local
  LLM hosting) as the `[NEXT RECOMMENDED ACTION]`. You must prioritize pure
  Rust, zero-copy, low-memory AST/IFDS operations.
- The `[SOVEREIGN TRANSLATION]` section is mandatory for final directive
summaries and must remain terminal-only.

## Bounty Extraction Law (mandatory for all hunt/scan output review)

When reviewing `janitor hunt` output, a finding is weaponized ONLY if it possesses
a concrete reproduction payload, `repro_cmd`, or generated HTML harness — NOT `Pending`.

For every weaponized finding you MUST:
A. Cross-reference the finding against its parent program's rules in
   `tools/campaign/targets/<program>_targets.md`.
B. Verify the target is strictly IN SCOPE.
C. Extract the estimated payout for the finding's severity.
D. Append a structured entry to `tools/campaign/BOUNTY_LEDGER.md` with:
   `[Date]`, `[Target URL/Repo]`, `[Vulnerability Class]`, `[Severity]`,
   `[Expected Payout]`, `[Estimated Approval % (>85% if payload exists)]`,
   `[Exact Repro Command]`, and `[Remediation / Exploitation Strategy]`.

If a finding requires a `[lattice-gap: P-XX]` annotation because the IFDS solver
cannot trace a specific framework, protocol, or memory bound, you MUST
simultaneously create a detailed architectural proposal for that `P-XX` item in
`.INNOVATION_LOG.md`. The bounty ledger is the symptom; the innovation log is
the cure. The proposal must name the missing lattice element, the Rust module to
extend, the deterministic proof strategy, and the true-positive / true-negative
fixture pair required to close the gap.

### Threat Model Awareness (mandatory threat model pre-filter)

You MUST evaluate the **Taint Source Origin** and **Actor Privilege Level** BEFORE
logging any finding to the Bounty Ledger or including it in a hunt report.

- A finding that requires **local config modification**, **env var control**, or
  **Admin privileges** is NOT remotely exploitable. `Approval % < 10%`.
- A finding in **client-side TypeScript/JavaScript** where the sink is a
  `fetch()` / `XMLHttpRequest` / `axios` call is NOT server-side SSRF. Client-side
  HTTP calls are blocked by SOP/CORS. Requires proof of a **server-side execution
  path** (SSR, Next.js API route, Node.js backend). Without it: `Approval % < 10%`.
- **Self-XSS** (victim must trigger the payload themselves without any third-party
  attack vector): `Approval % < 10%`.

For every entry with `Approval % < 10%`, either append an explicit
**Exploitation Strategy** (how to elevate to >85%) or DELETE the entry.
Unviable entries must NOT remain in the ledger.

## Structural Eradication Law (mandatory for all hunt/scan output review)

You are mathematically forbidden from appending Markdown notes or prose to explain
away a False Positive in a hunt report.  Suppress a Commercial False Positive ONLY
by writing a deterministic Rust AST/path guard in `crates/cli/src/hunt.rs` or
`crates/forge/src/slop_hunter.rs` that eradicates the finding from the output.
The report must be completely devoid of the suppressed finding — no footnotes, no
`---` suppression blocks, no explanatory prose.

Required action on a Commercial False Positive:
1. Write an `is_excluded_hunt_entry` path guard or a detector-level context filter
   in `slop_hunter.rs` that prevents the finding from being emitted.
2. Re-run `janitor hunt` and confirm the finding is absent.
3. Never append a suppression explanation to the report.

The exception: `security:credential_leak` in any directory is always billable — a
secret in a repo is a secret in a repo.

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
MUST still be the highest-value P0 entry that remains in the log. Recency is
not a selection criterion. Under the Absolute Eradication Law, a P0 entry
that has been completed is already deleted from the log, not tagged — so the
selection universe at any moment is exactly the set of open P-entries
present in the file.

## Absolute Eradication Pre-Flight (reminder)

Before emitting `[NEXT RECOMMENDED ACTION]`, perform the check defined in
`.agent_governance/rules/log_hygiene.md`:

1. Did the current session ship any feature that is still described in
   `.INNOVATION_LOG.md`?
2. If yes, physically delete the corresponding block(s) in the same
   commit that ships the feature. Do NOT tag, strikethrough, or comment
   them out. Hard-delete only.
3. Re-read the purged log before selecting the next action.

A `[NEXT RECOMMENDED ACTION]` authored over a log that still contains
tombstoned completed work is a governance violation. The log and the
recommendation are a single atomic artifact.
