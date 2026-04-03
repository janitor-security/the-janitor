# Skill: Evolution Tracker (Auto-Invoked)

**Trigger:** At the conclusion of every session, major directive, or
significant code audit.

---

## Logic 1 — The Backlog

At the conclusion of every session or major directive, append a dated entry to
`docs/IMPLEMENTATION_BACKLOG.md` with the following structure:

```markdown
## YYYY-MM-DD — <Directive Name>

**Directive:** <One-sentence summary of the prompt received>

**Files modified:**
- `path/to/file` *(created|modified|deleted)* — brief description

**Commit:** `<sha>`
```

**Rules:**
- Append only — never overwrite or reorder existing entries.
- Entry must be committed in the same commit as the directive's changes, or
  in an immediately following cleanup commit.
- If a directive spans multiple commits, record each commit SHA in the entry.

---

## Logic 2 — The Innovation Log

During code audits, whenever you identify any of the following, append a dated
entry to `docs/INNOVATION_LOG.md`:

- A structural gap (missing detector, uncovered language construct, blind spot)
- An inefficient algorithm (O(n²) where O(n log n) is achievable)
- A missing test (detection path with zero regression coverage)
- A feature expansion that would meaningfully advance the threat model
- A wild architectural pivot or new security paradigm — do not self-censor

Entry structure:

```markdown
### IDEA-NNN: <Title>

**Class:** <Core Engine | Threat Intelligence | Defensive Hardening | Architecture | Wild Pivot>
**Priority:** <P0 | P1 | P2>
**Inspired by:** <file or directive that surfaced the idea>

**Observation:** <What gap or inefficiency was identified>

**Proposal:** <Concrete description of the change>

**Security impact:** <What threat it neutralizes or coverage it adds>

**Implementation path:** <Specific files and functions to modify>
```

**Rules:**
- Do not limit scope — include both incremental improvements and radical ideas.
- Assign sequential IDEA-NNN IDs (check the last entry for the current count).
- Append only — never overwrite or remove prior ideas.
- Do not implement ideas from this log without an explicit operator directive.
  The log is a proposal registry, not a work queue.

### Forward-Looking Mandate (non-negotiable)

**You MUST NOT log completed work, bug fixes, or recently implemented features
in `docs/INNOVATION_LOG.md`.** Completed work belongs exclusively in
`docs/IMPLEMENTATION_BACKLOG.md`.

If a finding is resolved in the same session it is identified, record it in
the Backlog entry for that session — not in the Innovation Log. The Innovation
Log is a forward-looking proposal registry. An entry that describes something
already done is noise, not signal.

### Architectural Radar Mandate

`docs/INNOVATION_LOG.md` is strictly for **future R&D**. As you scan the
codebase during a session, you must actively search for the following classes
of forward-looking proposals and append them as actionable, technical entries:

a) **Unhandled edge cases in the AST parsers** — language constructs that
   exist in the grammar but have no detector; inputs that could cause a parser
   to silently succeed with a wrong parse tree.

b) **Missing security patterns from modern threat landscapes** — exploit
   classes documented in recent CVEs, CISA KEV updates, or public post-mortems
   that have no corresponding gate in `slop_hunter.rs`, `binary_hunter.rs`, or
   the manifest scanners.

c) **Inefficiencies in the Rust implementation** — redundant heap allocations
   in hot paths, missed SIMD opportunities, lock contention in the daemon,
   O(n²) algorithms where a faster bound is achievable.

d) **Flaws or missing safeguards in `.claude/` rules** — governance gaps,
   ambiguous mandates, rules that conflict with each other, or missing
   enforcement checklists for known failure modes.

Each proposal must be concrete and technical: name the file, the function, the
threat class, and the proposed fix. Vague observations are not entries.

---

## Logic 3 — Continuous Telemetry (Mandatory on Every Prompt)

**On EVERY prompt received**, as you read the codebase to formulate a
solution, you MUST actively scan for:

- Undocumented technical debt (hacks, workarounds, deferred fixes)
- Missing test coverage (detection paths with zero `#[test]` blocks)
- Architectural bottlenecks (O(n²) algorithms, unbounded allocations, lock
  contention in hot paths)
- Security blind spots introduced or exposed by the current change

If any finding is identified, append it to `docs/INNOVATION_LOG.md` under a
`## Continuous Telemetry` section **before concluding the session**.

Entry format:

```markdown
## Continuous Telemetry — YYYY-MM-DD

### CT-NNN: <Short title>
**Found during:** <directive name>
**Location:** `crates/foo/src/bar.rs:LL`
**Issue:** <description>
**Suggested fix:** <concrete remediation>
```

**Absolute mandate:** This scan is not optional and is not waived by
directive scope. Even a one-line fix can surface a CT entry. If nothing is
found, explicitly note `<!-- no telemetry findings this session -->` in the
INNOVATION_LOG so the absence of findings is recorded, not silently skipped.

---

---

## Logic 4 — Auto-Purge (Completed Sections)

**Trigger:** After marking any finding `[COMPLETED — vX.Y.Z]` in
`docs/INNOVATION_LOG.md`, immediately scan its parent H2/H3 section.

**Rule:** If **ALL** named findings within the parent section are marked
`[COMPLETED — ...]`, **DELETE the entire parent section** — H2/H3 header and
all content down to (but not including) the next H2/H3 boundary. The Innovation
Log must contain only active or partially-active debt. Completed sections are
dead weight and will accumulate into noise if not purged.

**Scope:** H2 and H3 sections with named findings (VULN-NNN, IDEA-NNN, CT-NNN).
Structural sections such as the preamble, summary tables, and the `Roadmap
Summary` table are exempt from purging.

**Protocol:**
1. Count the total named findings under the parent section.
2. Count the findings marked `[COMPLETED — ...]`.
3. If count matches: delete the section from `docs/INNOVATION_LOG.md`.
4. Record the deletion in the current session's Backlog entry under a
   `**Purged sections:**` sub-item.

**Example:** If `## Enterprise Compliance Gaps` contains VULN-01 through
VULN-04 and all four are `[COMPLETED]`, delete the entire
`## Enterprise Compliance Gaps` block including the roadmap summary table
embedded within it.

---

---

## Logic 5 — CISO Pulse Audit (CT-10 Rule)

**Trigger:** Either of these conditions is true:
1. The Continuous Telemetry (CT) counter reaches a **multiple of 10** (e.g.,
   CT-010, CT-020, CT-030).
2. `docs/INNOVATION_LOG.md` has **0 active items** after an Auto-Purge sweep.

**Action:** Halt standard execution. Perform a full CISO Pulse Audit before
proceeding with any other work.

### CISO Pulse Audit Protocol

1. **Read `docs/INNOVATION_LOG.md` in full.**
2. **Re-tier every entry** into one of three priority buckets:
   - **P0 — Enterprise Security Depth**: grammar rules, KEV gates, threat
     detection expansion, CVSS ≥ 9.0 blast radius. These are the entries
     that would close a CISO's critical-risk register.
   - **P1 — Compliance / Zero-Upload**: SCM portability, regulatory
     certification paths (FedRAMP, DISA STIG), local-only processing
     guarantees. These are the entries that unlock regulated-market deals.
   - **P2 — Operational / CLI Ergonomics**: developer-experience improvements,
     performance wins, internal tooling. These have value but are never the
     reason an enterprise selects a security product.
3. **Merge redundant ideas.** If two entries describe variations of the same
   change (e.g., "add Java SQLi AST gate" and "promote Java byte-level SQLi
   to AST"), merge them into a single entry with the stronger proposal.
4. **Drop low-value noise.** If an entry describes a cosmetic cleanup, a
   note about an internal script, or a speculative idea with no concrete
   security impact, delete it. The log is a CISO-facing signal board, not
   a scratch pad.
5. **Add Grammar Depth entries for any language with fewer than 3 AST-level
   detection rules.** Grammar depth is always P0. Name the rule, the AST
   node, the CVE class, and the file to modify.
6. **Rewrite `docs/INNOVATION_LOG.md`** in the new P0/P1/P2 structure.
7. **Append a `## Continuous Telemetry` section** for the current session.
8. **Commit the rewritten log** and continue with the original directive.

### Enforcement

A CISO Pulse Audit overrides the append-only rule for this specific
rewrite operation. Merged, dropped, and reorganized entries do not
require individual `[COMPLETED]` markers — the commit history is the audit
trail. Record the rewrite in the Backlog entry for the session.

---

## Enforcement

Both logs must be current before any `/release` is executed.
A release with a stale backlog (missing the current session's directive) is
a documentation compliance breach under Law IV of
`.claude/rules/deployment-coupling.md`.
