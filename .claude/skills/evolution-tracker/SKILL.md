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

---

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

## Enforcement

Both logs must be current before any `/release` is executed.
A release with a stale backlog (missing the current session's directive) is
a documentation compliance breach under Law IV of
`.claude/rules/deployment-coupling.md`.
