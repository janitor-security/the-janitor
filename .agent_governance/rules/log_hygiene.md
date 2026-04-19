# Rule: The Absolute Eradication Law — Innovation Log Hygiene

The `.INNOVATION_LOG.md` file is a forward-looking roadmap of ACTIVE, UNBUILT
architecture. It is never a historical record. Completed work is not logged —
it is deleted.

## The Law

**THE ABSOLUTE ERADICATION LAW**: The `.INNOVATION_LOG.md` file must NEVER
contain completed items. You are forbidden from using `[COMPLETED]`,
`[COMPLETE]`, `[RESOLVED]`, `[DONE]`, `[SHIPPED]`, `[FIXED]`, `[LANDED]`,
strikethroughs (`~~text~~`), commented-out blocks, or any other tombstone
marker. When a feature is shipped, you MUST physically delete its entire
text block from the file — the heading, the gap description, the build
steps, the crate list, the deliverables, all of it. The log is for active,
unbuilt architecture only.

Soft deletion (tagging and leaving text in place) is a form of
procrastination. Hard deletion is the discipline.

## Rationale

A log that accumulates completed items becomes unreadable. Every agent
session then spends input tokens re-parsing dead context. Every operator
session risks mistaking a tombstoned item for open work. The commit
history, the release notes, and the memory system are the authoritative
sources for what was built, by whom, and when — the innovation log has
exactly one job: to state what is next.

A mixed log also corrupts recommendations: agents scanning a log that
contains `[COMPLETED]` markers start cherry-picking "close enough"
already-shipped work as the next action. A pure log forces the agent to
choose from real, open frontiers only.

## Protocol — Mandatory Every Session

Before finalizing any commit, and unconditionally before writing the
`[NEXT RECOMMENDED ACTION]` section of a summary:

1. Audit the innovation log for any block whose work was shipped in the
   current session (consult commit messages, release notes, memory).
2. **Delete** those blocks entirely, in the same commit that ships the
   feature. No strikethrough. No tag. No comment.
3. Reshape parent blocks that contained sub-items — if a parent covered
   three sub-phases and one shipped, remove that sub-phase entirely.
   Preserve the parent's identifier (do not renumber siblings); simply
   collapse the completed child out of existence.
4. Before the commit is authored, the file must contain ZERO completion
   markers. Verify with a literal-string search for:
   `[COMPLETED]`, `[COMPLETE]`, `[RESOLVED]`, `[DONE]`, `[SHIPPED]`,
   `[FIXED]`, `[LANDED]`, `~~`.
   Any match is a blocking violation — delete the offending block
   before proceeding.

## Enforcement

- A commit that introduces any completion marker in `.INNOVATION_LOG.md`
  is a governance violation equivalent to a non-zero `slop_score`.
- A commit that ships a feature without deleting its corresponding
  innovation-log block is **incomplete**. The feature commit and the
  log deletion are a single atomic unit — they must ship together, in
  the same commit.
- The final substantive summary for every directive MUST verify that the
  innovation log is free of completion markers, and state that
  verification in `[EXECUTION STATUS]`, before the directive is
  considered closed.

## Scope

This rule governs `.INNOVATION_LOG.md` specifically. It does NOT apply
to:

- `docs/CHANGELOG.md` — historical by design.
- Commit messages, release notes, GitHub Releases — historical by design.
- Memory system entries under `~/.claude/projects/.../memory/` —
  historical by design.
- `CHANGELOG.md` files — historical by design.

The innovation log is the only file bound by the Absolute Eradication
Law, because it is the only file with a forward-looking-only mandate.

## Cross-reference

- `.agent_governance/rules/evolution.md` — constitutional evolution gate
  (pair: every deletion from the log presupposes a structural gate now
  present in the code, not silence).
- `.agent_governance/rules/response-format.md` — the
  `[NEXT RECOMMENDED ACTION]` section cannot cite a completed item,
  because no completed items exist in the log by construction.
