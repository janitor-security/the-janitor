# Rule: Context Asceticism — Token Governance

The operator's API budget is a finite, strictly rationed resource.
Every token burned on orientation, exploration, or verbose output is waste.

## The Four Laws

### Law I — No Exploration

You are strictly forbidden from spawning sub-agents, using open-ended
`grep`/`find`, or running broad workspace scans to orient yourself.
You must only read the exact file paths provided by the operator or
explicitly required by a stack trace.

**Permitted reads**: files named in the directive, files cited in a
compiler error, files whose paths you already know from prior context.

**Forbidden**: `Glob("**/*")`, `Grep` with speculative patterns across
the whole workspace, `Agent` with `subagent_type=Explore`, or any tool
call whose purpose is "let me see what's here".

### Law II — Fail-Fast on Ambiguity

If a directive lacks specific file paths and you do not know exactly
where the target code lives, **DO NOT guess and DO NOT search the
repository**. Abort the operation immediately and ask the operator for
the exact paths.

The cost of a wrong guess (reading 3 wrong files, then the right one)
is 4× the cost of a single targeted read.  The cost of asking is zero.

### Law III — Context Compaction

After successfully completing any multi-step directive or `just release`,
you **MUST** remind the operator:

> Run `/compact` now to purge dead context memory.

Stale context from completed directives consumes input tokens on every
subsequent turn without contributing any information.  Compaction is
mandatory hygiene, not optional.

### Law IV — Ascetic Payload

Never read `Cargo.lock` or `gauntlet_report.json` into your context
window unless you are explicitly debugging a **Version Silo** or an
**Actuarial calculation**.

These files are large, dense, and almost never the source of the issue
being investigated.  Reading them by default bloats the context window
with hundreds of dependency lines that contribute no signal.

## Enforcement checklist

- [ ] No `Glob` or `Grep` calls without an exact target path
- [ ] No `Agent` spawns for orientation or exploration
- [ ] Operator reminded to `/compact` after every completed directive
- [ ] `Cargo.lock` / `gauntlet_report.json` not read unless explicitly required
