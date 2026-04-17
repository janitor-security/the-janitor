# Universal Agent Protocol (UAP) — Shared Governance Layer

This directory is the canonical source for all governance rules, commands,
and skills. It is agent-agnostic: Claude Code, Codex, and any other
AI agent operating in this repository MUST read this directory on startup
to understand operating constraints.

## Directory Structure

| Path | Purpose |
|------|---------|
| `rules/` | Hard laws governing code quality, memory, testing, security, deployment |
| `commands/` | Slash-command definitions (`/release`, `/audit`, `/scan`, etc.) |
| `skills/` | Auto-invoked skill protocols (pre-commit gate, crucible enforcement, etc.) |

## Agent Bootstrap Instructions

**For all agents (Claude Code, Codex, GPT-4o, etc.):**

1. Read `rules/` — all `.md` files are mandatory constraints. Violations block commits.
2. Read `commands/` — these define the canonical release, audit, and strike workflows.
3. Read `skills/` — SKILL.md files define auto-invoked protocols that fire on specific events.

## Shared Ledgers

Both agents share and MUST maintain:
- `docs/CHANGELOG.md` — append-only log of every major directive
- `.INNOVATION_LOG.md` — forward-looking architectural insights (P0/P1/P2)

When completing a directive, BOTH agents must append to these logs before
finalizing any commit. The ledgers are the authoritative record of the
system's evolution — never let them fall out of sync.

## Compatibility Note

`.claude/rules`, `.claude/commands`, and `.claude/skills` are symlinks that
resolve to this directory. Claude Code reads from `.claude/` via those symlinks.
All edits must be made here in `.agent_governance/` — never in the symlink stubs.
