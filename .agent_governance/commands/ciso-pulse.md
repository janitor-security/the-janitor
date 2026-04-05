# Command: /ciso-pulse

Execute the Hard Compaction audit on `docs/INNOVATION_LOG.md`.

## Usage

```
/ciso-pulse
```

## Mapped action

Hard Compaction of `docs/INNOVATION_LOG.md` per Logic 5 of
`.agent_governance/skills/evolution-tracker/SKILL.md`.

## Protocol (execute in order)

1. **Read `docs/INNOVATION_LOG.md` in full.**
2. **Delete all completed work immediately.**
   - Delete every entry marked `[COMPLETED]`.
   - Delete all resolved telemetry (`CT-NNN` entries whose fixes are merged).
   - Delete all `## Continuous Telemetry — YYYY-MM-DD` section blocks.
3. **Delete all legacy IDs.**
   - Drop every `IDEA-XXX` and `CT-XXX` identifier inline label.
   - Do not preserve old numbering as aliases.
4. **Re-tier every remaining active entry** into P0 / P1 / P2:
   - **P0 — Enterprise Security Depth**: grammar rules, KEV gates, CVSS ≥ 9.0.
   - **P1 — Compliance / Zero-Upload**: SCM portability, FedRAMP/DISA STIG paths.
   - **P2 — Operational / CLI Ergonomics**: DX improvements, performance, tooling.
5. **Merge redundant entries.** Two entries describing the same change become one
   with the stronger proposal text.
6. **Drop low-value noise.** Cosmetic cleanups, speculative non-security ideas,
   or entries with no concrete implementation path are deleted.
7. **Add Grammar Depth entries** for any language with fewer than 3 AST-level
   detection rules. Grammar depth is always P0.
8. **Hard-compact the file** — rewrite with only active items, re-indexed to
   clean `P0-N`, `P1-N`, `P2-N` numbering.
9. **Commit the rewritten log** in the same commit as the current directive.

## CI gate (enforced in `justfile::fast-release`)

`fast-release` blocks if `grep -c "CT-" docs/INNOVATION_LOG.md` ≥ 10.
Run `/ciso-pulse` to compact the log before releasing.
