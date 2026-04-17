# Command: /ciso-pulse

Execute the Hard Compaction audit on `.INNOVATION_LOG.md`.

## Usage

```
/ciso-pulse
```

## Mapped action

Hard Compaction of `.INNOVATION_LOG.md` per the Direct Triage Law:
every active item must be tiered P0/P1/P2 with no legacy numbering.

## Protocol (execute in order)

1. **Read `.INNOVATION_LOG.md` in full.**
2. **Delete all completed work immediately.**
   - Delete every entry marked `[COMPLETED]`.
   - Delete all `## Continuous Telemetry` section blocks and resolved entries.
3. **Re-tier every remaining active entry** into P0 / P1 / P2:
   - **P0 — Enterprise Security Depth**: grammar rules, KEV gates, CVSS ≥ 9.0.
   - **P1 — Compliance / Zero-Upload**: SCM portability, FedRAMP/DISA STIG paths.
   - **P2 — Operational / CLI Ergonomics**: DX improvements, performance, tooling.
4. **Merge redundant entries.** Two entries describing the same change become one
   with the stronger proposal text.
5. **Drop low-value noise.** Cosmetic cleanups, speculative non-security ideas,
   or entries with no concrete implementation path are deleted.
6. **Add Grammar Depth entries** for any language with fewer than 3 AST-level
   detection rules. Grammar depth is always P0.
7. **Hard-compact the file** — rewrite with only active items, re-indexed to
   clean `P0-N`, `P1-N`, `P2-N` numbering. No legacy `IDEA-` or `CT-` labels.
8. **Commit the rewritten log** in the same commit as the current directive.

## CI gate (enforced in `justfile::fast-release`)

`fast-release` verifies the log contains only P0/P1/P2 triage entries.
Run `/ciso-pulse` if the log has grown stale before releasing.
