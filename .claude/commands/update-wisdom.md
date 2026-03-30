---
# Command: /update-wisdom

Synchronize the local Wisdom Registry with the latest Janitor Sentinel rules,
then run the Autonomous KEV Ingestion pipeline.

## Usage

```
/update-wisdom
```

## Mapped command (registry sync)

```bash
janitor update-wisdom
```

## Full Protocol (two-phase)

### Phase A — Wisdom Registry Sync

Downloads the current `wisdom.rkyv` archive from
`https://api.thejanitor.app/v1/wisdom.rkyv` and writes it to
`.janitor/wisdom.rkyv` in the current repository root.

The Wisdom Registry is a compiled rkyv binary produced by the `wisdom-bake`
tool. It contains:
- `ImmortalityRule` entries — symbols that must never be deleted (framework
  entry points, decorated exports, test fixtures)
- `MetaPattern` entries — language-specific markers for protection heuristics

The daemon (`janitor serve`) hot-reloads this file via `HotRegistry`
(arc-swap). Updates take effect on the next scan cycle without restart.

### Phase B — Autonomous KEV Ingestion

Immediately after the registry sync, execute the KEV ingestion protocol
defined in `.claude/skills/cve-ingestion/SKILL.md`.

**Summary of Phase B steps**:
1. Fetch `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
2. Filter to grammars supported by `crates/polyglot/src/lib.rs`
3. Cross-reference against existing gates in `slop_hunter.rs`
4. Propose structural gates for uncovered KEV entries
5. Implement operator-approved gates + Crucible verification
6. Deploy via `/release` if new gates were added

The full protocol is authoritative. This summary is a navigation aid only.

## When to run

- After a `janitor release` to pull in new protection rules from the Sentinel.
- Weekly cadence (CISA publishes KEV updates continuously).
- When `cargo test` reports unexpected false positives in the dead-symbol
  pipeline (stale local registry).
- Before running a gauntlet against a new tech stack (e.g., first Rails or
  Spring Boot audit).
- After any CISA KEV alert lands in a language covered by the engine's grammar
  registry — do not wait for the weekly cycle.

## Governance

Phase B is governed by the Scanner Sovereignty Law and Credential Detection
Sovereignty Law in `.claude/rules/evolution.md`:

- All KEV-to-gate translation happens on-device.
- No source is uploaded to cloud scanners or external analysis services.
- The Crucible is the sole acceptance criterion for new gates.
