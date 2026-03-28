---
# Command: /update-wisdom

Synchronize the local Wisdom Registry with the latest Janitor Sentinel rules.

## Usage

```
/update-wisdom
```

## Mapped command

```bash
janitor update-wisdom
```

## Description

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

## When to run

- After a `janitor release` to pull in any new protection rules from the
  Sentinel service.
- When `cargo test` reports unexpected false positives in the dead-symbol
  pipeline (stale local registry).
- Before running a gauntlet against a new tech stack (e.g., first Rails or
  Spring Boot audit).
