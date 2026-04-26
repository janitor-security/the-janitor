# Atlassian Campaign — Target Ledger

Extracted from `atlassian_targets.md`. Tier ranking by P1 bounty ceiling.
Strike protocol: `npm pack` / `curl` download → extract → `janitor hunt <dir> --format bugcrowd`.

---

## Tier 1 — Forge ($7k P1) — Open-Source / Downloadable SDK Targets

- [x] `@forge/cli` (https://www.npmjs.com/package/@forge/cli) — Node.js CLI; `npm pack @forge/cli && tar xf forge-cli-*.tgz -C /tmp/forge-cli` — Sprint Batch 59
- [x] `@forge/api` (https://www.npmjs.com/package/@forge/api) — Forge app runtime API surface; Node.js — Sprint Batch 61
- [x] `@forge/ui` (https://www.npmjs.com/package/@forge/ui) — UI Kit component library; React/Node.js — Sprint Batch 61
- [ ] `@forge/bridge` (https://www.npmjs.com/package/@forge/bridge) — iframe bridge; JS XSS surface

## Tier 1 — Rovo Dev ($12k P1)

- [ ] `Rovo Dev CLI` (https://support.atlassian.com/rovo/docs/use-rovo-dev-cli/) — Python; `pip download rovo-dev-cli --no-deps -d /tmp/rovo-cli` then inspect wheel

## Tier 2 — Loom ($7k P1) — Electron/ASAR Targets

- [x] `Loom Desktop App (macOS)` (https://www.loom.com/download) — Electron/ASAR; `curl -Lo /tmp/loom.dmg <dmg-url>; 7z x ...` — Sprint Batch 59
- [ ] `Loom Chrome Extension` (https://chromewebstore.google.com/detail/loom/liecbddmkiiihnedobmlmillhodjkdmb) — JS/browser-extension; unzip CRX

## Tier 2 — Bitbucket ($7k P1) — Python / Django SDK

- [ ] `atlassian-python-api` (https://github.com/atlassian-api/atlassian-python-api) — Python; `git clone https://github.com/atlassian-api/atlassian-python-api /tmp/atlassian-python-api`

---

## Hunt Results Log

| Target | Sprint | Findings | FPs Squashed | Verdict |
|--------|--------|----------|--------------|---------|
| `@forge/cli` (latest) | 59 | See below | See below | See below |
| Loom Desktop (macOS) | 59 | N/A — DMG download requires browser auth | — | Deferred to manual ASAR extraction |
| `@forge/api` v7.1.3 | 61 | 0 | 0 | Clean — pre-built package, no raw TS source |
| `@forge/ui` v1.11.4 | 61 | 0 | 0 | Clean — pre-built package, no raw TS source |
