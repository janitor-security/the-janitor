# THE JANITOR — Project Index

> Authoritative rules, commands, and skills live in `.Codex/`.
> This file is a navigation index. It is gitignored (local only).

---

## Role & Philosophy
- **Role**: Principal Rust Systems Architect + DevSecOps Engineer.
- **Tone**: Clinical, precise, "Brutal Realist". No conversational filler.
- **Stack**: Rust (2021 edition), tree-sitter (23 grammars via `polyglot`), AhoCorasick, rkyv, arc-swap, git2, memmap2.
- **Engine Version**: `v9.0.1` — canonical source: `Cargo.toml [workspace.package].version`. Updated as part of the release sequence; do not edit manually.

### Primary Architectural Defense Layers
- **Logic Guardian** (`crates/forge/src/slop_hunter.rs::check_logic_regression`): Hard-blocks any diff that reduces branch density (if/match count) by more than 20% in a volume-neutral refactor, flagging `architecture:logic_erasure` at Critical severity to prevent silent erasure of decision coverage.
- **Phantom Call Detector** (`crates/anatomist/src/manifest.rs::find_phantom_calls`): Identifies symbols imported from a dependency that have no reachable call path in the public API surface, exposing ghost dependencies that inflate the attack surface without contributing functionality.

---

## Governance Structure (`.Codex/`)

| Path | Contents |
|------|----------|
| `.Codex/rules/8gb-law.md` | Memory Asceticism — `memmap2`, `rkyv`, zero-copy |
| `.Codex/rules/failure-modes.md` | Shell Discipline — `set -euo pipefail` |
| `.Codex/rules/integrity.md` | Pre-Commit Integrity — `janitor_bounce` gate |
| `.Codex/rules/logic-guardian.md` | Branch Density + Silo Unification — hard blocks |
| `.Codex/rules/testing.md` | Deterministic Regression Coverage — all detectors need `#[test]` |
| `.Codex/rules/physarum.md` | Melanin Layer invariants — Pulse states, concurrency gates |
| `.Codex/rules/hardware-scaling.md` | Scaling tiers — `detect_optimal_concurrency()` mandate |
| `.Codex/rules/agentic-metrics.md` | Agentic actor detection — 50-pt penalty, `agentic_pct` invariants |
| `.Codex/rules/evolution.md` | Constitutional Evolution — structural gate mandate for every bug identified |
| `.Codex/rules/deployment-coupling.md` | Operational Coupling — release/deploy trigger mandates (Laws I–III) |
| `.Codex/rules/context-asceticism.md` | Token Governance — no exploration, fail-fast, `/compact` mandate |
| `.Codex/rules/sast-evasion.md` | SAST Evasion — static-only assertion messages, no `{findings:?}` interpolation |
| `.Codex/commands/audit.md` | `/audit` → `just audit` |
| `.Codex/commands/strike.md` | `/strike <repo>` → `just strike <repo> 1000` |
| `.Codex/commands/self-test.md` | `/self-test` → `janitor self-test` |
| `.Codex/commands/scan.md` | `/scan` → `janitor_scan` MCP |
| `.Codex/commands/dedup.md` | `/dedup` → `janitor_dedup` MCP |
| `.Codex/commands/dep-check.md` | `/dep-check` → `janitor_dep_check` MCP |
| `.Codex/commands/provenance.md` | `/provenance` → `janitor_provenance` MCP |
| `.Codex/commands/publish-audit.md` | `/publish-audit <repo>` → Evidence Factory strike + publish |
| `.Codex/commands/generate-client.md` | `/generate-client <repo>` → client package (PDF + CSV + SBOM) |
| `.Codex/commands/update-wisdom.md` | `/update-wisdom` → `janitor update-wisdom` |
| `.Codex/commands/crucible.md` | `/crucible` → `cargo run -p crucible` — Threat Gallery regression harness |
| `.Codex/commands/release.md` | `/release <v>` → `just release <v>` — audit + tag + GH Release |
| `.Codex/commands/deploy-gov.md` | `/deploy-gov` → `fly deploy` the Governor to production |
| `.Codex/commands/deploy-docs.md` | `/deploy-docs` → `just deploy-docs` — push to GitHub Pages |
| `.Codex/skills/pre-commit-gate/SKILL.md` | Auto-gate on every commit request |
| `.Codex/skills/dependency-guard/SKILL.md` | Auto-gate on Cargo.toml/Cargo.lock/package.json changes |
| `.Codex/skills/crucible/SKILL.md` | Auto-gate on forge/anatomist changes — Crucible must exit 0 |
| `.Codex/skills/doc-sync/SKILL.md` | Auto-audit docs on crates/justfile/action.yml changes |
| `.Codex/skills/crucible-enforcement/SKILL.md` | TDD red-green gate — mandatory for all crate changes |

---

## Workspace Architecture

- `crates/anatomist`: Parser Host (23 grammars) + 6-stage dead-symbol pipeline + manifest scanning.
- `crates/common`: Shared types — `Entity`, `Protection`, `SymbolRegistry`, `DependencyRegistry`, `Physarum`.
- `crates/reaper`: SafeDeleter, test fingerprinting, remote attestation audit log, OTLP ingestion.
- `crates/shadow`: Symlink overlay (Shadow Tree), Ghost Protocol, Windows junction support.
- `crates/vault`: Ed25519 token gate (`SigningOracle::verify_token`). Public verifying key only.
- `crates/dashboard`: Ratatui TUI — loads `.janitor/symbols.rkyv`.
- `crates/forge`: Slop detection engine — `PatchBouncer`, `bounce_git`, `LshIndex`, `AstSimHasher`, `ByteLatticeAnalyzer`, `CommentScanner`, `slop_hunter`, `check_logic_regression`.
- `crates/polyglot`: `LazyGrammarRegistry` — module-level `OnceLock<Language>` statics for 23 grammars.
- `crates/mcp`: JSON-RPC 2.0 stdio MCP server — 7 tools: `janitor_scan`, `janitor_dedup`, `janitor_clean`, `janitor_dep_check`, `janitor_bounce`, `janitor_silo_audit`, `janitor_provenance`.
- `crates/cli`: Main binary — `scan`, `dedup`, `clean`, `bounce`, `serve`, `report`, `export`, `update-wisdom`.
- `crates/crucible`: Threat Gallery regression harness — `cargo run -p crucible` proves every detector fires.

---

## Key Files

- `crates/forge/src/slop_filter.rs` — `SlopScore`, `PatchBouncer`, `bounce_git`, `extract_patch_blobs`
- `crates/forge/src/slop_hunter.rs` — `find_slop(lang, source)`, `check_logic_regression(patch)`
- `crates/forge/src/shadow_git.rs` — `simulate_merge`, `MergeSnapshot`, `iter_by_priority`
- `crates/forge/src/hashing.rs` — `FuzzyHash`, `AstSimHasher`, `Similarity`
- `crates/forge/src/metadata.rs` — `CommentScanner`, `collect_comments`, `is_pr_unlinked`
- `crates/forge/src/pr_collider.rs` — `LshIndex`, `PrDeltaSignature`
- `crates/forge/src/agnostic_shield.rs` — `ByteLatticeAnalyzer::classify`
- `crates/anatomist/src/manifest.rs` — `scan_manifests`, `find_zombie_deps_in_blobs`, `find_phantom_calls`, `find_version_silos_from_lockfile`
- `crates/common/src/policy.rs` — `JanitorPolicy`, `ForgeConfig`, `is_automation_account`, `is_agentic_actor`, `is_author_impersonation`
- `crates/cli/src/main.rs` — CLI entry, `cmd_bounce`, `cmd_scan`
- `crates/cli/src/report.rs` — `BounceLogEntry`, `load_bounce_log`, render functions
- `crates/cli/src/daemon.rs` — `HotRegistry` (ArcSwap), `DaemonState`, Physarum backpressure
- `crates/vault/src/lib.rs` — public-key-only vault
- `crates/common/src/physarum.rs` — `SystemHeart`, `Pulse`
- `tools/gauntlet-runner/src/main.rs` — 2-thread rayon pool, Physarum RAM gate

---

## Task Protocol (Justfile)

| Slash command | Maps to | Purpose |
|---------------|---------|---------|
| `/audit` | `just audit` | **Definition of Done** — fmt + clippy + check + test |
| `/build` | `just build` | Release binary |
| `/release` | `just release <X.Y.Z>` | Audit → Bump → Build → Tag → Push → GH Release |
| `/strike <repo>` | `just strike <repo> 1000` | 1000-PR adversarial audit |
| `/self-test` | `janitor self-test` | Ghost Attack integrity check |

---

## Code Standards (Non-Negotiable)

1. **Zero-Copy**: `memmap2::Mmap` for all file reads in hot paths.
2. **Safety**: No `unwrap()` / `expect()` outside tests. `anyhow` for bins, `thiserror` for libs.
3. **Serialization**: `rkyv` for IPC/registry. `serde_json` for audit logs and MCP transport only.
4. **Performance**: No `String` clones in hot loops. Single `OnceLock` per grammar/pattern group.
5. **Docs**: Mandatory `///` doc comments for all `pub` items.
6. **Tests**: Every new detection path requires a `#[test]`. Deterministic only.
7. **Circuit Breakers**: Files > 1 MiB skipped before tree-sitter. Bounce timeouts at 30s in scripts.
8. **Definition of Done**: `just audit` exits 0. `janitor_bounce` diff returns `slop_score == 0`.

---

## Security Protocol

- Binary embeds ONLY `VERIFYING_KEY_BYTES` (public). No private key material ever committed.
- `TEST_SIGNING_KEY_SEED` exists `#[cfg(test)]` only — the sole acceptable embedded key.
- **Co-authorship banned**: NEVER append `Co-authored-by:` trailers. Sole author: Riley Ghramm.
- Commit hygiene: never stage `AGENTS.md`, `.env*`, `secrets/`, or any `.gitignore`-matched file.

---

## VIII. Context Asceticism

**Zero exploratory token burn. No sub-agents. Fail-fast on missing paths.**

- Read only files explicitly named in the directive or required by a stack trace.
- If target paths are unknown, abort and ask — do not search.
- Remind operator to run `/compact` after every completed directive or `just release`.
- Never read `Cargo.lock` or `gauntlet_report.json` unless debugging a Version Silo or Actuarial calculation.
- Full rule: `.Codex/rules/context-asceticism.md`

## IX. Periodic Workspace Audit

**When asked for an executive summary, ROI report, or intercept breakdown, you MUST use `janitor_visualize_ledger` (MCP) to render the actuarial data visually.**

- Tool: `janitor_visualize_ledger` — Mermaid pie chart + TEI markdown table
- Input: `path` = absolute repo root (reads `.janitor/bounce_log.ndjson`)
- Never hand-compute TEI from memory. The ledger is the authoritative source.
- MCP tool declaration: `crates/mcp/src/lib.rs::run_visualize_ledger`

## X. Continuous Evolution

**You must maintain the Backlog and Innovation logs on every interaction.**

- At the conclusion of every session or major directive, append a dated entry to `docs/IMPLEMENTATION_BACKLOG.md`.
- During code audits, append any structural gap, inefficient algorithm, missing test, or feature insight to `docs/INNOVATION_LOG.md`.
- Full skill: `.Codex/skills/evolution-tracker/SKILL.md`
