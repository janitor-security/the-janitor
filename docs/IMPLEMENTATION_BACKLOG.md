# Implementation Backlog

Append-only log of every major directive received and the specific changes
implemented as a result. Maintained by the Evolution Tracker skill.

---

## 2026-04-04 — Canonical Alignment Strike (v9.7.0)

**Directive:** Eradicate stale version strings from all forward-facing docs, add a
`sync-versions` justfile recipe hardlinked as a `fast-release` prerequisite, add the
LiteLLM/Mercor breach case study to `docs/manifesto.md`, complete the P0-1 ParsedUnit
migration verification, and cut `v9.7.0`.

**Files modified:**
- `Cargo.toml` *(modified)* — workspace version bumped to `9.7.0`
- `justfile` *(modified)* — `sync-versions` recipe added; made prerequisite of `fast-release`
- `README.md` *(modified)* — headline version updated to `v9.7.0`; Vibe-Check Gate version qualifier removed
- `docs/index.md` *(modified)* — headline version updated to `v9.7.0`
- `docs/manifesto.md` *(modified)* — `v7.9.4` qualifiers removed; LiteLLM/Mercor case study added
- `docs/privacy.md` *(modified)* — `v7.9.4+` updated to `v9.7.0+`
- `docs/architecture.md` *(modified)* — FINAL VERSION block updated; version qualifiers stripped from table and section headers
- `RUNBOOK.md` *(modified)* — example release command updated; inline version qualifiers removed
- `SOVEREIGN_BRIEFING.md` *(modified)* — version qualifiers stripped from table, section headers, and FINAL VERSION block
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `pending release commit`

---

## 2026-04-04 — UAP Pipeline Integration & Parse-Forest Completion (v9.6.4)

**Directive:** Fix the release pipeline to include `.agent_governance/` in the
`git add` surface, complete P0-1 by migrating `find_java_slop`, `find_csharp_slop`,
and `find_jsx_dangerous_html_slop` to consume cached trees via `ParsedUnit::ensure_tree()`,
verify with crucible + `just audit`, and cut `v9.6.4`.

**Files modified:**
- `Cargo.toml` *(modified)* — workspace version bumped to `9.6.4`
- `justfile` *(modified)* — `fast-release` `git add` now includes `.agent_governance/`
- `crates/forge/src/slop_hunter.rs` *(modified)* — `find_java_slop`, `find_csharp_slop`, `find_jsx_dangerous_html_slop` migrated to `ParsedUnit`/`ensure_tree`; all Phase 4–7 detectors share cached CST
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `docs/INNOVATION_LOG.md` *(modified)* — P0-1 parse-forest phase marked complete; CT-010 filed for residual Phase 4–7 single-language detectors

**Commit:** `pending release commit`

---

## 2026-04-04 — Parse-Forest Integration & Telemetry Hardening (v9.6.3)

**Directive:** Enforce autonomous telemetry updates in the UAP evolution
tracker, refactor Forge so `find_slop` consumes a shared `ParsedUnit`, reuse
the Python CST instead of reparsing it, verify with `just audit` plus
`cargo run -p crucible`, and cut `v9.6.3`.

**Files modified:**
- `.agent_governance/skills/evolution-tracker/SKILL.md` *(modified)* — Continuous Telemetry law now forbids waiting for operator instruction; every prompt must autonomously append `CT-NNN` findings before session close
- `Cargo.toml` *(modified)* — workspace version bumped to `9.6.3`
- `crates/forge/src/slop_hunter.rs` *(modified)* — `ParsedUnit` upgraded to a cache-bearing parse carrier; `find_slop` now accepts `&ParsedUnit`; Python AST walk reuses or lazily populates the cached tree instead of reparsing raw bytes
- `crates/forge/src/slop_filter.rs` *(modified)* — patch analysis now instantiates one `ParsedUnit` per file and passes it into the slop dispatch chain
- `crates/crucible/src/main.rs` *(modified)* — Crucible now routes fixtures through `ParsedUnit` so the gallery exercises the production API shape
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `docs/INNOVATION_LOG.md` *(modified)* — autonomous telemetry entry `CT-009` appended for the tracked CDN artefact gap

**Commit:** `pending release commit`

---

## 2026-04-04 — Wisdom Infrastructure Pivot (v9.6.1)

**Directive:** Pivot `update-wisdom` off the dead `api.thejanitor.app`
endpoint onto the live CDN, fail open in `--ci-mode` with an empty manifest on
bootstrap/network faults, publish a bootstrap `docs/v1/wisdom.rkyv`, and cut
`v9.6.1`.

**Files modified:**
- `Cargo.toml` *(modified)* — workspace version bumped to `9.6.1`
- `crates/cli/src/main.rs` *(modified)* — `update-wisdom` now fetches from `https://thejanitor.app/v1/wisdom.rkyv`, supports URL overrides for controlled verification, degrades to an empty `wisdom_manifest.json` in `--ci-mode` on Wisdom/KEV fetch failures, and adds regression coverage for the fallback path
- `docs/v1/wisdom.rkyv` *(created)* — bootstrap empty `WisdomSet` archive committed for CDN hosting at `/v1/wisdom.rkyv`
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `docs/INNOVATION_LOG.md` *(modified)* — CT-008 telemetry recorded for the DNS/CDN pivot

**Commit:** `pending release commit`

---

## 2026-04-04 — Release Pipeline Eradication & Rescue (v9.5.2)

**Directive:** Rescue the burned `v9.5.1` state by committing the staged
executable-surface expansion manually, eradicate the unstaged-only
`git diff --quiet` heuristic from the release path, roll forward to `v9.5.2`,
and cut a real signed release from the audited code.

**Files modified:**
- `justfile` *(modified)* — fast-release now stages the governed release set and commits unconditionally; empty-release attempts fail closed under `set -euo pipefail`
- `Cargo.toml` *(modified)* — workspace version bumped to `9.5.2`
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `docs/INNOVATION_LOG.md` *(modified)* — release-surface debt updated to include staged-only ghost-tag failure and the need for a tag-target regression test

**Rescue commit:** `e095fae` — `feat: autonomous expansion for executable gaps (v9.5.1)`
**Commit:** `pending release commit`

---

## 2026-04-04 — Autonomous Expansion & Release Hygiene (v9.5.1)

**Directive:** Repair the fast-release staging gap that dropped new crates from
the prior tag, autonomously execute `P0-1` by expanding the executable-surface
detectors across six high-risk file types, prove them in Crucible, and record
new architecture debt discovered during implementation.

**Files modified:**
- `justfile` *(modified)* — fast-release now stages `crates/ tools/ docs/ Cargo.toml Cargo.lock justfile action.yml` before the signed release commit, preventing new crates from being omitted while still ignoring root-level agent garbage
- `Cargo.toml` *(modified)* — workspace version bumped to `9.5.1`
- `crates/forge/src/slop_filter.rs` *(modified)* — filename-aware pseudo-language extraction added for `Dockerfile`, `CMakeLists.txt`, and Bazel root files so extensionless security surfaces reach the detector layer
- `crates/forge/src/slop_hunter.rs` *(modified)* — new detectors added for Dockerfile remote `ADD`, XML XXE, protobuf `google.protobuf.Any`, Bazel/Starlark `http_archive` without `sha256`, CMake `execute_process(COMMAND ${VAR})`, and dynamic `system()` in C/C++; unit tests added
- `crates/crucible/src/main.rs` *(modified)* — true-positive and true-negative fixtures added for all six new executable-surface detectors
- `docs/INNOVATION_LOG.md` *(modified)* — implemented `P0-1` removed; new `P2-5` added for filename-aware surface routing
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `e095fae`

---

## 2026-04-04 — Air-Gap Update (v9.5.0)

**Directive:** Execute the Sovereign Governor extraction, decouple CLI
attestation routing from the Fly.io default, prove custom Governor routing in
tests, retire `P0-1` from the Innovation Log, and cut `v9.5.0`.

**Files modified:**
- `Cargo.toml` *(modified)* — workspace version bumped to `9.5.0`; shared `serde_json` workspace dependency normalized for the new Governor crate
- `crates/gov/Cargo.toml` *(created)* — new `janitor-gov` binary crate added to the workspace
- `crates/gov/src/main.rs` *(created)* — minimal localhost Governor stub added with `/v1/report` and `/v1/analysis-token` JSON-validation endpoints
- `crates/common/src/policy.rs` *(modified)* — `[forge].governor_url` added and covered in TOML/load tests
- `crates/cli/src/main.rs` *(modified)* — `janitor bounce` now accepts `--governor-url` (with `--report-url` compatibility alias), resolves base URL through policy, and routes timeout/report traffic through the custom Governor
- `crates/cli/src/report.rs` *(modified)* — Governor URL resolution centralized; `/v1/report` and `/health` endpoints derived from the configured base URL; routing tests updated
- `docs/INNOVATION_LOG.md` *(modified)* — `P0-1` removed as implemented; remaining P0 items re-indexed
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `pending release commit`

---

## 2026-04-04 — Log Compaction & CISO Pulse Hardening (v9.4.1)

**Directive:** Enforce hard compaction in the Evolution Tracker, purge
completed and telemetry debt from the innovation log, re-index active work
into clean P0/P1/P2 numbering, and cut `v9.4.1`.

**Files modified:**
- `.agent_governance/skills/evolution-tracker/SKILL.md` *(modified)* — CISO Pulse rewritten to enforce hard compaction: delete completed work, delete telemetry, drop legacy IDs, and re-index active items into `P0-1`, `P1-1`, `P2-1`, etc.
- `docs/INNOVATION_LOG.md` *(rewritten)* — completed grammar-depth work, legacy telemetry, and stale IDs purged; active debt compacted into clean P0/P1/P2 numbering
- `Cargo.toml` *(modified)* — workspace version bumped to `9.4.1`
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `pending release commit`

---

## 2026-04-04 — Deep-Scan & Innovation Synthesis (v9.4.0)

**Directive:** Enforce the fast-release law, add a deep-scan evasion shield to
the bounce path and GitHub Action, clear Forge warning debt, and perform a
dedicated innovation synthesis pass over MCP and slop-hunter.

**Files modified:**
- `.agent_governance/commands/release.md` *(modified)* — absolute prohibition added against `just release`; release path now explicitly mandates `just audit` followed by `just fast-release <v>`
- `action.yml` *(modified)* — optional `deep_scan` input added; composite action now forwards `--deep-scan` to `janitor bounce`
- `Cargo.toml` *(modified)* — workspace version bumped to `9.4.0`
- `crates/common/src/policy.rs` *(modified)* — `[forge].deep_scan` config added and covered in TOML roundtrip tests
- `crates/cli/src/main.rs` *(modified)* — `janitor bounce` gains `--deep-scan`; CLI now merges the flag with `[forge].deep_scan` policy config
- `crates/cli/src/git_drive.rs` *(modified)* — git-native bounce call updated for the deep-scan-capable `bounce_git` signature
- `crates/forge/src/slop_hunter.rs` *(modified)* — configurable parse-budget helper added; 30 s deep-scan timeout constant added; stale test warning removed
- `crates/forge/src/slop_filter.rs` *(modified)* — patch and git-native size budgets raised to 32 MiB under deep-scan; parser timeouts retry at 30 s before emitting `Severity::Exhaustion`
- `crates/forge/src/metadata.rs` *(modified)* — stale test warning removed
- `docs/INNOVATION_LOG.md` *(modified)* — `IDEA-003` and `IDEA-004` rewritten from the mandatory MCP/slop-hunter synthesis pass
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `pending release commit`

---

## 2026-04-04 — Communication Bifurcation & KEV Correlation Strike (v9.3.0)

**Directive:** Relax intermediate execution messaging while preserving the
final response law, implement KEV-aware dependency correlation across the
lockfile/bounce/MCP paths, add Crucible regression coverage, and cut `v9.3.0`.

**Files modified:**
- `.agent_governance/rules/response-format.md` *(modified)* — intermediate execution updates now explicitly permit concise natural language; 4-part response format reserved for the final post-release summary only
- `Cargo.toml` *(modified)* — workspace version bumped to `9.3.0`; `semver` promoted to a workspace dependency for KEV range matching
- `crates/common/Cargo.toml` *(modified)* — `semver.workspace = true` added for shared KEV matching logic
- `crates/common/src/deps.rs` *(modified)* — archived `DependencyEcosystem` gains ordering/equality derives required by KEV rule archival
- `crates/common/src/wisdom.rs` *(modified)* — KEV dependency rule schema, archive compatibility loader, and shared `find_kev_dependency_hits()` matcher added
- `crates/anatomist/Cargo.toml` *(modified)* — `semver.workspace = true` added
- `crates/anatomist/src/manifest.rs` *(modified)* — `check_kev_deps(lockfile, wisdom_db)` implemented as the SlopFinding adapter over shared KEV hit correlation; regression tests added
- `crates/forge/src/slop_filter.rs` *(modified)* — `PatchBouncer` made workspace-aware, KEV findings injected into both aggregate and lockfile-source-text fast paths
- `crates/mcp/src/lib.rs` *(modified)* — `janitor_dep_check` now surfaces `kev_count` and `kev_findings`; `run_bounce` uses workspace-aware `PatchBouncer`
- `crates/cli/src/main.rs` *(modified)* — patch-mode bounce path switched to workspace-aware `PatchBouncer`
- `crates/cli/src/daemon.rs` *(modified)* — daemon bounce path switched to workspace-aware `PatchBouncer`
- `crates/crucible/Cargo.toml` *(modified)* — test dependencies added for synthetic wisdom archive fixtures
- `crates/crucible/src/main.rs` *(modified)* — synthetic `Cargo.lock` KEV fixture added; 150-point intercept enforced
- `docs/INNOVATION_LOG.md` *(modified)* — `IDEA-002` removed as implemented
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `pending release commit`

---

## 2026-04-02 — Enterprise Supremacy Ingestion

**Directive:** Encode Fortune 500 CISO teardown into architectural ledger and
harden the governance constitution against stale documentation.

**Files modified:**
- `docs/ENTERPRISE_GAPS.md` *(created)* — 4 Critical vulnerability entries:
  VULN-01 (Governor SPOF), VULN-02 (PQC key custody), VULN-03 (SCM lock-in),
  VULN-04 (hot-path blind spots); v9.x.x solution spec for each
- `.claude/rules/deployment-coupling.md` *(modified)* — Law IV added:
  stale documentation is a compliance breach; `rg` audit mandate after every
  feature change; enforcement checklist updated

**Commit:** `010d430`

---

## 2026-04-03 — Continuous Evolution Protocol (v9.0.0)

**Directive:** Abandon static roadmap in favour of dynamic AI-driven
intelligence logs; implement Evolution Tracker skill; seed backlog and
innovation log; harden CLAUDE.md with Continuous Evolution law.

**Files modified:**
- `docs/R_AND_D_ROADMAP.md` *(deleted)* — superseded by dynamic logs
- `docs/IMPLEMENTATION_BACKLOG.md` *(created)* — this file
- `docs/INNOVATION_LOG.md` *(created)* — autonomous architectural insight log
- `.claude/skills/evolution-tracker/SKILL.md` *(created)* — skill governing
  backlog and innovation log maintenance
- `CLAUDE.md` *(modified, local/gitignored)* — Law X: Continuous Evolution

**Commit:** e01a3b5

---

## 2026-04-03 — VULN-01 Remediation: Soft-Fail Mode (v9.0.0)

**Directive:** Implement `--soft-fail` flag and `soft_fail` toml key so the
pipeline can proceed without Governor attestation when the network endpoint
is unreachable; mark bounce log entries with `governor_status: "degraded"`.

**Files modified:**
- `crates/common/src/policy.rs` *(modified)* — `soft_fail: bool` field added to `JanitorPolicy`
- `crates/cli/src/report.rs` *(modified)* — `governor_status: Option<String>` field added to `BounceLogEntry`; 3 `soft_fail_tests` added
- `crates/cli/src/main.rs` *(modified)* — `--soft-fail` CLI flag; `cmd_bounce` wired; POST+log restructured for degraded path
- `crates/cli/src/daemon.rs` *(modified)* — `governor_status: None` added to struct literal
- `crates/cli/src/git_drive.rs` *(modified)* — `governor_status: None` added to two struct literals
- `crates/cli/src/cbom.rs` *(modified)* — `governor_status: None` added to test struct literal
- `docs/INNOVATION_LOG.md` *(modified)* — VULN-01 short-term solution marked `[COMPLETED — v9.0.0]`
- `RUNBOOK.md` *(modified)* — `--soft-fail` flag documented
- `Cargo.toml` *(modified)* — version bumped to `9.0.0`

**Commit:** `dbfe549`

---

## 2026-04-03 — Governance Optimization (v9.0.1)

**Directive:** Linearize the release skill to prevent re-auditing; add Auto-Purge
law to the Evolution Tracker; confirm single-source version ownership; fix stale
`v8.0.14` engine version in `CLAUDE.md`.

**Files modified:**
- `.claude/commands/release.md` *(modified)* — 5-step linear AI-guided release
  sequence; GPG fallback procedure documented; version single-source law enforced
- `.claude/skills/evolution-tracker/SKILL.md` *(modified)* — Logic 4 added:
  Auto-Purge of fully-completed H2/H3 sections from `docs/INNOVATION_LOG.md`
- `CLAUDE.md` *(modified, gitignored)* — stale `v8.0.14` corrected to `v9.0.1`;
  note added that version is managed exclusively by the release sequence
- `Cargo.toml` *(modified)* — version bumped to `9.0.1`
- `docs/INNOVATION_LOG.md` *(modified)* — CT-003 filed (telemetry)

**Commit:** `4527fbb`

---

## 2026-04-03 — Signature Sovereignty (v9.1.0)

**Directive:** Hard-fix GPG tag signing in justfile (CT-005); implement BYOK Local
Attestation (VULN-02) — `--pqc-key` flag on `janitor bounce`, `janitor verify-cbom`
command, ML-DSA-65 signing/verification, CycloneDX upgrade to v1.6.

**Files modified:**
- `justfile` *(modified)* — `git tag v{{version}}` changed to `git tag -s v{{version}} -m "release v{{version}}"` in both `release` and `fast-release` recipes (CT-005 resolved)
- `Cargo.toml` *(modified)* — `fips204 = "0.4"` and `base64 = "0.22"` added to workspace dependencies; version bumped to `9.1.0`
- `crates/cli/Cargo.toml` *(modified)* — `fips204.workspace = true` and `base64.workspace = true` added
- `crates/cli/src/report.rs` *(modified)* — `pqc_sig: Option<String>` field added to `BounceLogEntry`; all struct literals updated
- `crates/cli/src/cbom.rs` *(modified)* — `specVersion` upgraded `"1.5"` → `"1.6"`; `render_cbom_for_entry()` added (deterministic, no UUID/timestamp, used for PQC signing)
- `crates/cli/src/main.rs` *(modified)* — `--pqc-key` flag added to `Bounce` subcommand; `VerifyCbom` subcommand added; `cmd_bounce` BYOK signing block; `cmd_verify_cbom()` function; 4 tests in `pqc_signing_tests` module
- `crates/cli/src/daemon.rs` *(modified)* — `pqc_sig: None` added to struct literal
- `crates/cli/src/git_drive.rs` *(modified)* — `pqc_sig: None` added to 2 struct literals
- `docs/INNOVATION_LOG.md` *(modified)* — VULN-02 section purged (all findings `[COMPLETED — v9.1.0]`); roadmap table updated

**Commit:** `89d742f`

---

## 2026-04-04 — Codex Alignment & Git Hygiene (v9.2.2)

**Directive:** Enforce tracked-only release commits, ignore local agent state,
resynchronize to the mandatory response format law, and cut `v9.2.2`.

**Files modified:**
- `justfile` *(modified)* — `fast-release` now uses `git commit -a -S -m "chore: release v{{version}}"` behind a dirty-tree guard, preventing untracked local files from being staged during releases
- `.gitignore` *(modified)* — explicit ignore rules added for `.agents/`, `.codex/`, `AGENTS.md`, and other local tool-state directories
- `Cargo.toml` *(modified)* — workspace version bumped to `9.2.2`
- `docs/INNOVATION_LOG.md` *(modified)* — CT-006 logged for the release hygiene regression; session telemetry section appended
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `pending release commit`

---

## 2026-04-03 — Codex Initialization & Redundancy Purge (v9.2.1)

**Directive:** Align Codex to UAP governance, audit release execution paths for redundant compute, record legacy-governance drift proposals, and cut the `9.2.1` release.

**Files modified:**
- `justfile` *(modified)* — `release` recipe collapsed into a thin `audit` → `fast-release` delegator so agentic deploys follow the single-audit path without duplicated release logic
- `Cargo.toml` *(modified)* — workspace version bumped to `9.2.1`
- `docs/architecture.md` *(modified)* — stale `just release` pipeline description corrected to the linear `audit` → `fast-release` flow
- `docs/INNOVATION_LOG.md` *(modified)* — `Legacy Governance Gaps (P2)` section appended with governance-drift proposals; session telemetry recorded
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry

**Commit:** `pending release commit`

---

## 2026-04-03 — Forward-Looking Telemetry (v9.0.2)

**Directive:** Add `just fast-release` recipe (audit-free release path); harden
Evolution Tracker with Forward-Looking Mandate and Architectural Radar Mandate;
purge completed-work entry CT-003 from Innovation Log.

**Files modified:**
- `justfile` *(modified)* — `fast-release version` recipe added; identical to
  `release` but without the `audit` prerequisite
- `.claude/commands/release.md` *(modified)* — Step 4 updated from `just release`
  to `just fast-release`
- `.claude/skills/evolution-tracker/SKILL.md` *(modified)* — Forward-Looking
  Mandate added (no completed work in Innovation Log); Architectural Radar
  Mandate added (4 scanning categories for future R&D proposals)
- `docs/INNOVATION_LOG.md` *(modified)* — CT-003 purged (completed work,
  belongs in Backlog); CT-004 and CT-005 filed as forward-looking proposals
- `Cargo.toml` *(modified)* — version bumped to `9.0.2`

**Commit:** `ff42274`

---

## 2026-04-03 — CISO Pulse & Autonomous Clock (v9.1.1)

**Directive:** Enforce response formatting law; implement CT-10 CISO Pulse rule
in Evolution Tracker; build weekly CISA KEV autonomous sync workflow; execute
the first CISO Pulse Audit — re-tier `INNOVATION_LOG.md` into P0/P1/P2 with
12 new grammar depth rule proposals (Go ×3, Rust ×3, Java ×3, Python ×3).

**Files modified:**
- `.claude/rules/response-format.md` *(created)* — Mandatory 4-section
  response format law: [EXECUTION STATUS], [CHANGES COMMITTED], [TELEMETRY],
  [NEXT RECOMMENDED ACTION]
- `.claude/skills/evolution-tracker/SKILL.md` *(modified)* — Logic 5 added:
  CT-10 CISO Pulse Audit trigger with full P0/P1/P2 re-tiering protocol
- `.github/workflows/cisa-kev-sync.yml` *(created)* — Weekly CISA KEV JSON
  sync (every Monday 00:00 UTC); diffs against `.janitor/cisa_kev_ids.txt`;
  auto-opens PR with updated snapshot + AST gate checklist
- `docs/INNOVATION_LOG.md` *(rewritten)* — CISO Pulse Audit: full P0/P1/P2
  re-tiering; 12 new grammar depth rules; IDEA-004 (HSM/KMS) added; CT-007
  (update-wisdom --ci-mode gap) and CT-008 (C/C++ AST zero-coverage) filed
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `Cargo.toml` *(modified)* — version bumped to `9.1.1`

**Purged sections:** CT-005 (`[COMPLETED — v9.1.0]`) merged into the CISO
Pulse log restructure. VULN-02 section was already purged in v9.1.0.

**Commit:** `5056576`

---

## 2026-04-03 — Wisdom & Java Consolidation (v9.1.2)

**Directive:** Harden CISO Pulse with CT counter reset rule; fix CT-007 by
adding `--ci-mode` to `update-wisdom`; update CISA KEV sync workflow to use
the janitor binary as sole arbiter; execute P0 Java AST depth — implement
Java-1 (readObject KevCritical + test suppression), Java-2 (ProcessBuilder
injection), and Java-3 (XXE DocumentBuilderFactory); add Crucible fixtures.

**Files modified:**
- `.claude/skills/evolution-tracker/SKILL.md` *(modified)* — Logic 5 step 8
  added: CT counter resets to CT-001 after every CISO Pulse Audit (epoch reset)
- `crates/cli/src/main.rs` *(modified)* — `--ci-mode` flag added to
  `UpdateWisdom` subcommand; `cmd_update_wisdom` fetches CISA KEV JSON and
  emits `.janitor/wisdom_manifest.json` when `ci_mode = true`
- `crates/forge/src/slop_hunter.rs` *(modified)* — `find_java_danger_invocations`
  gains `inside_test: bool` param + `@Test` annotation suppression;
  `readObject`/`exec`/`lookup` upgraded from `Critical` to `KevCritical`;
  `new ProcessBuilder(expr)` (Java-2b) and
  `DocumentBuilderFactory.newInstance()` XXE (Java-3) detection added;
  `java_has_test_annotation()` helper added; 5 new unit tests
- `crates/crucible/src/main.rs` *(modified)* — 4 new fixtures: ProcessBuilder
  TP/TN and DocumentBuilder XXE TP/TN
- `.github/workflows/cisa-kev-sync.yml` *(modified)* — switched from raw `curl`
  to `janitor update-wisdom --ci-mode`; workflow downloads janitor binary from
  GH releases before running
- `docs/INNOVATION_LOG.md` *(modified)* — Java-1/2/3 grammar depth section
  marked `[COMPLETED — v9.1.2]`; CT epoch reset to Epoch 2 (CT-001, CT-002)
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `Cargo.toml` *(modified)* — version bumped to `9.1.2`

**Commit:** `da591d6`

---

## 2026-04-03 — SIEM Integration & Autonomous Signing Update (v9.1.3)

**Directive:** Eliminate manual GPG intervention via `JANITOR_GPG_PASSPHRASE`
env var; broadcast zero-upload proof to enterprise SIEM dashboards; harden
`[NEXT RECOMMENDED ACTION]` against recency bias.

**Files modified:**
- `justfile` *(modified)* — both `release` and `fast-release` recipes gain
  `JANITOR_GPG_PASSPHRASE` env var block: if set, pipes to
  `gpg-preset-passphrase --preset EA20B816F8A1750EB737C4E776AE1CBD050A171E`
  before `git tag -s`; falls back to existing cache if unset
- `crates/cli/src/report.rs` *(modified)* — `fire_webhook_if_configured` doc
  comment gains explicit provenance call-out: `provenance.source_bytes_processed`
  and `provenance.egress_bytes_sent` always present in JSON payload for SIEM
  zero-upload dashboards (Datadog/Splunk)
- `.claude/rules/response-format.md` *(modified)* — Anti-Recency-Bias Law added
  to `[NEXT RECOMMENDED ACTION]`: must scan entire Innovation Log P0/P1/P2;
  select highest commercial TEI or critical compliance upgrade; recency is not
  a selection criterion
- `RUNBOOK.md` *(modified)* — Section 3 RELEASE: `JANITOR_GPG_PASSPHRASE`
  export documented with key fingerprint, keygrip, and fallback to `gpg-unlock`
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `Cargo.toml` *(modified)* — version bumped to `9.1.3`

**Commit:** `b6da4e0`

---

## 2026-04-03 — Go SQLi Interceptor & Portability Fix (v9.1.4)

**Directive:** Execute P0 Go-3 SQL injection AST gate; add Crucible TP/TN
fixtures; resolve CT-003 by making `gpg-preset-passphrase` path portable.

**Files modified:**
- `crates/forge/src/slop_hunter.rs` *(modified)* — `GO_MARKERS` pre-filter
  extended with 5 DB method patterns; `find_go_danger_nodes` gains Go-3 gate:
  `call_expression` with field in `{Query,Exec,QueryRow,QueryContext,ExecContext}`
  fires `security:sql_injection_concatenation` (KevCritical) when first arg is
  `binary_expression{+}` with at least one non-literal operand; 3 unit tests added
- `crates/crucible/src/main.rs` *(modified)* — 2 Go-3 fixtures: TP (dynamic
  concat in `db.Query`) + TN (parameterized `db.Query`); Crucible 141/141 → 143/143
- `justfile` *(modified)* — CT-003 resolved: `gpg-preset-passphrase` path now
  resolved via `command -v` + `find` fallback across Debian/Fedora/Arch/macOS;
  no-op if binary not found anywhere (falls back to `gpg-unlock` cache)
- `docs/INNOVATION_LOG.md` *(modified)* — Go-3 marked `[COMPLETED — v9.1.4]`;
  CT-003 section purged (auto-purge: all findings completed)
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `Cargo.toml` *(modified)* — version bumped to `9.1.4`

**Commit:** `fc9c11f`


---

## 2026-04-03 — Universal Agent Protocol & RCE Hardening (v9.2.0)

**Directive:** Establish shared multi-agent governance layer; intercept WebLogic
T3/IIOP `resolve()` and XMLDecoder F5/WebLogic RCE vectors; add Cognition
Surrender Index to quantify AI-introduced structural rot density.

**Files modified:**
- `.agent_governance/` *(created)* — UAP canonical governance dir; `README.md`
  documents bootstrap sequence and shared ledger mandate for all agents
- `.agent_governance/rules/` — git mv from `.claude/rules/` (symlink preserved)
- `.agent_governance/commands/` — git mv from `.claude/commands/` (symlink preserved)
- `.agent_governance/skills/` — git mv from `.claude/skills/` (symlink preserved)
- `.claude/rules`, `.claude/commands`, `.claude/skills` *(converted to symlinks)*
- `.cursorrules` *(created)* — Codex/Cursor bootstrap: reads `.agent_governance/`
- `crates/forge/src/slop_hunter.rs` *(modified)* — `JAVA_MARKERS` gains `b"resolve"`;
  `"lookup"` arm extended to `"lookup" | "resolve"` (WebLogic CVE-2023-21839/21931);
  `new XMLDecoder(stream)` `object_creation_expression` gate (KevCritical,
  CVE-2017-10271, CVE-2019-2725); 3 new unit tests
- `crates/crucible/src/main.rs` *(modified)* — 3 new fixtures: ctx.resolve TP/TN,
  XMLDecoder TP; Crucible 141/141 → 144/144
- `crates/cli/src/report.rs` *(modified)* — `BounceLogEntry` gains
  `cognition_surrender_index: f64`; `render_step_summary` outputs CSI row
- `crates/cli/src/main.rs` *(modified)* — CSI computed in main log entry (inline);
  timeout entry gains `cognition_surrender_index: 0.0`; test helper updated
- `crates/cli/src/daemon.rs` *(modified)* — `cognition_surrender_index: 0.0`
- `crates/cli/src/git_drive.rs` *(modified)* — `cognition_surrender_index: 0.0` (×2)
- `crates/cli/src/cbom.rs` *(modified)* — `cognition_surrender_index: 0.0`
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `Cargo.toml` *(modified)* — version bumped to `9.2.0`

**Commit:** `89d742f`


---

## 2026-04-04 — v9.6.0: Omni-Purge & MCP Structured Findings (P1-3)

**Directive:** Omni-Purge + MCP Structured Findings Envelope (P1-3)

**Changes:**
- `crates/common/src/slop.rs` *(created)* — `StructuredFinding` DTO: `{ id: String, file: Option<String>, line: Option<u32> }`; registered in `common::lib.rs`
- `crates/forge/src/slop_filter.rs` *(modified)* — `SlopScore` gains `structured_findings: Vec<StructuredFinding>`; `bounce()` populates findings from accepted antipatterns with line numbers; `bounce_git()` injects file context per blob; redundant `let mut` rebinding removed
- `crates/mcp/src/lib.rs` *(modified)* — `run_bounce()` emits `"findings"` structured array alongside `"antipattern_details"`; `run_scan()` emits dead-symbol findings as `{ id: "dead_symbol", file, line, name }`
- `SOVEREIGN_BRIEFING.md` *(modified)* — `StructuredFinding` DTO row in primitives table; Stage 17 in bounce pipeline
- `/tmp/omni_mapper*`, `/tmp/the-janitor*` *(purged)* — orphaned clone cleanup
- `Cargo.toml` *(modified)* — version bumped to `9.6.0`

**Status:** P1-3 COMPLETED. Crucible 156/156 + 3/3. `just audit` ✅.

---

## 2026-04-04 — v9.6.2: Git Exclusion Override & Taint Spine Initialization (P0-1)

**Directive:** Git Hygiene Fix + P0-1 Taint Spine Foundation

**Changes:**
- `.gitignore` *(modified)* — `!docs/v1/wisdom.rkyv` exception punched below `*.rkyv` rule; `git add -f` staged the artifact
- `crates/common/src/taint.rs` *(created)* — `TaintKind` enum (7 variants, stable `repr(u8)` for rkyv persistence), `TaintedParam` struct, `TaintExportRecord` struct; all derive `Archive + Serialize + Deserialize` (rkyv + serde); 3 unit tests
- `crates/common/src/lib.rs` *(modified)* — `pub mod taint` registered
- `crates/forge/src/slop_hunter.rs` *(modified)* — `ParsedUnit<'src>` struct exported: holds `source: &[u8]`, `tree: Option<Tree>`, `language: Option<Language>`; `new()` and `unparsed()` constructors; no `find_slop` refactor yet (foundational type only)
- `docs/INNOVATION_LOG.md` *(modified)* — CT-009 appended
- `docs/IMPLEMENTATION_BACKLOG.md` *(modified)* — this entry
- `Cargo.toml` *(modified)* — version bumped to `9.6.2`

**Status:** P0-1 foundation COMPLETE. `just audit` ✅.

---

## 2026-04-04 — v9.6.4: UAP Pipeline Integration & Parse-Forest Completion (P0-1)

**Directive:** Fix release pipeline to include `.agent_governance/` in `git add`; complete P0-1 parse-forest reuse by migrating all high-redundancy AST-heavy detectors to `ParsedUnit::ensure_tree()`

**Files modified:**
- `justfile` *(modified)* — `fast-release` recipe: `git add` now includes `.agent_governance/` directory so governance rule changes enter the release commit
- `crates/forge/src/slop_hunter.rs` *(modified)* — 11 AST-heavy detectors migrated from `(eng, source: &[u8])` to `(eng, parsed: &ParsedUnit<'_>)` using `ensure_tree()`: `find_js_slop`, `find_python_sqli_slop`, `find_python_ssrf_slop`, `find_python_path_traversal_slop`, `find_java_slop`, `find_js_sqli_slop`, `find_js_ssrf_slop`, `find_js_path_traversal_slop`, `find_csharp_slop`, `find_prototype_merge_sink_slop`, `find_jsx_dangerous_html_slop`; 4 `#[cfg(test)]` byte-wrappers added; 3 test module aliases updated; `find_slop` call sites updated to pass `parsed`
- `SOVEREIGN_BRIEFING.md` *(modified)* — `find_slop` signature updated to `(lang, &ParsedUnit)` with P0-1 parse-forest note; stale `(lang, source)` reference corrected
- `Cargo.toml` *(modified)* — version bumped to `9.6.4`

**Commit:** (see tag v9.6.4)

**Status:** P0-1 Phase 2 COMPLETE (Python 4→1 parse, JS 6→1 parse per file). Crucible 156/156 + 3/3. `just audit` ✅.
