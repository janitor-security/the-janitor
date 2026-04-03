# Implementation Backlog

Append-only log of every major directive received and the specific changes
implemented as a result. Maintained by the Evolution Tracker skill.

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

**Commit:** *(pending)*

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

**Commit:** *(pending)*

