# Innovation Log

Autonomous architectural insights, structural gap observations, intelligence
ledgers, and forward-looking feature proposals. Maintained by the Evolution
Tracker skill. Entries are append-only and dated. Proposals range from
incremental hardening to wild architectural pivots.

---

## Enterprise Compliance Gaps

*Source: Fortune 500 CISO teardown — 2026-04-02*  
*Status: v9.x.x neutralization track*

### VULN-01 — Availability Coupling (SPOF)

**Severity:** Critical  
**Class:** Infrastructure / Reliability

#### Finding

The Janitor CLI fails-closed when the Fly.io Governor is unreachable. Any
network partition, Fly.io maintenance window, or DNS failure halts every
CI/CD pipeline that depends on `janitor bounce`. For an enterprise deploying
the Janitor as a hard gate on PR merges, this is an unacceptable Single Point
of Failure.

#### Solution — Soft-Fail Mode + Sovereign Governor

**Short-term — Soft-Fail Mode:** `[COMPLETED — v9.0.0]`  
`--soft-fail` flag added to `janitor bounce`; `soft_fail = true` supported in
`janitor.toml`. When the Governor is unreachable and soft-fail is active, the
CLI logs a `[JANITOR DEGRADED]` warning to stderr, marks the bounce log entry
with `governor_status: "degraded"`, and exits `0`. The slop score remains
authoritative in the local `.janitor/bounce_log.ndjson` audit trail.

**Long-term (v9.1.x) — Sovereign Governor binary:**  
Package the Governor as a self-contained binary (`janitor-gov`) that the
customer deploys inside their own VPC (EKS, GKE, or bare-metal). The SaaS
Fly.io Governor becomes optional; `janitor bounce --governor-url
https://janitor-gov.internal` routes to the on-prem instance. The Governor
binary is stateless-first — PostgreSQL is optional; SQLite (`janitor-gov
--storage sqlite:///.janitor/gov.db`) is the default for air-gapped
deployments.

**Definition of Done:**
- `just audit` passes with Sovereign Governor binary crate skeleton
- `--soft-fail` wired into `cmd_bounce`; degraded attestation logged to NDJSON
- Integration test: Governor endpoint returns 500 → soft-fail path exercises

---

### VULN-02 — Key Custody & Compliance Theater

**Severity:** Critical  
**Class:** Cryptography / Compliance

#### Finding

The current architecture implies vendor-held ML-DSA-65 (FIPS 204) signing keys
on the Fly.io Governor. Enterprises operating under FedRAMP, SOC 2 Type II, or
DISA STIG cannot delegate key custody to a SaaS vendor. Claiming post-quantum
attestation while the vendor controls the signing key is compliance theater —
the customer cannot independently verify the chain of custody.

#### Solution — BYOK Local Attestation

**v9.0.x — `--pqc-key` CLI argument:**  
Add `--pqc-key <path>` to `janitor bounce`. When present, the CLI signs the
`BounceResult` CBOM directly on the runner using the customer's locally-stored
ML-DSA-65 private key, bypassing the Governor signing path entirely. The
signature is embedded in the bounce log entry (`"pqc_sig": "<base64>"`) and
verifiable offline via `janitor verify-cbom --key <pub.pem> <log.ndjson>`.

**v9.1.x — HSM / KMS integration:**  
Extend `--pqc-key` to accept a PKCS#11 URI (`pkcs11:token=...`) or AWS KMS
ARN (`arn:aws:kms:...`). The signing operation is delegated to the HSM/KMS;
no private key material ever touches the runner filesystem.

**Key invariant (never violate):**  
The Fly.io Governor's verifying key (`VERIFYING_KEY_BYTES`) remains a
public-only embed. The private key is never shipped in any binary — local or
cloud. `--pqc-key` loads from a path external to the binary at runtime.

**Definition of Done:**
- `janitor bounce --pqc-key ./mlksa.key` signs CBOM locally; Governor not contacted
- `janitor verify-cbom` verifies detached signature offline
- `cargo test` covers: sign + verify round-trip, missing key error, invalid key error

---

### VULN-03 — SCM Lock-in

**Severity:** High  
**Class:** Portability / Ecosystem

#### Finding

All environment variable resolution, webhook handling, and Check Run APIs are
coupled to GitHub's specific contract: `GITHUB_SHA`, `GITHUB_REF`,
`GITHUB_REPOSITORY`, `GITHUB_TOKEN`, GitHub App installation IDs, and the
`POST /repos/:owner/:repo/check-runs` API. GitLab CI, Bitbucket Pipelines, and
Azure DevOps have incompatible environment shapes and no equivalent "Check Run"
primitive. This locks the Janitor out of approximately 45% of the enterprise
SCM market.

#### Solution — `ScmContext` abstraction

**v9.0.x — `ScmContext` struct in `crates/common/src/scm.rs`:**

```rust
pub struct ScmContext {
    pub provider: ScmProvider,   // GitHub | GitLab | Bitbucket | AzureDevOps | Generic
    pub commit_sha: String,
    pub repo_slug: String,       // owner/repo or group/project
    pub pr_number: Option<u64>,
    pub base_ref: String,
    pub head_ref: String,
    pub token: Option<String>,
}

pub enum ScmProvider {
    GitHub,
    GitLab,
    Bitbucket,
    AzureDevOps,
    Generic,
}

impl ScmContext {
    /// Auto-detect from environment variables.
    pub fn from_env() -> Self { … }
}
```

Detection priority: `GITLAB_CI` → GitLab; `BITBUCKET_BUILD_NUMBER` →
Bitbucket; `TF_BUILD` → Azure DevOps; `GITHUB_ACTIONS` → GitHub; else Generic.

**Governor extension (v9.1.x):**  
Replace the GitHub App Check Run emit path with a `ScmContext`-aware notifier
trait. GitLab implementation uses MR Notes API; Bitbucket uses Build Status
API; Azure DevOps uses Pull Request Thread API.

**Definition of Done:**
- `ScmContext::from_env()` correctly detects all 4 providers in unit tests
- `cmd_bounce` uses `ScmContext` for all env var reads; no raw `std::env::var("GITHUB_SHA")` calls remain in hot path
- CI matrix tests GitHub + GitLab env fixture sets

---

### VULN-04 — Hot-Path Blind Spots

**Severity:** High  
**Class:** Detection Coverage / Evasion

#### Finding

Two deterministic circuit breakers create exploitable blind spots:

1. **1 MiB patch skip** (`crates/forge/src/slop_hunter.rs`): Files exceeding
   1 MiB are skipped before tree-sitter parsing. A malicious actor can pad a
   payload past this threshold to guarantee bypass.
2. **500 ms parse timeout** (`PARSER_TIMEOUT_MICROS = 500_000`): Adversarially
   crafted source (deeply nested ASTs, O(n²) grammar ambiguities) can force a
   timeout, causing the file to be skipped with `Severity::Exhaustion` and no
   security findings emitted.

These thresholds are correct for high-velocity PR gating (sub-second latency
requirement) but unacceptable as the sole defence for comprehensive audits.

#### Solution — `--deep-scan` flag

**v9.0.x — `--deep-scan` mode in `janitor bounce`:**  
When `--deep-scan` is active:
- File size limit raised from 1 MiB to 32 MiB (configurable via
  `[forge] deep_scan_max_bytes` in `janitor.toml`)
- Parse timeout raised from 500 ms to 30 s per file
- `Severity::Exhaustion` findings are re-attempted with the extended timeout
  before being suppressed
- Parallelism capped at `Pulse::Constrict` level (2 workers) to prevent OOM

**Intended invocation:** scheduled nightly CI job (`janitor bounce --deep-scan`
on the full repo diff since last release tag), not the per-PR fast path.

**Constitutional note:**  
The 1 MiB / 500 ms limits on the fast path remain unchanged. `--deep-scan`
is an opt-in mode, not a replacement. The Physarum `Stop` gate still applies
even in deep-scan mode — RAM pressure can still abort a file.

**Definition of Done:**
- `--deep-scan` flag parsed in `cmd_bounce`; `ForgeConfig` gains
  `deep_scan_max_bytes: Option<u64>` and `deep_scan_timeout_us: Option<u64>`
- Unit test: 2 MiB synthetic file skipped on fast path, processed on deep-scan path
- `cargo test` covers Exhaustion retry logic under deep-scan

---

### Roadmap Summary

| VULN | Solution | Target | Priority |
|---|---|---|---|
| VULN-01 | `--soft-fail` + Sovereign Governor binary | v9.0.x / v9.1.x | P0 |
| VULN-02 | `--pqc-key` BYOK local attestation | v9.0.x | P0 |
| VULN-03 | `ScmContext` auto-detect abstraction | v9.0.x / v9.1.x | P1 |
| VULN-04 | `--deep-scan` flag, 32 MiB / 30 s limits | v9.0.x | P1 |

---

## Executable Surface Gaps

*Source: Omniscient Coverage Audit — 2026-04-02*  
*Recon tool: `tools/omni_coverage_mapper.sh` across 15 enterprise repos (~250k paths)*

### Current Grammar Coverage (23 languages)

| Extension(s) | Language | Depth |
|---|---|---|
| rs | Rust | AST |
| py | Python | AST |
| ts, tsx | TypeScript / TSX | AST |
| js, jsx, mjs, cjs | JavaScript / JSX | AST |
| go | Go | AST |
| java | Java | AST |
| cs | C# | AST |
| cpp, cxx, cc, hpp, hxx | C++ | AST |
| c, h | C | AST |
| rb | Ruby | AST |
| php | PHP | AST |
| swift | Swift | AST |
| kt, kts | Kotlin | AST |
| scala | Scala | AST |
| lua | Lua | AST |
| tf, hcl | HCL / Terraform | AST |
| nix | Nix | AST |
| gd | GDScript | AST |
| glsl, vert, frag | GLSL | AST |
| m, mm | Objective-C / C++ | AST |
| sh, bash, cmd, zsh | Bash | AST |
| yaml, yml | YAML | byte |

### Identified Executable Gaps

| Rank | Extension | Count | Class | Risk |
|---|---|---|---|---|
| 1 | Dockerfile (no ext) | ∞ | container | Critical — supply chain |
| 2 | xml | 1 439 | infra / config | Critical — XXE |
| 3 | proto | 481 | RPC contract | High — deser gadget |
| 4 | bzl, bazel | 473 | build system | High — unverified fetch |
| 5 | cmake | 48 | build system | High — build injection |

Non-executable (excluded): `json`, `pbtxt`, `md`, `mlir`, `css`, `html`,
`svg`, `png`, `avif`, `lock`, `snap`, `rast`, `mir`.

### Proposed AST Gates

**Gate 1 — `security:dockerfile_pipe_execution` (Critical, 50 pts)**  
Grammar: `tree-sitter-dockerfile` | Trigger: `RUN … | bash/sh`  
Rationale: supply-chain execution; XZ Utils backdoor class.

**Gate 2 — `security:xxe_external_entity` (Critical, 50 pts)**  
Grammar: `tree-sitter-xml` | Trigger: `DOCTYPE … SYSTEM/PUBLIC`  
Rationale: OWASP A05, CWE-611; Spring/Java/Android attack surface.

**Gate 3 — `security:protobuf_any_type_field` (High, 50 pts)**  
Grammar: `tree-sitter-proto` | Trigger: `google.protobuf.Any` field in RPC message  
Rationale: arbitrary-message gadget chain via attacker-controlled `type_url`.

**Gate 4 — `security:bazel_unverified_http_archive` (Critical, 50 pts)**  
Grammar: `tree-sitter-starlark` | Trigger: `http_archive()` without `sha256`  
Rationale: mirrors Nix-1 gate; supply-chain tarball substitution.

**Gate 5 — `security:cmake_execute_process_injection` (High, 50 pts)**  
Grammar: `tree-sitter-cmake` | Trigger: `execute_process(COMMAND ${VAR})`  
Rationale: build-time RCE via user-controlled toolchain variable.

### Script Limitation: Extension-Less Files

`awk -F'.' 'NF>1'` silently drops `Dockerfile`, `Makefile`, `BUILD`,
`Gemfile`, `Jenkinsfile`. Secondary pass via `git ls-files | awk -F'.' 'NF==1'`
confirms their presence. Extend `omni_coverage_mapper.sh` to capture these.

---

## 2026-04-03 — Architectural Insights

### IDEA-001: Semantic CST Diff Engine — Structural Patch Analysis

**Class:** Core Engine Enhancement  
**Priority:** P1  
**Inspired by:** `crates/forge/src/hashing.rs::AstSimHasher`, VULN-04 blind spots

**Observation:**  
The current bounce engine operates on line-level unified diffs. Two diffs that
are semantically identical (e.g., a variable rename + reorder of function
arguments) produce different line hashes, inflating the `LshIndex` clone
detection false-negative rate. Conversely, a malicious payload inserted via a
whitespace-only formatting change can evade the diff pre-filter.

**Proposal:**  
Replace the line-diff input to `find_slop()` with a **Concrete Syntax Tree
(CST) diff** computed via tree-sitter's built-in incremental parsing. Given
the old and new source for each file:

1. Parse both versions with the appropriate grammar.
2. Compute the minimal edit sequence on the CST (node insertions, deletions,
   replacements) using a tree-edit-distance algorithm (Zhang-Shasha, O(n²)).
3. Feed only the *changed subtrees* into the slop detectors — not the whole
   file diff.

**Security impact:**  
- Eliminates whitespace-padding evasion (VULN-04 class).
- Reduces false positive `logic_erasure` flags for pure refactors that
  preserve branch structure.
- Enables sub-file granularity: a 10 MiB file with a 3-node AST change is
  no longer circuit-breakered by the 1 MiB limit.

**Implementation path:**  
`crates/forge/src/cst_diff.rs` (new) → `CstDelta { added: Vec<Node>, removed: Vec<Node> }` → wire into `PatchBouncer::bounce()` as an optional fast path when `--cst-diff` flag is active.

---

### IDEA-002: Provenance-Aware KEV Escalation

**Class:** Threat Intelligence Integration  
**Priority:** P0  
**Inspired by:** `crates/forge/src/slop_hunter.rs::find_kev_slop`,
`crates/anatomist/src/manifest.rs::find_version_silos_from_lockfile`, VULN-02

**Observation:**  
The KEV gate (`Severity::KevCritical`, 150 pts) currently fires only when
a patch contains a *syntactic pattern* matching a known exploit class (SQLi
concatenation, SSRF, path traversal). This requires the attacker to introduce
code that *uses* the vulnerable function. But the most common real-world
scenario is different: a dependency upgrade silently introduces a version that
*contains* a CVE-listed vulnerability, with no change to the calling code.

**Proposal:**  
Extend `janitor_dep_check` to correlate the resolved dependency tree against
the CISA KEV catalog (already fetched via `update-wisdom`):

1. For each direct + transitive dep in `Cargo.lock`, query the local
   `wisdom.db` for KEV entries matching the crate + version range.
2. If a match is found, synthesize a `SlopFinding` with
   `severity: KevCritical`, `category: "supply_chain:kev_dependency"`, and
   the CVE ID in `description`.
3. The finding is emitted into the bounce result even if the patch itself
   contains no dangerous code.

**Security impact:**  
Closes the gap between "dep is vulnerable" and "patch uses the vulnerable
codepath." A `cargo add serde_json@1.0.94` that pulls in a KEV-listed transitive
dep becomes a hard block at `slop_score >= 150` before the PR is merged.

**Implementation path:**  
`crates/anatomist/src/manifest.rs::check_kev_deps(lockfile, wisdom_db)`  
→ returns `Vec<SlopFinding>` with `KevCritical` severity  
→ merged into `PatchBouncer::bounce()` result alongside structural findings.

---

### IDEA-003: Adversarial Grammar Stress Harness

**Class:** Defensive Hardening / Fuzzing  
**Priority:** P1  
**Inspired by:** `PARSER_TIMEOUT_MICROS`, `Severity::Exhaustion`, VULN-04

**Observation:**  
The 500 ms parse timeout (`Severity::Exhaustion`) exists because adversarially
crafted source can drive tree-sitter into O(n²) or O(n³) parse time on certain
grammar ambiguities. Currently, the only protection is the timeout itself — we
have no systematic way to discover *which* inputs trigger worst-case parse
behaviour across all 23 grammars before a real attacker does.

**Proposal:**  
Build a `crates/fuzz` target (cargo-fuzz / libFuzzer) for each grammar that:

1. Takes arbitrary bytes as input.
2. Attempts to parse with the grammar under a 100 ms budget.
3. If the parse exhausts the budget, records the input as a new
   `Severity::Exhaustion` Crucible fixture.
4. Runs as a scheduled CI job (nightly, 30 min budget per grammar).

Any input that causes Exhaustion becomes a permanent regression fixture in
`crates/crucible/src/main.rs`. The deep-scan mode (`--deep-scan`, VULN-04
solution) is then validated against these fixtures to confirm the extended
timeout handles them without OOM.

**Implementation path:**  
`crates/fuzz/fuzz_targets/fuzz_grammar_<lang>.rs` × 23  
→ `cargo fuzz run fuzz_grammar_py -- -max_total_time=1800`  
→ crash corpus committed to `crates/crucible/fixtures/exhaustion/`

**Wild pivot:**  
Feed the fuzzer corpus into an LLM-guided mutator that generates *semantically
valid* source (not random bytes) to probe higher-level ambiguities in the
grammar (e.g., deeply nested closures in Kotlin, recursive HCL modules).
This shifts the threat model from syntactic to semantic exhaustion attacks.

---

## Continuous Telemetry — 2026-04-03

**Found during:** VULN-01 Remediation (Soft-Fail Mode, v9.0.0)

### CT-001: `BounceLogEntry` struct literals are not `Default`-derivable
**Found during:** VULN-01 Remediation  
**Location:** `crates/cli/src/report.rs:321`  
**Issue:** `BounceLogEntry` does not derive `Default`, forcing every callsite
to enumerate all fields in full struct literals.  Adding a new field (as done
in this directive with `governor_status`) requires updating every literal
across `main.rs`, `daemon.rs`, `git_drive.rs`, `cbom.rs`, and test helpers.
The spread of callsites creates a maintenance burden and a regression surface
on each schema evolution.  
**Suggested fix:** Derive `Default` on `BounceLogEntry` (all fields have
sensible zero/empty/None defaults) and switch existing struct literals to
`BounceLogEntry { field: value, ..Default::default() }`.  This also enables
cleaner test fixtures with minimal initialisation boilerplate.

### CT-002: Degraded attestation has no SIEM visibility path
**Found during:** VULN-01 Remediation  
**Location:** `crates/cli/src/main.rs` (soft_fail match arm)  
**Issue:** When `governor_status: "degraded"` is written to the local NDJSON
log, there is no mechanism to forward the degraded event to the configured
webhook endpoint.  An operator running soft-fail mode will see the warning on
`stderr` but the outbound webhook (Slack, SIEM, Teams) will not receive a
`degraded_attestation` event.  A governance auditor reviewing the webhook feed
would have no signal that some CI runs proceeded without attestation.  
**Suggested fix:** Add a `"degraded_attestation"` event class to
`WebhookConfig::events` filter and fire `fire_webhook_if_configured` in the
soft-fail match arm, passing a synthetic `governor_status: "degraded"` entry.
