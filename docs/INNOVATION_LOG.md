# Innovation Log

Autonomous architectural insights, structural gap observations, intelligence
ledgers, and forward-looking feature proposals. Maintained by the Evolution
Tracker skill. Entries are organized by priority tier and dated at creation.

**CISO Pulse Audit completed 2026-04-03 (v9.1.1).** All entries re-tiered
into P0/P1/P2. Twelve new grammar depth rules added. Redundant ideas merged.
Low-value noise dropped.

---

## P0 — Enterprise Security Depth

*Grammar-first. Every language construct without an AST gate is a liability
a CISO cannot sign off on. P0 entries are the reason enterprises select
the Janitor over byte-pattern scanners.*

---

### Grammar Depth: Go — 3 New Detection Rules

**Languages to target:** Go (current AST coverage: 2 rules — `exec.Command`
shell interpreter, `InsecureSkipVerify`)

**Go-3 — `security:sql_injection_concatenation` (KevCritical, 150 pts)**
`[COMPLETED — v9.1.4]`
- Implemented in `find_go_danger_nodes()` — AST walk on `call_expression` with
  `selector_expression` field in `{Query,Exec,QueryRow,QueryContext,ExecContext}`;
  fires when first arg is `binary_expression{+}` with at least one non-literal operand.
- Crucible: TP (`db.Query("..." + userID)`) + TN (parameterized `db.Query("?", id)`)
- 3 unit tests: dynamic fires, literal-concat safe, parameterized safe

**Go-4 — `security:unsafe_pointer_cast` (Critical, 50 pts)**
- **Trigger:** `call_expression` matching `unsafe.Pointer(expr)` inside
  a type conversion `(*T)(unsafe.Pointer(...))` where the inner expression
  is not an address-of literal.
- **Suppress if:** inside a function named with `ffi`, `cgo`, or `bridge`.
- **AST node:** `type_conversion_expression → call_expression{unsafe.Pointer}`
- **File:** `crates/forge/src/slop_hunter.rs::find_go_slop()`
- **CVE class:** CWE-843 (type confusion), memory safety

**Go-5 — `security:path_traversal_http_serve` (KevCritical, 150 pts)**
- **Trigger:** `call_expression` matching `http.ServeFile|os.Open|os.ReadFile`
  where the path argument is a `binary_expression{+}` containing a variable.
- **Suppress if:** path is a `interpreted_string_literal` (constant).
- **AST node:** `call_expression{http.ServeFile|os.Open} → argument → binary_expression{+}`
- **File:** `crates/forge/src/slop_hunter.rs::find_go_slop()`
- **CVE class:** CWE-22 (path traversal), OWASP A01

---

### Grammar Depth: Rust — 3 New Detection Rules

**Rust current AST coverage:** 2 rules — `mem::transmute`, raw pointer deref.

**Rust-3 — `security:unsafe_slice_from_raw_parts` (Critical, 50 pts)**
- **Trigger:** `call_expression` matching `from_raw_parts|from_raw_parts_mut`
  inside an `unsafe` block where the pointer argument is not an address-of
  expression (`&arr[0]` is acceptable; a variable is not).
- **Suppress if:** function name contains `ffi`, `raw`, `sys`, `extern`.
- **AST node:** `unsafe_block → call_expression{from_raw_parts}`
- **File:** `crates/forge/src/slop_hunter.rs::find_rust_slop()`
- **CVE class:** CWE-119 (buffer overflow / out-of-bounds read)

**Rust-4 — `security:smart_ptr_from_raw` (Critical, 50 pts)**
- **Trigger:** `call_expression` matching `Box::from_raw|Arc::from_raw|Rc::from_raw`
  inside an `unsafe` block; any argument.
- **Suppress if:** function name contains `ffi`, `raw`, `extern`.
- **Rationale:** `from_raw` reconstructs ownership from a raw pointer; misuse
  causes use-after-free or double-free.
- **AST node:** `unsafe_block → call_expression{Box::from_raw|Arc::from_raw|Rc::from_raw}`
- **File:** `crates/forge/src/slop_hunter.rs::find_rust_slop()`
- **CVE class:** CWE-416 (use-after-free), CWE-415 (double-free)

**Rust-5 — `security:process_command_injection` (KevCritical, 150 pts)**
- **Trigger:** `call_expression` matching `Command::new(expr)` where `expr`
  is not a `string_literal` — i.e., the executable name is user-influenced.
- **Suppress if:** function is `#[test]` or name contains `test`.
- **Rationale:** `Command::new(user_input)` is direct OS command injection
  with no shell interpolation needed; more dangerous than shell=True Python
  equivalents.
- **AST node:** `call_expression{Command::new} → argument` (non-literal)
- **File:** `crates/forge/src/slop_hunter.rs::find_rust_slop()`
- **CVE class:** CWE-78 (OS command injection)

---

### Grammar Depth: Java — 3 New AST-Level Rules `[COMPLETED — v9.1.2]`

**Java-1 `[COMPLETED — v9.1.2]`** — `readObject()` upgraded to `KevCritical`;
test-method suppression added; existing `find_java_slop` extended.

**Java-2 `[COMPLETED — v9.1.2]`** — `Runtime.getRuntime().exec()` upgraded to
`KevCritical`; `new ProcessBuilder(expr)` non-literal detection added.

**Java-3 `[COMPLETED — v9.1.2]`** — `DocumentBuilderFactory.newInstance()`
without XXE hardening fires `security:xxe_documentbuilder` at `Critical`.

---

### Grammar Depth: Python — 3 New Detection Rules

**Python current AST coverage:** SQLi concatenation, SSRF dynamic URL, path
traversal concatenation. Missing deserialization and shell-injection vectors.

**Python-1 — `security:pickle_deserialization` (KevCritical, 150 pts)**
- **Trigger:** `call{pickle.loads|pickle.load}` where the argument is not a
  `bytes` literal.
- **Suppress if:** inside a function named `test*` or `*_test`.
- **AST node:** `call → attribute{pickle.loads|pickle.load}`
- **File:** `crates/forge/src/slop_hunter.rs::find_python_slop()`
- **CVE class:** CWE-502; countless ML-pipeline supply chain attacks
  (pickle is the serialization format for PyTorch, scikit-learn model files)

**Python-2 — `security:yaml_unsafe_load` (Critical, 50 pts)**
- **Trigger:** `call{yaml.load}` where the `keywords` list does NOT contain
  a `keyword_argument` with key `Loader`.
- **Suppress if:** inside a function named `test*`.
- **Rationale:** `yaml.load(data)` without `Loader=yaml.SafeLoader` executes
  arbitrary Python objects embedded in YAML.
- **AST node:** `call → attribute{yaml.load}` → assert no `Loader=` keyword
- **File:** `crates/forge/src/slop_hunter.rs::find_python_slop()`
- **CVE class:** CVE-2017-18342; OWASP A08 (software/data integrity)

**Python-3 — `security:subprocess_shell_injection` (KevCritical, 150 pts)**
- **Trigger:** `call{subprocess.Popen|subprocess.call|subprocess.run|subprocess.check_call}`
  where a `keyword_argument{shell=True}` is present AND the first positional
  argument is not a `string` literal.
- **Suppress if:** inside a function named `test*`.
- **Rationale:** `shell=True` combined with a non-literal first arg passes
  user input to `/bin/sh -c`, enabling full OS command injection.
- **AST node:** `call{subprocess.*}` with `keyword_argument{shell: True}`
  and non-literal first arg
- **File:** `crates/forge/src/slop_hunter.rs::find_python_slop()`
- **CVE class:** CWE-78; the most common Python pentest finding

---

### IDEA-002: Provenance-Aware KEV Escalation — Dependency × CVE Correlation

**Class:** Threat Intelligence Integration
**Priority:** P0
**Inspired by:** `crates/anatomist/src/manifest.rs::find_version_silos_from_lockfile`

**Observation:**
The KEV gate (`Severity::KevCritical`, 150 pts) fires only when a patch
contains a *syntactic pattern* matching a known exploit class. The most common
real-world scenario is different: a dependency upgrade silently introduces a
version that *contains* a CVE-listed vulnerability, with no change to the
calling code.

**Proposal:**
Extend `janitor_dep_check` to correlate the resolved dependency tree against
the CISA KEV catalog (fetched via `update-wisdom`):

1. For each direct + transitive dep in `Cargo.lock`, query the local
   `wisdom.db` for KEV entries matching the crate + version range.
2. If a match is found, synthesize a `SlopFinding` with
   `severity: KevCritical`, `category: "supply_chain:kev_dependency"`, and
   the CVE ID in `description`.
3. The finding is emitted into the bounce result even if the patch itself
   contains no dangerous code.

**Security impact:**
Closes the gap between "dep is vulnerable" and "patch uses the vulnerable
codepath." A `cargo add serde_json@1.0.94` that pulls in a KEV-listed
transitive dep becomes a hard block at `slop_score >= 150` before the PR
is merged.

**Implementation path:**
`crates/anatomist/src/manifest.rs::check_kev_deps(lockfile, wisdom_db)`
→ returns `Vec<SlopFinding>` with `KevCritical` severity
→ merged into `PatchBouncer::bounce()` result alongside structural findings.

---

### VULN-01: Sovereign Governor Binary (Long-term)

**Severity:** Critical
**Class:** Infrastructure / Reliability

The short-term `--soft-fail` mode is `[COMPLETED — v9.0.0]`. The long-term
sovereign deployment path is still open.

**Long-term (v9.1.x) — Sovereign Governor binary:**
Package the Governor as a self-contained binary (`janitor-gov`) that the
customer deploys inside their own VPC (EKS, GKE, or bare-metal). The SaaS
Fly.io Governor becomes optional; `janitor bounce --governor-url
https://janitor-gov.internal` routes to the on-prem instance. Stateless-first —
PostgreSQL is optional; SQLite (`janitor-gov --storage sqlite:///.janitor/gov.db`)
is the default for air-gapped deployments.

**Definition of Done:**
- `just audit` passes with Sovereign Governor binary crate skeleton
- `cmd_bounce` routes to `--governor-url` override when set
- Integration test: custom governor URL path validates end-to-end

---

### VULN-04: `--deep-scan` Flag — Extended Parse Budget

**Severity:** High
**Class:** Detection Coverage / Evasion

**Finding:**
Two circuit breakers create exploitable blind spots:
1. **1 MiB patch skip** — files exceeding 1 MiB are skipped before
   tree-sitter parsing. A malicious actor can pad a payload past this
   threshold to guarantee bypass.
2. **500 ms parse timeout** — adversarially crafted source can force a
   timeout, causing the file to be skipped with `Severity::Exhaustion`.

**Solution — `--deep-scan` mode in `janitor bounce`:**
- File size limit raised from 1 MiB to 32 MiB (configurable via
  `[forge] deep_scan_max_bytes` in `janitor.toml`)
- Parse timeout raised from 500 ms to 30 s per file
- Parallelism capped at `Pulse::Constrict` level (2 workers) to prevent OOM

**Definition of Done:**
- `--deep-scan` flag parsed in `cmd_bounce`; `ForgeConfig` gains
  `deep_scan_max_bytes: Option<u64>` and `deep_scan_timeout_us: Option<u64>`
- Unit test: 2 MiB synthetic file skipped on fast path, processed on
  deep-scan path
- `cargo test` covers Exhaustion retry logic under deep-scan

---

## P1 — Compliance / Zero-Upload

*These entries unlock regulated-market deals (FedRAMP, DISA STIG, ISO 27001)
and multi-SCM enterprises. Not the primary reason a CISO buys the product,
but hard blocks on procurement if absent.*

---

### Executable Surface Gaps — 5 New Grammar Extensions

**Current grammar coverage:** 23 languages, all AST depth.
**Unmapped critical extensions in the enterprise corpus:**

| Rank | Extension | Count | Class | Risk |
|---|---|---|---|---|
| 1 | Dockerfile | ∞ | container | Critical — supply chain |
| 2 | xml | 1 439 | infra / config | Critical — XXE |
| 3 | proto | 481 | RPC contract | High — deser gadget |
| 4 | bzl, bazel | 473 | build system | High — unverified fetch |
| 5 | cmake | 48 | build system | High — build injection |

**Proposed AST gates:**

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

---

### IDEA-003: Adversarial Grammar Stress Harness

**Class:** Defensive Hardening / Fuzzing
**Priority:** P1
**Inspired by:** `PARSER_TIMEOUT_MICROS`, `Severity::Exhaustion`, VULN-04

**Observation:**
The 500 ms parse timeout exists because adversarially crafted source can
drive tree-sitter into O(n²) or O(n³) parse time on certain grammar
ambiguities. We have no systematic way to discover which inputs trigger
worst-case parse behaviour across all 23 grammars before a real attacker does.

**Proposal:**
Build a `crates/fuzz` target (cargo-fuzz / libFuzzer) for each grammar:
1. Takes arbitrary bytes as input.
2. Attempts to parse with the grammar under a 100 ms budget.
3. If the parse exhausts the budget, records the input as a new
   `Severity::Exhaustion` Crucible fixture.
4. Runs as a scheduled CI job (nightly, 30 min budget per grammar).

**Implementation path:**
`crates/fuzz/fuzz_targets/fuzz_grammar_<lang>.rs` × 23
→ crash corpus committed to `crates/crucible/fixtures/exhaustion/`

---

### IDEA-004: HSM / KMS Integration for `--pqc-key`

**Class:** Compliance / Key Custody
**Priority:** P1
**Inspired by:** CT-006 (v9.1.0), FedRAMP/DISA STIG requirements

**Observation:**
`--pqc-key` accepts only a path to raw private key bytes on disk. Enterprise
FedRAMP and DISA STIG deployments require that private key material NEVER
touch the runner filesystem — signing operations must be delegated to an
HSM (PKCS#11) or cloud KMS.

**Proposal (v9.2.x):**
Extend `--pqc-key` to accept:
- PKCS#11 URI: `pkcs11:token=janitor;object=mlksa-key`
- AWS KMS ARN: `arn:aws:kms:us-east-1:123456789012:key/abc-...`
- Azure Key Vault URI: `https://vault.azure.net/keys/janitor-pqc/...`

The file-path mode remains the default for air-gapped deployments. The
KMS/HSM mode requires a thin shim crate (`crates/pqc-kms`).

**Implementation path:**
`crates/cli/src/main.rs` — extend `--pqc-key` arg type; add `PqcKeySource`
enum in `crates/pqc-kms/src/lib.rs`.

---

### VULN-03: `ScmContext` Abstraction

**Severity:** High
**Class:** Portability / Ecosystem

**Finding:**
All env var resolution and webhook handling are coupled to GitHub's specific
contract (`GITHUB_SHA`, `GITHUB_REF`, GitHub App installation IDs). GitLab CI,
Bitbucket Pipelines, and Azure DevOps lock the Janitor out of ~45% of the
enterprise SCM market.

**Solution — `ScmContext` struct in `crates/common/src/scm.rs`:**
```rust
pub enum ScmProvider { GitHub, GitLab, Bitbucket, AzureDevOps, Generic }
pub struct ScmContext {
    pub provider: ScmProvider,
    pub commit_sha: String,
    pub repo_slug: String,
    pub pr_number: Option<u64>,
    pub base_ref: String,
    pub head_ref: String,
    pub token: Option<String>,
}
impl ScmContext { pub fn from_env() -> Self { … } }
```
Detection priority: `GITLAB_CI` → GitLab; `BITBUCKET_BUILD_NUMBER` →
Bitbucket; `TF_BUILD` → Azure DevOps; `GITHUB_ACTIONS` → GitHub; else Generic.

**Definition of Done:**
- `ScmContext::from_env()` detects all 4 providers in unit tests
- `cmd_bounce` uses `ScmContext` for all env var reads
- CI matrix tests GitHub + GitLab env fixture sets

---

## P2 — Operational / CLI Ergonomics

*DX improvements and maintenance items. Important for retention but not the
primary purchasing decision driver. Implement after P0 and P1 queues drain.*

---

### IDEA-001: Semantic CST Diff Engine — Structural Patch Analysis

**Class:** Core Engine Enhancement
**Priority:** P2
**Inspired by:** `crates/forge/src/hashing.rs::AstSimHasher`, VULN-04

**Observation:**
The current bounce engine operates on line-level unified diffs. Two diffs that
are semantically identical produce different line hashes, inflating clone
detection false-negative rate. A malicious payload inserted via a
whitespace-only formatting change can evade the diff pre-filter.

**Proposal:**
Replace the line-diff input to `find_slop()` with a CST diff computed via
tree-sitter's incremental parsing. Feed only the *changed subtrees* into the
slop detectors — not the whole file diff.

**Security impact:**
Eliminates whitespace-padding evasion. Enables sub-file granularity for
the 1 MiB circuit breaker.

**Implementation path:**
`crates/forge/src/cst_diff.rs` (new) → `CstDelta { added: Vec<Node>, removed: Vec<Node> }`
→ wire into `PatchBouncer::bounce()` as optional fast path via `--cst-diff`.

---

### CT-001: `BounceLogEntry` Default Derive

**Found during:** VULN-01 Remediation
**Location:** `crates/cli/src/report.rs`
**Issue:** `BounceLogEntry` does not derive `Default`, forcing every callsite
to enumerate all fields. Adding a new field requires updating every struct
literal across `main.rs`, `daemon.rs`, `git_drive.rs`, `cbom.rs`, and test
helpers.
**Suggested fix:** Derive `Default` on `BounceLogEntry`; switch existing
struct literals to `BounceLogEntry { field: value, ..Default::default() }`.

---

### CT-002: Degraded Attestation Has No SIEM Visibility Path

**Found during:** VULN-01 Remediation
**Location:** `crates/cli/src/main.rs` (soft_fail match arm)
**Issue:** When `governor_status: "degraded"` is written to the local NDJSON
log, there is no mechanism to forward the degraded event to the configured
webhook endpoint. A governance auditor reviewing the webhook feed would have
no signal that some CI runs proceeded without attestation.
**Suggested fix:** Add a `"degraded_attestation"` event class to
`WebhookConfig::events` filter and fire `fire_webhook_if_configured` in the
soft-fail match arm.

---

### CT-004: `just fast-release` Has No Audit Stamp Guard

**Found during:** Forward-Looking Telemetry
**Location:** `justfile` — `fast-release` recipe
**Issue:** `fast-release` skips the `audit` prerequisite on the honour-system
assumption that the caller ran `just audit` first. An operator who invokes
`just fast-release` directly will ship a binary that has never been audited.
**Suggested fix:** In `just audit`, write `.janitor/audit_stamp` containing
`git rev-parse HEAD`. In `just fast-release`, verify that `.janitor/audit_stamp`
matches `HEAD` before proceeding; abort with an actionable error if not.

---

## Continuous Telemetry — 2026-04-03 (CISO Pulse Audit, v9.1.1)

### CT-007: `update-wisdom` has no CISA KEV diff / checklist export path

**Found during:** CISO Pulse & Autonomous Clock (v9.1.1)
**Location:** `crates/cli/src/main.rs::cmd_update_wisdom`
**Issue:** `update-wisdom` downloads a binary `wisdom.rkyv` file — a format
that cannot be diffed in CI, grepped by jq, or used to generate human-readable
checklists. The CISA KEV sync workflow (`cisa-kev-sync.yml`) therefore fetches
the CISA JSON directly from `www.cisa.gov` rather than using the wisdom
registry. This bypasses the on-device sovereignty model and creates a
split-path architecture: the wisdom registry and the KEV catalog are not
unified.
**Suggested fix:** Add a `--ci-mode` flag to `update-wisdom` that, in addition
to writing `wisdom.rkyv`, emits a JSON summary
(`.janitor/wisdom_manifest.json`) listing all KEV entries in a diffable,
human-readable format. The CISA sync workflow can then use this JSON file
instead of fetching the CISA feed independently.

### CT-008: C/C++ grammars have zero AST-level detectors

**Found during:** CISO Pulse grammar depth audit
**Location:** `crates/forge/src/slop_hunter.rs`
**Issue:** `tree-sitter-c` and `tree-sitter-cpp` are loaded into the polyglot
registry but have no corresponding `find_c_slop()` or `find_cpp_slop()`
functions in `slop_hunter.rs`. All C/C++ detection is byte-level
(`binary_hunter.rs`). The following high-priority patterns have no AST gate:
`gets()` (CWE-119), `strcpy()` / `strcat()` with non-literal dest (CWE-121),
`sprintf()` / `vsprintf()` with non-literal format string (CWE-134),
`system()` with non-literal arg (CWE-78).
**Suggested fix (P0):** Implement `find_c_slop()` and `find_cpp_slop()` for
the four patterns above. C/C++ is the language most represented in CVE
exploits; having only byte-level detection is a credibility gap in enterprise
security conversations.

---

## Continuous Telemetry — 2026-04-03 (Epoch 2, Wisdom & Java Consolidation v9.1.2)

*CT counter reset to CT-001 per Logic 5 CISO Pulse epoch boundary.*

### CT-001: `utc_now_iso8601()` is file-local — not accessible across modules

**Found during:** Wisdom & Java Consolidation (v9.1.2)
**Location:** `crates/cli/src/main.rs`
**Issue:** `utc_now_iso8601()` is defined in `main.rs` as a private function.
The `--ci-mode` path in `cmd_update_wisdom` calls it directly, coupling the
timestamp implementation to a single file.  If the function is ever needed
in a library crate (e.g., `crates/common`), this will require a refactor.
**Suggested fix:** Move `utc_now_iso8601()` to `crates/common/src/` as a
`pub` utility, or introduce a thin `janitor_timestamp()` wrapper in a
shared utilities module.

### CT-002: `wisdom_manifest.json` is not committed to the repo as a baseline

**Found during:** Wisdom & Java Consolidation (v9.1.2)
**Location:** `.github/workflows/cisa-kev-sync.yml`
**Issue:** The `cisa_kev_ids.txt` snapshot is committed as part of the first
workflow run.  Until that first run executes, the diff step has no baseline
and will always output "No prior snapshot — writing baseline."  This means
the first Monday after deployment produces no PR — a confusing no-op.
**Suggested fix:** Commit an initial `.janitor/cisa_kev_ids.txt` (populated
from the current CISA KEV catalog) as part of this session, so the first
automated run produces a meaningful diff rather than a silent baseline write.

---

## Continuous Telemetry — 2026-04-03 (Epoch 2, Go SQLi Interceptor v9.1.4)

<!-- no new telemetry findings this session beyond CT-003 resolution -->
