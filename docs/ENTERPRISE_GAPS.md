# Enterprise Gaps — CISO Vulnerability Ledger

**Classification:** Internal Architecture Review  
**Date:** 2026-04-02  
**Source:** Simulated Fortune 500 CISO teardown  
**Status:** Roadmap defined — v9.x.x neutralization track

---

## VULN-01 — Availability Coupling (SPOF)

**Severity:** Critical  
**Class:** Infrastructure / Reliability

### Finding

The Janitor CLI fails-closed when the Fly.io Governor is unreachable. Any
network partition, Fly.io maintenance window, or DNS failure halts every
CI/CD pipeline that depends on `janitor bounce`. For an enterprise deploying
the Janitor as a hard gate on PR merges, this is an unacceptable Single Point
of Failure.

### Solution — Soft-Fail Mode + Sovereign Governor

**Short-term (v9.0.x) — Soft-Fail Mode:**  
Add a `--soft-fail` flag to `janitor bounce` (and a `soft_fail = true` option
in `janitor.toml`). When the Governor is unreachable and `soft_fail` is active,
the CLI logs a structured warning (`"governor_status": "unreachable"`) to the
bounce log, emits exit code `0`, and allows the pipeline to proceed. The bounce
result is marked `"attestation": "degraded"` in the audit trail.

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

## VULN-02 — Key Custody & Compliance Theater

**Severity:** Critical  
**Class:** Cryptography / Compliance

### Finding

The current architecture implies vendor-held ML-DSA-65 (FIPS 204) signing keys
on the Fly.io Governor. Enterprises operating under FedRAMP, SOC 2 Type II, or
DISA STIG cannot delegate key custody to a SaaS vendor. Claiming post-quantum
attestation while the vendor controls the signing key is compliance theater —
the customer cannot independently verify the chain of custody.

### Solution — BYOK Local Attestation

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

## VULN-03 — SCM Lock-in

**Severity:** High  
**Class:** Portability / Ecosystem

### Finding

All environment variable resolution, webhook handling, and Check Run APIs are
coupled to GitHub's specific contract: `GITHUB_SHA`, `GITHUB_REF`,
`GITHUB_REPOSITORY`, `GITHUB_TOKEN`, GitHub App installation IDs, and the
`POST /repos/:owner/:repo/check-runs` API. GitLab CI, Bitbucket Pipelines, and
Azure DevOps have incompatible environment shapes and no equivalent "Check Run"
primitive. This locks the Janitor out of approximately 45% of the enterprise
SCM market.

### Solution — `ScmContext` abstraction

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

## VULN-04 — Hot-Path Blind Spots

**Severity:** High  
**Class:** Detection Coverage / Evasion

### Finding

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

### Solution — `--deep-scan` flag

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

## Roadmap Summary

| VULN | Solution | Target | Priority |
|---|---|---|---|
| VULN-01 | `--soft-fail` + Sovereign Governor binary | v9.0.x / v9.1.x | P0 |
| VULN-02 | `--pqc-key` BYOK local attestation | v9.0.x | P0 |
| VULN-03 | `ScmContext` auto-detect abstraction | v9.0.x / v9.1.x | P1 |
| VULN-04 | `--deep-scan` flag, 32 MiB / 30 s limits | v9.0.x | P1 |

All four solutions are non-breaking changes to the existing v8.x API surface.
The v8.x fast path (1 MiB / 500 ms / GitHub-only / Governor-required) remains
the default. The v9.x additions are strictly additive.
