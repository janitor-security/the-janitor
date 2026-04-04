# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

### P0-1: Parse-Forest Reuse + Interprocedural Taint Spine

**Class:** Detection Depth / Performance
**Inspired by:** `crates/forge/src/slop_hunter.rs::find_slop`

**Observation:**
`slop_hunter.rs` reparses the same file for multiple detector phases and treats
taint as statement-local rather than propagating through helper functions or
module boundaries.

**Proposal:**
Build a shared parse context per file and a lightweight taint graph that can
propagate source-to-sink signal across local helpers and exported wrappers.

**Security impact:**
Raises true-positive depth on SSRF, SQLi, path traversal, and process-launch
chains while cutting repeated parse overhead from the hot path.

**Implementation path:**
Refactor detector dispatch around shared `ParsedUnit` state plus optional
cross-file taint summaries threaded from `PatchBouncer`.

## P1 — Compliance / Integration

### P1-1: KMS / HSM Key Sources for `--pqc-key`

**Class:** Compliance / Key Custody
**Inspired by:** Enterprise attestation requirements for BYOK signing

**Observation:**
`--pqc-key` currently accepts only filesystem-backed key material, which does
not satisfy FedRAMP or DISA STIG controls requiring hardware- or KMS-isolated
private keys.

**Proposal:**
Extend `--pqc-key` to support PKCS#11 URIs and managed cloud KMS backends while
preserving file-path mode for air-gapped deployments.

**Security impact:**
Moves PQC signing into compliant custody models without changing the attestation
protocol or exposing raw private key bytes on runner disks.

**Implementation path:**
Introduce a key-source abstraction and a thin `pqc-kms` integration crate for
PKCS#11, AWS KMS, and Azure Key Vault backends.

### P1-2: SCM Context Abstraction

**Class:** Portability / Ecosystem
**Inspired by:** GitHub-specific env resolution in CLI and Action paths

**Observation:**
Bounce execution is still heavily coupled to GitHub environment variables and
App metadata, limiting portability to GitLab, Bitbucket, Azure DevOps, and
generic on-prem CI runners.

**Proposal:**
Introduce a provider-neutral `ScmContext` that normalizes commit SHA, repo
slug, PR number, refs, and auth tokens across supported SCM providers.

**Security impact:**
Expands zero-upload deployment into multi-SCM enterprises without forking the
attestation model per CI platform.

**Implementation path:**
Add `crates/common/src/scm.rs`, teach CLI entrypoints to consume it, and add
fixture-based env tests for each provider.

## P2 — Architecture / Ergonomics

### P2-1: Semantic CST Diff Engine

**Class:** Core Engine Enhancement
**Inspired by:** Diff-surface false negatives in current line-based bounce flow

**Observation:**
Line-level unified diffs lose structural intent. Semantically equivalent edits
hash differently, and whitespace or formatting churn can obscure the true
changed subtrees.

**Proposal:**
Add an incremental CST diff engine that feeds only changed subtrees into the
detectors and clone heuristics.

**Security impact:**
Improves precision, reduces whitespace-padding evasion, and enables more
granular gating on large files.

**Implementation path:**
Introduce `crates/forge/src/cst_diff.rs` and wire an optional subtree-based
path into `PatchBouncer`.

### P2-2: Grammar Stress Fuzzer

**Class:** Defensive Hardening / Fuzzing
**Inspired by:** Parse-budget exhaustion risk and AST bomb classes

**Observation:**
The engine now has deep-scan retry logic, but there is still no systematic
corpus generation for grammar-specific worst-case parse behavior.

**Proposal:**
Build nightly fuzz targets per grammar that record timeout-inducing inputs into
Crucible fixtures for permanent regression coverage.

**Security impact:**
Turns parser-exhaustion failures into harvested adversarial corpora before
attackers can weaponize them in CI.

**Implementation path:**
Add `crates/fuzz` targets and promote timeout reproducers into
`crates/crucible/fixtures/exhaustion/`.

### P2-3: Governance Bootstrap Drift Sentinel

**Class:** Governance / Consistency
**Inspired by:** Historical drift between governance entrypoints and canonical docs

**Observation:**
Bootstrap surfaces can still drift on engine version, canonical governance
root, or release instructions across local rules and operator entrypoints.

**Proposal:**
Add a deterministic governance audit that cross-checks version strings,
governance roots, and release-path documentation for parity.

**Security impact:**
Prevents stale operator surfaces from binding downstream agents to obsolete
workflow law before the firewall executes.

**Implementation path:**
Add a governance parity test spanning `Cargo.toml`, `.cursorrules`,
`.agent_governance/README.md`, and release command docs.

### P2-4: Release Surface Parity Gate

**Class:** Defensive Hardening
**Inspired by:** `justfile` and release command drift across operator surfaces

**Observation:**
Documented release entrypoints can silently diverge from the actual linearized
execution graph, reintroducing redundant audit/build paths or stale operator
instructions. The burned `v9.5.1` release exposed a second failure mode:
recipes that reason about only the unstaged worktree can publish a tag and
GitHub release for the previous `HEAD` while the real audited payload is
already staged and waiting to be committed.

**Proposal:**
Add a release-surface parity test that asserts all documented entrypoints
resolve to the same `audit -> fast-release` path, and add a release-integrity
test that proves the emitted commit/tag pair actually contains the staged
release payload rather than merely matching the pre-release `HEAD`.

**Security impact:**
Preserves symmetric-failure semantics while preventing redundant release work
from masking real regressions behind repeated compile passes.

**Implementation path:**
Add a shell regression in `tools/tests/` that parses `justfile`,
`.agent_governance/commands/release.md`, and `.cursorrules` for consistency.
Add a second regression that stages a synthetic tracked change, runs the
release recipe in fixture mode, asserts a new commit object is created before
tag emission, and fails if `vX.Y.Z` can still resolve to the pre-release
`HEAD`.

### P2-5: Filename-Aware Surface Routing Spine

**Class:** Core Engine Plumbing
**Inspired by:** Extensionless security surfaces discovered during P0-1 execution

**Observation:**
The slop firewall still keys most semantic routing off file extensions alone.
That is structurally incomplete for high-value build and control-plane files
whose semantics are carried by canonical filenames rather than suffixes:
`Dockerfile`, `CMakeLists.txt`, `BUILD`, `BUILD.bazel`, `WORKSPACE`,
`MODULE.bazel`, and many policy roots under repo-specific conventions.
P0-1 required an ad hoc filename shim in `extract_patch_ext()` to surface these
files at all. That patch closes the immediate blind spot, but it leaves the
engine without a first-class notion of "surface identity" separate from raw
extension text.

**Proposal:**
Introduce a canonical `SurfaceKind` classifier in `common` that resolves from
`Path + optional shebang + diff metadata` into a stable semantic target such as
`Dockerfile`, `CMake`, `StarlarkWorkspace`, `Proto`, `Xml`, `Rust`, or
`BinaryAsset`. Thread `SurfaceKind` through `PatchBouncer`, `bounce_git`,
`slop_hunter`, and the MCP response envelope so every detector, budget policy,
and downstream report keys off the same semantic identity rather than repeating
filename heuristics in multiple layers.

**Security impact:**
Eliminates silent coverage gaps on extensionless build files, prevents future
detectors from being added only to Crucible or only to one caller path, and
creates a single authoritative routing layer for size limits, parser budgets,
domain policy, and supply-chain findings.

**Implementation path:**
Add `crates/common/src/surface.rs` with `SurfaceKind` plus deterministic
classification helpers; replace `extract_patch_ext()` string returns with a
`SurfaceKind` return path; teach `slop_hunter::find_slop()` to dispatch on
`SurfaceKind`; update report/MCP serialization to include the resolved surface.

## Continuous Telemetry — 2026-04-04

- `CT-008: Wisdom Sync DNS Failure Resolved` — `janitor update-wisdom` now
  targets `https://thejanitor.app/v1/wisdom.rkyv` and `--ci-mode` degrades to
  a bootstrap-empty `wisdom_manifest.json` when the CDN or KEV source is
  unreachable, preventing first-run cron failure while the static registry is
  propagating.
- CT-009: P0-1 Foundation Laid — `TaintKind`, `TaintedParam`, `TaintExportRecord` in `crates/common/src/taint.rs`; `ParsedUnit<'src>` in `crates/forge/src/slop_hunter.rs`; foundational types for 3-hop cross-file taint propagation (v9.6.2)
