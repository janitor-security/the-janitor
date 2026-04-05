# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

### P0-4: Deterministic Slopsquating Interceptor

**Class:** AI Supply Chain Defense
**Inspired by:** package hallucination drift observed in AI-authored import surfaces

**Observation:**
The engine can already flag zombie dependencies after manifests land, but it has
no O(1) pre-resolution gate for LLM-hallucinated package namespaces at the AST
import layer. That leaves a gap between the first fake import and later manifest
or lockfile validation.

**Proposal:**
Implement an `rkyv`-backed Bloom filter of known LLM-hallucinated package
namespaces and cross-reference it against AST import nodes, emitting
`security:slopsquat_injection` as a critical bounce when a namespace matches.

**Security impact:**
Intercepts typo-free AI supply-chain injections before dependency resolution,
shrinking the window where a fabricated package name can enter review or artifact
generation.

**Implementation path:**
Add a compact namespace filter in `crates/common/src/wisdom.rs`, load it into
`PatchBouncer`, and thread import-node lookups through `slop_hunter.rs` for
Python, JS/TS, Rust, Go, and package-manager manifests.

### P0-5: Wasm BYOR (Bring Your Own Rule)

**Class:** Enterprise Governance
**Inspired by:** repeated customer demand for proprietary detector logic without forks

**Observation:**
Enterprises that need private AST rules must currently fork the engine or wait
for upstream additions. That creates governance drift, slows adoption, and makes
customer-specific policy impossible to ship without source divergence.

**Proposal:**
Integrate a lightweight WebAssembly runtime so enterprises can compile
proprietary AST rules into `.wasm` modules and mount them via
`janitor bounce --wasm-rules ./corp.wasm`, enabling zero-fork custom governance.

**Security impact:**
Allows closed-world policy enforcement on sovereign infrastructure without
exposing proprietary heuristics or weakening the deterministic core engine.

**Implementation path:**
Add a sandboxed Wasm rule host in `crates/forge`, define a stable ABI for
serialized findings and parsed-node views, and expose module loading through
`crates/cli/src/main.rs` plus policy controls in `crates/common/src/policy.rs`.

### P0-6: FIPS 205 (SLH-DSA) Stateless Signatures

**Class:** Post-Quantum Cryptography
**Inspired by:** long-horizon CBOM permanence beyond stateful key-management assumptions

**Observation:**
The current CBOM attestation path relies solely on ML-DSA-65. That is strong,
but it does not offer a hash-based stateless companion for environments that
want absolute post-quantum permanence and diversity against lattice-family risk.

**Proposal:**
Implement the SLH-DSA hash-based signature scheme as a companion to ML-DSA-65 so
CBOMs can optionally carry a second, stateless FIPS 205 signature.

**Security impact:**
Introduces cryptographic diversity and immutable long-term verification paths for
artifact attestations that may need to survive decades of compliance retention.

**Implementation path:**
Add a parallel signing backend in `crates/common/src/pqc.rs`, extend the CBOM
envelope to carry dual-signature metadata, and update `verify-cbom` to validate
ML-DSA, SLH-DSA, or both under explicit policy.

## P1 — Compliance / Integration

### P1-3: Wisdom Manifest Is Metadata, Not KEV Authority

**Class:** Infrastructure / Threat Intel Integrity
**Inspired by:** `crates/common/src/wisdom.rs::resolve_kev_database`

**Observation:**
`.janitor/wisdom_manifest.json` is a diffable metadata snapshot for CI review.
It does not contain package-ecosystem/version binding rules and cannot drive
dependency KEV correlation on its own.

**Proposal:**
Split the manifest and archive responsibilities explicitly in the docs and
sync pipeline so `wisdom_manifest.json` is never treated as a functional
replacement for `wisdom.rkyv`.

**Security impact:**
Prevents CI and MCP operators from assuming KEV coverage exists when the
binding archive is absent, corrupted, or replaced with manifest-only state.

**Implementation path:**
Clarify the contract in `update-wisdom`, the docs CDN bootstrap, and the MCP
dependency-check surface so archive absence is surfaced immediately.

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

### P2-3: Release Surface Parity Gate

**Class:** Defensive Hardening
**Inspired by:** `justfile` and release command drift across operator surfaces

**Observation:**
Documented release entrypoints can silently diverge from the actual linearized
execution graph. The `v9.5.1` burn incident exposed a failure mode where
unstaged-worktree reasoning published a tag for the previous `HEAD` rather than
the staged payload.

**Proposal:**
Add a release-surface parity test that asserts all documented entrypoints resolve
to the same `audit → fast-release` path, and prove the emitted commit/tag pair
contains the audited payload.

**Security impact:**
Preserves symmetric-failure semantics while preventing redundant release work
from masking regressions.

**Implementation path:**
Add a shell regression in `tools/tests/` that parses `justfile`,
`.agent_governance/commands/release.md` for consistency. Add a second regression
that stages a synthetic change, runs the recipe in fixture mode, and asserts a
new commit is created before tag emission.

### P2-4: Filename-Aware Surface Routing Spine

**Class:** Core Engine Plumbing
**Inspired by:** Extensionless security surfaces in P0-1 execution

**Observation:**
Semantic routing still keys off file extensions alone. High-value build and
control-plane files (`Dockerfile`, `CMakeLists.txt`, `BUILD`, `BUILD.bazel`,
`WORKSPACE`, `MODULE.bazel`) carry semantics via canonical filename, not suffix.

**Proposal:**
Introduce a `SurfaceKind` classifier in `common` that resolves from
`Path + shebang + diff metadata` to a stable semantic target. Thread it through
`PatchBouncer`, `bounce_git`, `slop_hunter`, and the MCP response envelope.

**Security impact:**
Eliminates silent coverage gaps on extensionless build files and creates a single
authoritative routing layer for size limits, parser budgets, and domain policy.

**Implementation path:**
Add `crates/common/src/surface.rs` with `SurfaceKind` classification helpers;
replace `extract_patch_ext()` string returns; update MCP serialization.
