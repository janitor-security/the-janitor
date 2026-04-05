# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

### P0-1: Interprocedural Taint Spine

**Class:** Detection Depth / Performance
**Inspired by:** `crates/forge/src/slop_hunter.rs::find_slop`

**Observation:**
Intra-file Go SQLi taint confirmation implemented in v9.7.1: `track_taint_go_sqli`
in `crates/forge/src/taint_propagate.rs` confirms parameter→SQL-sink flows for
the Go-3 gate. Cross-file 3-hop propagation is not yet implemented; taint
summaries cannot follow values through helper functions or module boundaries.

**Proposal:**
Extend `taint_propagate.rs` to emit `TaintExportRecord` entries into
`.janitor/taint_catalog.rkyv` and implement a 3-hop consumer in `PatchBouncer`
that follows taint across file boundaries.

**Security impact:**
Raises true-positive depth on SSRF, SQLi, path traversal, and process-launch
chains that route tainted values through one or two helper call levels — the
dominant real-world pattern in enterprise middleware.

**Implementation path:**
1. Add `TaintExportRecord` emission in `track_taint_go_sqli` after confirmed flow.
2. Implement `taint_catalog.rs` in `crates/forge/src/` for rkyv-backed catalog I/O.
3. Wire catalog lookups into `find_python_slop_ast`, `find_java_slop`, and
   `find_js_sqli_slop` for cross-file confirmation.

### P0-2: Phase 4–7 Single-Language Detectors — ParsedUnit Migration

**Class:** Architecture / Performance
**Inspired by:** `crates/forge/src/slop_hunter.rs` Phase 4–7 language gates

**Observation:**
12 single-language AST detectors (`find_go_slop`, `find_ruby_slop`,
`find_bash_slop`, `find_php_slop`, `find_kotlin_slop`, `find_scala_slop`,
`find_swift_slop`, `find_lua_slop`, `find_nix_slop`, `find_gdscript_slop`,
`find_objc_slop`, `find_rust_slop`) still create their own `tree_sitter::Parser`
instead of using `ParsedUnit::ensure_tree()`. This blocks multi-phase detector
sharing for those languages and diverges from the P0-1 architecture.

**Proposal:**
Migrate each of the 12 functions from `(eng: &QueryEngine, source: &[u8])` to
`(eng: &QueryEngine, parsed: &ParsedUnit<'_>)` using the `ensure_tree` pattern.
Add `_bytes_test` wrappers and update dispatch aliases.

**Security impact:**
Enables multi-phase taint tracking for Go, Ruby, PHP, Kotlin, Scala, Swift, Lua,
Nix, GDScript, ObjC, and Rust — same TP gains as the Python/Java/JS migration.

**Implementation path:**
Modify each of the 12 functions in `crates/forge/src/slop_hunter.rs`. Update
`find_slop()` dispatch to pass `parsed` instead of `source`. Add
`ParsedUnit::unparsed()` test wrappers for each migrated function.

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
