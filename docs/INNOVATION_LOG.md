# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

## P1 — Compliance / Integration

### P1-1: Governor-Signed Threat Intel Receipts

**Class:** Commercial Trust / Threat Intel Governance

**Observation:**
Detached signature verification closes archive tampering in transit, but the
operator still cannot prove *which* signed feed version was active for a given
bounce result or customer receipt. Feed trust is local-state correct but not yet
attestation-visible.

**Proposal:**
Emit the verified Wisdom feed hash, signature fingerprint, and receipt metadata
into Governor receipts, CBOMs, and bounce logs so every enforcement decision is
bound to a cryptographically identified threat-intel snapshot.

**Security impact:**
Prevents evidentiary drift where a finding can be challenged as having been made
against an unknown or unverifiable intel corpus.

**Implementation path:**
Extend `common::wisdom` with feed provenance metadata, thread it through
`BounceLogEntry`, Governor inclusion receipts, and exported CBOM properties.

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
