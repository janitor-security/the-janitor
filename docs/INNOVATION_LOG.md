# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

## P1 — Compliance / Integration

### P1-1: Replayable Decision Capsules

**Class:** Enterprise Forensics / Audit Replay

**Observation:**
Governor-sealed receipts now prove what decision was made, but they do not yet
carry a deterministic replay capsule that lets an external auditor re-run the
decision math over the exact semantic mutation set, policy digest, and threat
intel snapshot without reconstructing state by hand.

**Proposal:**
Define a compact replay capsule format containing the semantic CST mutation
roots, `policy_hash`, `wisdom_hash`, CBOM digest, and normalized score vector.
Have `janitor-gov` countersign that capsule and add a `janitor replay-receipt`
path that deterministically re-derives the decision from the sealed evidence
bundle.

**Security impact:**
Turns enforcement evidence from “signed verdict” into independently replayable
proof, closing the last auditor objection around deterministic reenactment.

**Implementation path:**
Extend `DecisionReceipt` with a replay capsule hash, add a capsule serializer in
`common`, persist capsules next to bounce logs, and teach `verify-cbom` /
`replay-receipt` to recompute the slop score from the sealed payload.

## P2 — Architecture / Ergonomics

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

### P2-5: Exhaustion Corpus Promotion Pipeline

**Class:** Defensive Hardening / Fuzzing Operations
**Inspired by:** `crates/fuzz` and harvested AST-bomb regressions

**Observation:**
The workspace now compiles a grammar stress fuzzer, but there is still no
governed promotion pipeline that minimizes interesting crashes/timeouts and
upgrades them into permanent, signed Crucible fixtures.

**Proposal:**
Build a corpus promotion tool that minimizes libFuzzer artifacts, annotates them
with grammar + elapsed parse budget metadata, and emits deterministic exhaustion
fixtures under `crates/crucible/fixtures/exhaustion/` with matching regression
tests.

**Security impact:**
Converts ephemeral fuzz discoveries into durable parser-hardening evidence and
prevents regression drift on algorithmic-complexity exploits.

**Implementation path:**
Add a `tools/promote-fuzz-corpus` binary, a manifest format for harvested
payloads, and a `just promote-fuzz` command that regenerates Crucible
exhaustion tests from minimized artifacts.
