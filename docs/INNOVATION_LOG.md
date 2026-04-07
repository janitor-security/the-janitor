# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

## P1 — Compliance / Integration

### P1-1: Wasm Policy Module Provenance

**Class:** Enterprise Governance / Audit Provenance

**Observation:**
Replay capsules now seal the decision math, but they still do not prove which
private Wasm rule modules participated in the decision. Once enterprise BYOR
rules are mounted, an auditor will need cryptographic evidence of the exact
module hash, ABI version, and invocation order that influenced the final score.

**Proposal:**
Add a `WasmPolicyReceipt` envelope that records the BLAKE3 digest, declared
rule ID, ABI version, and result vector for every loaded Wasm governance module.
Bind those module receipts into the replay capsule, Governor decision receipt,
and CBOM so offline verification can prove which private policies fired without
revealing the module source.

**Security impact:**
Closes the last enterprise governance blind spot by turning opaque private-rule
execution into sealed, replayable provenance rather than an unverifiable black
box.

**Implementation path:**
Introduce `crates/common/src/wasm_receipt.rs`, extend the Wasm host to emit
deterministic per-module result digests, and thread those receipts through
`DecisionCapsule`, `SignedDecisionReceipt`, `verify-cbom`, and
`replay-receipt`.

## P2 — Architecture / Ergonomics

### P2-1: Filename-Aware Surface Routing Spine

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

### P2-2: Exhaustion Corpus Promotion Pipeline

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
