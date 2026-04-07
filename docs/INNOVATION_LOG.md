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

### P1-2: Threshold-Signed Intel Mirror Quorum

**Class:** Sovereign Supply Chain / Feed Resilience

**Observation:**
The Wisdom feed is now signature-verified, but it is still operationally
anchored to a single CDN retrieval path. In a sanctions event, regional outage,
or targeted routing disruption, enterprises will need mathematically equivalent
feed acceptance from multiple mirrors without relaxing provenance guarantees.

**Proposal:**
Introduce a mirror-quorum receipt flow where `update-wisdom` can fetch the same
`wisdom.rkyv` plus detached signatures from multiple sovereign endpoints,
require a threshold of matching BLAKE3 digests, and emit a compact mirror
receipt proving which authorities agreed on the accepted archive.

**Security impact:**
Eliminates single-distribution trust assumptions while preserving strict
fail-closed provenance under hostile network or geopolitical conditions.

**Implementation path:**
Extend `JanitorPolicy` with a feed mirror set and quorum threshold, add a
`WisdomMirrorReceipt` structure in `common`, and bind the accepted mirror set
into `update-wisdom`, bounce logs, and CBOM metadata.

## P2 — Architecture / Ergonomics

### P2-1: Exhaustion Corpus Promotion Pipeline

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
