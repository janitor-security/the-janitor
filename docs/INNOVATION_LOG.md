# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

## P1 — Compliance / Integration

### P1-1: Air-Gap Intel Transfer Capsules

**Class:** Sovereign Distribution / Enterprise Portability

**Observation:**
Mirror quorum and feed signatures now prove online retrieval integrity, but
air-gapped operators still have to move `wisdom.rkyv`, detached signatures,
mirror receipts, and policy evidence as separate files. That manual bundle
assembly weakens custody guarantees at the exact handoff regulated buyers care
about most.

**Proposal:**
Introduce a signed `IntelTransferCapsule` that bundles the accepted
`wisdom.rkyv`, detached Ed25519 signatures, quorum mirror receipt, feed hash,
and compatible Governor / Wasm provenance metadata into one portable archive
with an offline verification command.

**Security impact:**
Preserves cryptographic chain-of-custody when threat intelligence crosses air
gaps, removable media, or sovereign mirror boundaries.

**Implementation path:**
Add `janitor export-intel-capsule` and `janitor import-intel-capsule`,
serialize the bundle under `common`, and teach `update-wisdom` to trust only
capsules whose internal receipts and archive hash agree.

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
