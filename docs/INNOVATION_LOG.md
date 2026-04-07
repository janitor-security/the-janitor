# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

> **FEATURE FREEZE ACTIVE: v10.0.0 RELEASE CANDIDATE.**
> Only P0 bug fixes and stability patches are permitted.
> CT-014, CT-015, CT-016 are deferred constraints tracked for v10.1.

---

## P0 — Core Security

<!-- CT-011 RESOLVED v9.9.19: 50 MiB size guard added to cmd_import_intel_capsule -->
<!-- CT-012 RESOLVED v9.9.19: canonicalize + starts_with confinement check added -->
<!-- CT-013 RESOLVED v10.0.0-rc.1: BLAKE3 catalog_hash bound into DecisionCapsule -->

## P1 — Compliance / Integration (Deferred to v10.1)

### CT-014: Cross-file taint — member-expression call chains not detected

**File:** `crates/forge/src/taint_catalog.rs::walk_js_calls`, `walk_python_calls`,
`walk_java_calls`, `walk_go_calls`

**Gap:** All four language scanners check only direct-identifier callees
(`identifier` node kind). Method call chains — `obj.dangerousSink(tainted)`,
`self.db_helper(user_input)`, `this.queryRunner.execute(payload)` — produce
`member_expression` / `attribute` / `selector_expression` function nodes, which
the current code silently skips. A helper that is a class method (the common case
in Java, Python, and TypeScript) is invisible to the cross-file detector.

**Fix:** Extend each language walker to also match `member_expression` (JS/TS),
`attribute` (Python), and `selector_expression` (Go) function nodes, extracting the
method name from the `property` / `attr` / `field` child and checking it against the
catalog. Add true-positive Crucible fixtures covering `obj.sink(tainted)` patterns.

**TEI:** This gap covers the majority of real-world cross-file sink patterns in
enterprise Java and TypeScript codebases. Fixing it expands the detectable attack
surface by an estimated 3×.

---

### CT-015: Wasm host — fuel budget allows indirect memory pressure

**File:** `crates/forge/src/wasm_host.rs`

**Gap:** The `WasmHost` enforces `memory_limit_bytes` as a linear-memory page ceiling
and `fuel` as an instruction budget, but a guest that allocates near the memory ceiling
within the fuel budget can cause host-side allocator fragmentation. On Linux this
manifests as `MADV_DONTNEED` latency spikes rather than OOM — the host does not crash
but scan latency becomes non-deterministic, violating the 500 ms Crucible budget.

**Fix:** Add a per-execution wall-clock timeout (100 ms) in `wasm_host.rs` alongside
the fuel gate. The timeout fires via `wasmtime`'s epoch interruption mechanism, which
does not require polling from the host thread. Add a Crucible test confirming that a
tight-loop Wasm module times out within the wall-clock budget even if it stays within
fuel.

**TEI:** Prevents BYOR governance modules from degrading CI scan latency on adversarial
or buggy rule modules. Sovereign tier quality gate.

---

## P2 — Architecture / Ergonomics (Deferred to v10.1)

### CT-016: ByteLatticeAnalyzer false-positives on UTF-16 encoded source files

**File:** `crates/forge/src/agnostic_shield.rs::ByteLatticeAnalyzer::classify`

**Gap:** `ByteLatticeAnalyzer` classifies by raw byte entropy. UTF-16 encoded source
files (valid on Windows — some MSVC-generated headers, legacy VB.NET projects) have a
BOM (`FF FE` or `FE FF`) and wide-char byte patterns that fall in the
`AnomalousBlob` entropy band. These are legitimate source files, not payloads.
The false positive adds 50 points and fires `AnomalousBlob` in the CBOM without a CVE
or structural finding.

**Fix:** Detect UTF-16 LE/BE BOM at bytes 0–1 in `classify`. If found, transcode to
UTF-8 before entropy analysis. Alternatively, classify BOM-present files as
`ProbableCode` unconditionally — the BOM itself is proof of textual encoding intent.

**TEI:** Eliminates false positives on Windows-adjacent repos (Azure SDK, Windows
drivers). Unblocks enterprise adoption in Windows-heavy shops currently seeing
spurious Critical findings.
