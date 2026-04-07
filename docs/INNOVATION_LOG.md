# Innovation Log

Active architectural debt only. Completed work, resolved telemetry, and legacy
ID epochs are purged during hard compaction.

---

## P0 — Core Security

### CT-011: IntelTransferCapsule JSON deserialization — no size guard (8GB Law violation)

**File:** `crates/cli/src/main.rs::cmd_import_intel_capsule`

**Gap:** `serde_json::from_slice(&raw)` deserializes the full JSON payload before
any size check. A crafted capsule with a multi-hundred-MB `wisdom_bytes` JSON array
allocates the full payload on the heap before the BLAKE3 check fires. In an air-gap
environment with limited RAM this is an OOM attack surface — a rogue USB capsule
can DoS the import workstation.

**Fix:** Read the file size before deserializing; reject if `raw.len() > 50 * 1024 * 1024`
(50 MiB hard ceiling). The wisdom feed is never legitimately that large. Add a unit
test asserting rejection at the threshold.

**TEI:** Prevents targeted DoS in IL5/IL6 import workflows. Sovereign tier blocker.

---

### CT-012: Symlink traversal in `cmd_import_intel_capsule` (path canonicalization missing)

**File:** `crates/cli/src/main.rs::cmd_import_intel_capsule`

**Gap:** The install path is constructed as `project_root.join(".janitor").join("wisdom.rkyv")`.
If `.janitor` is a symlink (or if `project_root` is a symlink), `std::fs::write` follows it
unconditionally, redirecting the wisdom write to an attacker-chosen location. A crafted
capsule import targeting a repo where `.janitor/` is a symlink to `/etc/` could overwrite
arbitrary system files if the CLI is run with elevated privileges.

**Fix:** Call `std::fs::canonicalize` on `janitor_dir` after `create_dir_all`, then verify
the canonical path has `project_root` as a prefix before writing.

**TEI:** Prevents write-anywhere privilege escalation in CI/CD pipelines running as root.

---

## P1 — Compliance / Integration

### CT-013: Taint catalog unsigned — injection via `.janitor/` directory control

**File:** `crates/forge/src/taint_catalog.rs::CatalogView::open`

**Gap:** `.janitor/taint_catalog.rkyv` is a zero-copy mmap'd file with no signature
or hash binding to the CBOM or wisdom archive. An attacker who can write to the repo
root (e.g. via a compromised CI step or a path traversal in a dependency) can inject
fake `TaintExportRecord` entries: either fabricating false-positive cross-file taint
findings (alert fatigue) or marking all helpers as clean (detection blind spot).

**Fix:** Chain a BLAKE3 hash of the taint catalog into the `DecisionCapsule` and
verify it on load. Optionally sign the catalog with the same Ed25519 key used for
wisdom verification.

**TEI:** Hardens the cross-file taint spine against supply-chain poisoning. Enterprise
audit requirement for SOC 2 Type II.

---

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

## P2 — Architecture / Ergonomics

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
