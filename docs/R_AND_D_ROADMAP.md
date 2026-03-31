# R&D Roadmap — 24-Month Supremacy Blueprint

> **Classification**: Internal Engineering Reference
> **Engine Baseline**: v8.8.0
> **AST Coverage**: 23/23 grammars (100%)
> **Horizon**: 24-Month Ecosystem Permanence Initiative

This document is the authoritative engineering blueprint. Every proposal names the exact
file, the exact function, and the exact invariant to encode. No section is aspirational
prose — each is a mechanical specification ready for implementation.

---

## I. Completed Foundation (v8.0.x — v8.7.0)

All phases in this section are gate-verified: `cargo run -p crucible` exits 0 and
`just audit` exits 0 for every entry.

| Phase | Version | Deliverables | Crucible entries |
|-------|---------|--------------|-----------------|
| Phase 1 | v8.1.0 | Java/C# AhoCorasick (JAVA_DANGER, CSHARP_DANGER patterns); Prototype Pollution Layer A | 12 |
| Phase 2 | v8.2.0 | Python AST walk (`find_python_slop_ast`); Java AST walk (`find_java_slop`; `QueryEngine::java_lang`) | 16 |
| Phase 3 | v8.3.0 | C# AST walk (`find_csharp_slop`); Prototype Pollution Layer B (`find_prototype_merge_sink_slop`); AVX-256 SIMD MinHash | 21 |
| KEV Sprint | v8.0.13 | Python/JS/Java/Go/C# SQLi gates (150 pts); Python/JS/Go SSRF gates; path traversal gates; XZ backdoor DNA | 46 |
| Phase 4 | v8.4.0 | Go AST walk (`find_go_slop`); Ruby AST walk (`find_ruby_slop`); Bash AST walk (`find_bash_slop`) | 12 |
| DFA Sprint | v8.4.1 | All 6 AhoCorasick automata forced to DFA (`AhoCorasickKind::DFA`) | — |
| Phase 5 | v8.5.0 | PHP/Kotlin/Scala/Swift AST walks; Predictive Physarum (`check_predictive_pressure`) | 18 |
| Phase 6 | v8.6.0 | Lua/Nix/GDScript/ObjC AST walks (8 new rules across 4 grammars) | 16 |
| Energy Ledger | v8.7.0 | `BounceLogEntry.ci_energy_saved_kwh`; Workslop energy row; `render_step_summary` TEI+energy banner | — |

**Current state (v8.7.0 baseline)**: 18/23 grammars had active AST security rules. 123/123 Crucible entries SANCTUARY INTACT.

| Phase 7 | v8.8.0 | Rust-1/2 (unsafe transmute + raw ptr deref); GLSL-1 (dangerous extension); HCL-1/2 (data external + local-exec provisioner); TSX-1/JSX-1 (dangerouslySetInnerHTML) | 12 |

---

## II. Grammar Capstone — Phase 7 [COMPLETED — v8.8.0]

**Target version**: v8.8.0
**Goal**: 23/23 grammar coverage (100%)
**Rationale**: The structural firewall is weakened by every grammar loaded but not inspected.
A grammar without rules is not neutral — it is a blind spot.

### 2.1 Turing-Completeness Audit of Remaining 5 Grammars

| Grammar | Turing-complete? | Attack surface at PR scope |
|---------|-----------------|---------------------------|
| **Rust** (`rs`) | Yes — general-purpose systems language | `unsafe` block misuse; `mem::transmute`; raw pointer arithmetic |
| **GLSL** (`glsl`, `vert`, `frag`) | Partial — compute shaders are Turing-complete; vertex/fragment shaders lack arbitrary I/O | WebGL extension abuse; integer overflow in array indexing; missing `discard` guard in depth writes |
| **HCL/Terraform** (`tf`, `hcl`) | No — declarative configuration DSL; no loops beyond `for_each` | `data "external"` arbitrary program execution; `provisioner "local-exec"` with non-literal command |
| **TSX** (`tsx`) | Yes — TypeScript superset | JSX `dangerouslySetInnerHTML={{ __html: expr }}` React XSS |
| **JSX** (`jsx`) | Yes — JavaScript superset | Same `dangerouslySetInnerHTML` React XSS pattern |

**Non-Turing-complete grammars (GLSL, HCL)**: Treated as high-signal data formats.
One gate per grammar, targeting the single highest-consequence pattern.

**Turing-complete grammars (Rust, TSX, JSX)**: Standard AST walk approach — pre-filter,
`QueryEngine` field, `find_<lang>_slop` function, `find_slop()` dispatch.

---

### 2.2 Gate Specifications

#### Gate Rust-1 — Unsafe Transmute

**Rule**: `unsafe { std::mem::transmute::<_, T>(expr) }` where `expr` is not a
numeric literal and the target type `T` is a pointer, reference, or function pointer.

```
node_type: unsafe_block
  descendant: call_expression
    function: scoped_identifier (text suffix == "transmute")
fire when: argument is NOT integer_literal or float_literal
label: security:unsafe_transmute
points: 50 (Critical)
suppression: function name contains "test" or "bench"
rationale: transmute circumvents the type system's memory safety guarantees;
           CVE-2020-36516 pattern class
```

**`QueryEngine` field**: `rust_lang: Language`
**Function**: `find_rust_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding>`
**`find_slop()` branch**: `"rs" => find_rust_slop(eng, source)` (existing credential scan becomes the pre-filter)

**Note**: The existing `detect_recursive_boilerplate("rs", ...)` path already uses the
Rust grammar. `QueryEngine::rust_lang` reuses the same `tree_sitter_rust::LANGUAGE` static.

#### Gate Rust-2 — Raw Pointer Dereference in Non-FFI Context

```
node_type: unsafe_block
  descendant: unary_expression (operator == "*")
    operand: identifier (type annotation is *mut T or *const T)
fire when: containing function name does NOT contain "ffi", "extern", "raw", "sys"
label: security:raw_pointer_deref
points: 50 (Critical)
suppression: file path contains "bindings" or "sys.rs" (FFI layer files)
rationale: raw pointer dereference outside FFI is almost always
           a safety violation introducible via AI-generated code
```

---

#### Gate GLSL-1 — Dangerous Extension Enablement

**Rationale**: GLSL is not Turing-complete for system I/O, but WebGL applications
running malicious shaders can abuse extensions for GPU cache timing attacks
(`GL_EXT_shader_image_load_store`) or denial-of-service via shader loop
bombs (`GL_ARB_gpu_shader_fp64`). The attack vector is not code injection but
capability escalation via extension declarations.

```
pattern: b"#extension"
byte-level scan of extension directive line:
  fire when line contains: "GL_EXT_shader_image_load_store",
                           "GL_ARB_bindless_texture",
                           "GL_NV_shader_atomic_fp16_vector",
                           "require" (as the behaviour qualifier)
label: security:glsl_dangerous_extension
points: 50 (Critical)
suppression: none (all of these are explicitly dangerous in WebGL contexts)
```

**Implementation**: `find_hcl_slop` is the byte-level template; GLSL gets a sibling
`find_glsl_slop(source: &[u8])`. No tree-sitter AST walk required — the `#extension`
directive is always on its own line, making byte scanning definitive.

**`find_slop()` branch**: `"glsl" | "vert" | "frag" => find_glsl_slop(source)`

---

#### Gate HCL-1 — External Data Source Execution

**Rationale**: HCL is not Turing-complete, but `data "external" {}` blocks execute an
arbitrary program during `terraform plan` — before any approval step. This is the
Terraform-native analogue of `eval()` and represents arbitrary code execution risk in
CI/CD pipelines that run `terraform plan` on untrusted PRs.

**Upgrade from byte-level to AST walk**:

```
node_type: block
  first_child: block_type (text == "data")
  second_child: block_label (text == "external")
fire unconditionally — there is no safe use of data "external"
  that is not worth a reviewer flag
label: security:terraform_external_exec
points: 50 (Critical)
suppression: block body contains only string literals in program list
             (static program path, not a variable reference)
```

**Gate HCL-2 — Local-Exec Provisioner**:

```
node_type: block
  first_child: identifier (text == "provisioner")
  second_child: string_lit (text == "local-exec")
  body:
    attribute key "command" whose value is NOT a string_literal
label: security:provisioner_command_injection
points: 50 (Critical)
```

**`find_slop()` change**: Replace `find_hcl_slop(source)` (byte-level) with
`find_hcl_slop_ast(eng, source)` that performs a tree-sitter walk via `HCL_LANG`
field in `QueryEngine`. Byte-level patterns are retained as the pre-filter.

---

#### Gate TSX-1 / JSX-1 — React `dangerouslySetInnerHTML`

**Rationale**: `dangerouslySetInnerHTML={{ __html: expr }}` is the canonical React XSS
vector. The JSX/TSX grammars produce a distinct `jsx_attribute` node that the existing
`find_js_slop` logic never checks — it operates on `assignment_expression` for
`innerHTML`, which is the DOM API form. JSX attribute form requires a separate walk.

```
node_type: jsx_attribute
  name: property_identifier (text == "dangerouslySetInnerHTML")
  value: jsx_expression
    descendant: pair
      key: property_identifier (text == "__html")
      value: NOT string (i.e., identifier, call_expression, template_string, binary_expression)
fire: flag the jsx_attribute node
label: security:react_xss_dangerous_html
points: 50 (Critical)
suppression: value is string_literal (static HTML is safe)
             containing function name contains "sanitize" or "purify"
CVE reference: OWASP A03:2021 Injection — XSS via JSX prop bypass
```

**Implementation**: Add `find_jsx_dangerous_html_slop(eng, source)` called from within
the existing `"js" | "jsx" | "ts" | "tsx"` branch of `find_slop()`, appended to the
result vec returned by `find_js_slop`. No new `QueryEngine` field needed — reuses
`eng.js_lang` (the TSX grammar parses JSX constructs with the same JavaScript grammar).

---

### 2.3 Phase 7 Implementation Checklist

```
Phase 7 [Target: v8.8.x]:
  ├── Rust-1/2 AST walk (Tier 1)
  │     Files: slop_hunter.rs (find_rust_slop; QueryEngine::rust_lang field)
  │            crucible/src/main.rs (TP + TN × 2 gates)
  │     find_slop dispatch: "rs" => find_rust_slop(eng, source)
  ├── GLSL-1 byte scan (Tier 2)
  │     Files: slop_hunter.rs (find_glsl_slop)
  │            crucible/src/main.rs (TP + TN × 1 gate)
  │     find_slop dispatch: "glsl"|"vert"|"frag" => find_glsl_slop(source)
  ├── HCL-1/2 AST walk upgrade (Tier 1 replacing Tier 2)
  │     Files: slop_hunter.rs (find_hcl_slop_ast; QueryEngine::hcl_lang field)
  │            crucible/src/main.rs (TP + TN × 2 gates)
  │     find_slop dispatch: "hcl"|"tf" => find_hcl_slop_ast(eng, source)
  └── TSX-1/JSX-1 JSX attribute walk (Tier 1 appended to existing handler)
        Files: slop_hunter.rs (find_jsx_dangerous_html_slop; called from js/jsx/ts/tsx branch)
               crucible/src/main.rs (TP + TN × 2 gates)
```

**Result**: `cargo run -p crucible` exits 0 with 135/135 entries SANCTUARY INTACT. `just audit` exits 0.

---

## III. Pillar I — The Janitor LSP

**Target version**: v9.0.0
**Purpose**: Surface `SlopScore` and `Critical Threats` as real-time IDE diagnostics
before commit — IDE squiggles for security antipatterns as the developer types.

### 3.1 Architecture

**New crate**: `crates/lsp`

The LSP server wraps `find_slop()` and `find_credential_slop()` into a standard
[Language Server Protocol](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/)
server communicating over stdio (universal IDE compatibility: VS Code, Neovim, Zed, Helix).

```
crates/lsp/
├── Cargo.toml
└── src/
    ├── main.rs          — stdio transport, event loop
    ├── server.rs        — LspServer struct, capability negotiation
    ├── diagnostics.rs   — SlopFinding → LSP Diagnostic conversion
    └── engine.rs        — document cache + incremental slop scan
```

**Dependency**: `lsp-server = "0.7"` (Rust Language Server project's transport crate;
no framework magic, just stdio framing). Do NOT use `tower-lsp` — async dependencies
are incompatible with the Physarum single-threaded dispatch model.

### 3.2 Core Design Constraints

| Constraint | Enforcement |
|-----------|-------------|
| `QueryEngine` initialised once at server startup, not per request | `OnceLock<QueryEngine>` in `engine.rs` |
| Debounce: scan fires 300 ms after last `textDocument/didChange` | `std::thread::sleep(Duration::from_millis(300))` + atomic sequence number check |
| Full-file scan, not diff-based | LSP provides full document text on every `didChange` (incremental sync mode) |
| Max scan latency: 500 ms | Same `PARSER_TIMEOUT_MICROS = 500_000` gate as `slop_hunter.rs` |
| No Physarum gate (editor diagnostics must never block) | LSP crate does not import `common::physarum` |

### 3.3 Capability Set (v9.0.0)

| LSP Capability | Behaviour |
|---------------|-----------|
| `textDocumentSync` | `Incremental` — full text provided on each change |
| `diagnosticProvider` | Push-based (server sends `textDocument/publishDiagnostics`) |
| `hoverProvider` | On hover over a flagged range: show antipattern description + remediation |
| `codeActionProvider` | Offer "Suppress this finding" → inserts `// janitor:ignore:<label>` comment |

### 3.4 Diagnostic Severity Mapping

```
Severity::KevCritical  → DiagnosticSeverity::Error    (red squiggle)
Severity::Exhaustion   → DiagnosticSeverity::Error
Severity::Critical     → DiagnosticSeverity::Warning  (yellow squiggle)
Severity::Necrotic     → DiagnosticSeverity::Warning
Severity::Warning      → DiagnosticSeverity::Information (blue squiggle)
```

### 3.5 VS Code Extension Wrapper

A minimal `extensions/vscode/` directory contains `package.json` (extension manifest)
and `src/extension.ts` (spawns the `janitor lsp` subprocess via `LanguageClient`).
The binary must expose a `janitor lsp` subcommand that starts the stdio server.

**CLI addition**: `crates/cli/src/main.rs` gains a `Lsp` variant in the `Subcommand`
enum, handled by `cmd_lsp()` which calls `crates/lsp::run_server()`.

---

## IV. Pillar II — Cross-File Taint Tracking

**Target version**: v9.1.0
**The Hard Problem**: Tracking a tainted user input in `file_A.rs` as it is passed to
a function in `file_B.rs` without violating the 8 GB RAM limit or the 30-second
bounce timeout.

### 4.1 Why Existing Architecture Cannot Do This

Current `find_slop()` is stateless per file — it receives `source: &[u8]` and returns
findings. It has no memory of other files. Cross-file analysis requires:

1. A persistent call graph (who calls what across files)
2. A taint propagation record (which function parameters are tainted by which sources)
3. A lookup mechanism fast enough to not blow the 30-second budget

The solution is a **pre-computed Taint Signature catalog** maintained by the daemon.

### 4.2 Taint Signature Design

**Taint Export Record (TER)**: Computed per function during `build_symbols_rkyv()`.

```rust
/// Pre-computed per-function taint record.
/// Stored in `.janitor/taint_catalog.rkyv` alongside `symbols.rkyv`.
#[derive(Archive, Serialize, Deserialize)]
pub struct TaintExportRecord {
    /// Canonical name: `module_path::function_name`
    pub fn_id: String,
    /// Which parameters may carry HTTP/OS taint
    pub tainted_params: Vec<TaintedParam>,
    /// Does the return value propagate taint from any param?
    pub return_propagates_taint: bool,
}

#[derive(Archive, Serialize, Deserialize)]
pub struct TaintedParam {
    pub index: u8,
    pub kind: TaintKind,
}

#[derive(Archive, Serialize, Deserialize)]
pub enum TaintKind {
    HttpBody,     // request body / POST data
    HttpQuery,    // URL query parameter
    EnvVar,       // std::env::var(), os.environ
    ProcessArg,   // argv[N]
    FileContent,  // file read result passed directly
    DbResult,     // query result (secondary taint)
}
```

### 4.3 Cross-File Propagation Algorithm

**Pre-compute phase** (daemon idle time, `crates/cli/src/daemon.rs`):

1. For each source file: run `find_slop(lang, source)` + taint source scan
2. For each function that directly reads HTTP/OS input: emit `TER{tainted_params: [...], return_propagates_taint: true}`
3. Serialize all TERs to `.janitor/taint_catalog.rkyv` via rkyv

**Bounce phase** (hot path, `crates/forge/src/slop_filter.rs`):

1. Load `taint_catalog.rkyv` at bounce start — O(1) mmap, zero copy
2. For each call site in the patch: extract callee name, look up in TER catalog
3. If callee TER exists and `return_propagates_taint = true`: mark the receiving variable as tainted
4. If the tainted variable flows to a sink (SQL query, shell exec, file write): fire `security:cross_file_taint_sink` at 50 pts

**RAM budget**: One TER ≈ 200 bytes average. 50,000 functions (large monorepo) = 10 MB.
Well within the 8 GB law.

**Propagation depth limit**: 3 call hops maximum. Chains deeper than 3 are deferred with
`TODO(cross-file-taint-depth)` in the finding description. This bounds worst-case
computation to O(3 × |call_sites_in_patch|).

**Fail-open semantics**: If the TER catalog is absent or the callee is not in it,
the bounce proceeds without cross-file taint analysis — no false positives, no crash.
A missing catalog is logged at `JANITOR_DEBUG=1` verbosity only.

### 4.4 Storage Contract

```
.janitor/
├── symbols.rkyv          # existing: dead symbol graph
├── bounce_log.ndjson     # existing: audit log
├── taint_catalog.rkyv    # NEW: pre-computed TERs for cross-file analysis
└── syndicate_sigs.rkyv   # (Pillar III, future)
```

---

## V. Pillar III — The Autonomous Syndicate

**Target version**: v9.2.0
**Purpose**: Decentralised, peer-to-peer network where Janitor instances share newly
discovered Swarm Signatures (MinHash sketches of AI botnet PR patterns) without
sharing source code.

### 5.1 Privacy Guarantee

A MinHash sketch is a one-way transform. Given the 64 × u64 sketch of a PR diff,
it is computationally infeasible to recover the original diff content. What is shared
is statistical similarity — not source. This is the fundamental privacy property that
makes the Syndicate safe.

**What is shared**: `PrDeltaSignature` structs — 512 bytes per sketch.
**What is never shared**: diff text, file paths, author names, PR numbers, source lines.

### 5.2 Protocol Design

```
Gossip over HTTPS/TLS 1.3 — each node maintains a peer list in janitor.toml

[syndicate]
enabled = false           # opt-in, disabled by default
peers = ["https://node1.example.com", "https://node2.example.com"]
min_observations = 3      # don't share a sketch seen fewer than N times locally
hmac_key = "<hex>"        # shared secret for sketch authentication (pre-shared)
```

**Syndicate sync** (triggered by `janitor update-wisdom`):

```
POST /v1/syndicate/sync
Content-Type: application/x-rkyv+zstd

Body: SyndicatePayload {
    sender_id:  BLAKE3(janitor.toml policy_hash),  // anonymous node ID
    sketches:   Vec<AuthenticatedSketch>,
    timestamp:  u64,
}

AuthenticatedSketch {
    sketch: PrDeltaSignature,           // 512 bytes
    hmac:   [u8; 32],                  // HMAC-SHA256(sketch bytes, hmac_key)
    observation_count: u32,            // local observation count at time of share
}
```

**Admission policy**: A received sketch is admitted to the local `LshIndex` only if:
- HMAC verification passes (prevents sketch poisoning)
- `observation_count >= 3` (prevents noise injection)
- The sketch is not already in the local index (BLAKE3 dedup)

**Storage**: Received sketches appended to `.janitor/syndicate_sigs.rkyv`. The `LshIndex`
is hydrated from both `bounce_log.ndjson` (local observations) and `syndicate_sigs.rkyv`
(network observations) on daemon startup.

### 5.3 Threat Model

| Attack | Mitigation |
|--------|-----------|
| Sketch poisoning (inject false collision) | HMAC-SHA256 with pre-shared key; unsigned sketches rejected |
| Deanonymization via sketch reversal | One-way MinHash transform; infeasible reversal |
| Sybil attack (many fake nodes inflate a sketch's count) | `min_observations = 3` threshold; single-node inflation requires ≥3 local observations per sketch |
| Network exfiltration of source | Only `PrDeltaSignature` structs transmitted; zero source bytes in protocol |

### 5.4 Governance

The Syndicate is disabled by default and activated only by explicit `[syndicate]` config.
There is no automatic peer discovery — operators must manually supply peer URLs.
This is intentional: the Syndicate is a tool for organisations that choose to share
threat intelligence, not a background service that activates silently.

---

## VI. Implementation Sequencing — 24-Month Horizon

```
Month  1–3  [v8.8.x] — Grammar Capstone (Phase 7):
  ├── Rust-1/2 (find_rust_slop)
  ├── GLSL-1 (find_glsl_slop byte-level)
  ├── HCL-1/2 (find_hcl_slop_ast)
  └── TSX-1/JSX-1 (find_jsx_dangerous_html_slop)
  Gate: 135/135 Crucible SANCTUARY INTACT; 23/23 grammar coverage

Month  4–9  [v9.0.x] — The Janitor LSP:
  ├── crates/lsp: LspServer, DiagnosticsEngine, document cache
  ├── CLI: janitor lsp subcommand
  ├── extensions/vscode: VS Code extension package
  └── Integration tests: lsp-server roundtrip fixtures
  Gate: LSP roundtrip test; VS Code VSIX builds without error

Month 10–15 [v9.1.x] — Cross-File Taint Tracking:
  ├── common: TaintExportRecord, TaintedParam, TaintKind (rkyv-serialisable)
  ├── daemon: taint_catalog.rkyv pre-compute during idle time
  ├── forge: cross_file_taint.rs — catalog load, 3-hop propagation
  └── CLI: janitor taint-report subcommand (dump taint catalog as table)
  Gate: Cross-file SQLi fixture (taint source in file_a, sink in file_b) fires; clean case passes

Month 16–21 [v9.2.x] — The Autonomous Syndicate:
  ├── common: SyndicatePayload, AuthenticatedSketch (rkyv-serialisable)
  ├── cli: syndicate.rs — POST /v1/syndicate/sync, admission policy
  ├── daemon: LshIndex hydration from syndicate_sigs.rkyv on startup
  └── Integration: janitor update-wisdom triggers syndicate sync when enabled
  Gate: Synthetic two-node sync fixture; collision detected post-sync; sketch poisoning rejected

Month 22–24 [v9.3.x] — Hardening & Ecosystem Permanence:
  ├── AVX-512 SIMD MinHash (8× lanes; benchmark against AVX-256 baseline)
  ├── NEON SIMD MinHash (ARM64/M-series GitHub runners)
  ├── taint_catalog.rkyv format v2: incremental update (diff-only rebuild)
  └── Syndicate: multi-hop gossip (sketches forward to peers of peers, depth-1 only)
```

---

## VII. Measurement Targets — 24-Month Horizon

| Metric | Baseline (v8.7.0) | 12-Month Target | 24-Month Target |
|--------|-------------------|-----------------|-----------------|
| Grammar AST coverage | 23/23 (100%) ✅ v8.8.0 | 23/23 (100%) | 23/23 maintained |
| Active threat rule classes | 42 | 50+ | 60+ |
| IDE integration | None | VS Code + Neovim | VS Code, Neovim, Zed, JetBrains |
| Cross-file taint depth | 0 hops | 3 hops | 5 hops |
| Syndicate peer support | N/A | opt-in, HMAC-auth | opt-in, cert-auth |
| MinHash throughput (10 KB patch, AVX-512) | AVX-256 baseline | 6× scalar | 8× scalar |
| False-positive rate (gauntlet, 1000 PRs) | < 1% | < 1% (maintained) | < 0.5% |
| Crucible gallery entries | 135 ✅ v8.8.0 | 135 (Phase 7 complete) | 160+ |
| Bounce wall-clock (50K-line repo) | < 30 s | < 20 s (LSP: < 500 ms/file) | < 15 s |

---

## VIII. CVE-to-AST Translation Protocol

> **Mandate**: Every CISA Known Exploited Vulnerability that maps to a detectable source
> pattern MUST be translated into a Crucible-verified structural gate within one sprint
> of publication. A KEV without a gate is a deferred breach.

### Step 1 — Identify the CISA KEV Patch (≤ 24 hours)

Pull the CISA KEV JSON feed via `janitor update-wisdom`. Filter to CVEs affecting
languages in the 23-grammar registry. Cross-reference with NVD to extract the
vulnerable code pattern. Artifact: one-paragraph brief naming CVE ID, language,
vulnerable construct, CVSS score.

### Step 2 — Extract the Vulnerable AST Structure (≤ 48 hours)

Run the snippet through the tree-sitter playground for the target grammar version
(matching `Cargo.toml`). Identify the minimal `node_type` + field values that
uniquely identify the vulnerability. Document the suppression rule.

### Step 3 — Write the Detector (≤ 72 hours)

| Pattern requires... | Use |
|---|---|
| Structural context (receiver type, field, argument count) | AST walk in `slop_hunter.rs` (Tier 1) |
| Exact byte string match | AhoCorasick in `slop_hunter.rs` or `binary_hunter.rs` (Tier 2) |
| Dependency-version-conditioned activation | `DepMigrationRule` in `migration_guard.rs` (Tier 2) |
| Cross-file data-flow | `taint_catalog.rkyv` lookup (Tier 1, v9.1.x+) |

### Step 4 — Crucible Verification (≤ 96 hours)

Add true-positive + true-negative `GalleryEntry` to `crates/crucible/src/main.rs`.
`cargo run -p crucible` must exit 0. A PR omitting the true-negative fixture is hard-blocked.

### Step 5 — Deploy (≤ 120 hours / 5 business days)

Bump version, commit, `/release <v>`. Binary embedded in GitHub Release must produce
non-zero exit on synthetic fixture matching the CVE pattern.

### VIII.A — Autonomous KEV Ingestion

`janitor update-wisdom` automates Steps 1–2. Operator approval required before Step 3.
Full machine-executable specification: `.claude/skills/cve-ingestion/SKILL.md`.

**Invariant**: All processing on-device. No source upload. Crucible exit 0 is the sole
acceptance criterion.

---

## IX. Grammar Depth Wave 2 — Archive (Phases 4–6, v8.4.0–v8.6.0)

Preserved for implementation reference. All entries COMPLETED and gate-verified.

### Phase 4 (v8.4.0) — Go, Ruby, Bash

| Gate | Rule | Points |
|------|------|--------|
| Go-1 | `exec.Command("sh"/"bash"/...)` → `security:command_injection_shell_exec` | 50 |
| Go-2 | `InsecureSkipVerify: true` → `security:tls_verification_bypass` (CVE-2022-27664) | 50 |
| Ruby-1 | `eval`/`system`/`exec`/`spawn` with non-literal arg → `security:dangerous_execution` | 50 |
| Ruby-2 | `Marshal.load`/`restore` → `security:unsafe_deserialization` (CVE-2013-0156) | 50 |
| Bash-1 | `curl`/`wget` piped to `bash`/`sh` → `security:curl_pipe_execution` | 50 |
| Bash-2 | `eval` with `$VAR` expansion → `security:eval_injection` | 50 |

### Phase 5 (v8.5.0) — PHP, Kotlin, Scala, Swift

| Gate | Rule | Points |
|------|------|--------|
| PHP-1 | `eval()` with non-literal → `security:eval_injection` | 50 |
| PHP-2 | `unserialize()` → `security:unsafe_deserialization` | 50 |
| PHP-3 | `system()`/`exec()`/`passthru()` with non-literal → `security:shell_exec` | 50 |
| Kotlin-1 | `Runtime.exec(` → `security:runtime_exec` | 50 |
| Kotlin-2 | `Class.forName(` with non-literal → `security:dynamic_class_loading` | 50 |
| Scala-1 | `Class.forName(` → `security:dynamic_class_loading` | 50 |
| Scala-2 | `asInstanceOf` + deser byte heuristic → `security:unsafe_cast_deser` | 50 |
| Swift-1 | `dlopen(` → `security:dynamic_library_loading` | 50 |
| Swift-2 | `NSClassFromString(` with non-literal → `security:dynamic_class_loading` | 50 |

### Phase 6 (v8.6.0) — Lua, Nix, GDScript, ObjC

| Gate | Rule | Points |
|------|------|--------|
| Lua-1 | `loadstring`/`load()` with non-literal → `security:eval_injection` | 50 |
| Lua-2 | `os.execute()` with non-literal → `security:command_injection` | 50 |
| Nix-1 | `fetchurl`/`builtins.fetchurl` without `sha256`/`hash` → `security:unverified_fetch` | 50 |
| Nix-2 | `builtins.exec` with non-literal arg → `security:nix_exec_injection` | 50 |
| GDScript-1 | `OS.execute()` with non-literal → `security:command_injection` | 50 |
| GDScript-2 | `load()` dynamic path → `security:dynamic_class_loading` | 50 |
| ObjC-1 | `NSClassFromString()` with non-literal → `security:dynamic_class_loading` | 50 |
| ObjC-2 | `valueForKeyPath:` with non-literal key → `security:kvc_injection` (CVE-2012-3524) | 50 |
