# R&D Roadmap — Architectural Supremacy Blueprint

> **Classification**: Internal Engineering Reference
> **Engine Baseline**: v8.0.11
> **Horizon**: 9-Month Structural Firewall Initiative

This document is a pure architecture blueprint. No production code is changed here.
Every proposal below is a specification — complete enough that implementation is a
mechanical translation, not a design exercise. Each item names the exact file, the
exact function, and the exact invariant to encode.

---

## I. Grammar Depth Audit

### Current Coverage Map

The engine hosts 23 tree-sitter grammars in `crates/polyglot/src/lib.rs`. Only three
receive active AST-walk query logic in `crates/forge/src/slop_hunter.rs`:

| Grammar | Detection depth | Active rules |
|---------|----------------|--------------|
| YAML    | Tree-sitter AST walk | K8s wildcard host (1 rule) |
| C / C++ | Tree-sitter AST walk | `gets`, `strcpy`, `sprintf`, `scanf` (4 rules) |
| JavaScript / TypeScript | Tree-sitter AST walk | `innerHTML` assignment (1 rule) |
| HCL / Terraform | Byte-level scan only | Open CIDR, S3 public ACL |
| Python  | Byte-level scan only | `subprocess` + `shell=True` |
| **Java, C#, Go, Kotlin, Swift, Scala, Ruby, PHP, Bash, Lua, GLSL, ObjC, Nix, GDScript** | **Zero** | None |

The three languages with the shallowest AST coverage relative to their attack
surface are: **Python**, **Java**, and **C#**. Each has a grammar loaded into
`OnceLock<Language>` and zero AST walks.

---

### Shallow Language 1 — Python

**Current gap**: `find_python_slop` is a byte-level window scan. The tree-sitter
`PYTHON` grammar (`crates/polyglot/src/lib.rs::python()`) is never called from
`slop_hunter.rs`. Python has five high-priority AST targets that byte scanning
cannot reliably hit without false positives:

| Attack class | Byte pattern (unreliable) | AST pattern (precise) |
|---|---|---|
| Code execution | `exec(` | `call_expression` with `function.name == "exec"` |
| Dynamic eval | `eval(` | Same as exec — but `eval` is idiomatic in test harnesses; AST context disambiguates |
| Unsafe deserialization | `pickle.loads(` | `call_expression` where callee is `attribute` with `object.name == "pickle"` and `attribute == "loads"` |
| OS command injection | `os.system(` | `call_expression` callee attribute `os.system` |
| Dynamic import | `__import__(` | `call_expression` with `function.name == "__import__"` |

**Proposed upgrade — `find_python_slop_ast` in `slop_hunter.rs`**:

```
fn find_python_slop_ast(source: &[u8]) -> Vec<SlopFinding>
```

1. Fast pre-filter: check for any of `exec(`, `eval(`, `pickle`, `os.system`,
   `__import__` bytes before loading the grammar.
2. `parser.set_language(&polyglot::python())` — grammar is already compiled.
3. Walk `call_expression` nodes. For each:
   - `function` field kind `identifier` → match name against the table above.
   - `function` field kind `attribute` → match `object.text + "." + attribute.text`.
4. The `eval(` rule must suppress findings inside `test_` function scopes and
   `# noqa` comment lines to stay below 1% false-positive rate on real repos.
5. `pickle.loads` and `pickle.load` both fire; `pickle.dumps` does not.

**Tier**: AST invariant (Tier 1 per `.claude/rules/evolution.md`).
**Points**: 50 (Critical) for `exec`, `os.system`, `pickle.loads`, `__import__`.
10 (Warning) for bare `eval` without test-scope suppression.

---

### Shallow Language 2 — Java

**Current gap**: The `JAVA` grammar is loaded (`crates/polyglot/src/lib.rs::java()`)
but `find_slop()` has no `"java"` branch. Java's two highest-impact vulnerability
classes are deserialization gadget chains and JNDI injection — both require AST
context to avoid drowning in false positives from legitimate library calls.

| Attack class | Why byte scan fails | AST anchor |
|---|---|---|
| `ObjectInputStream.readObject()` | `readObject` is a valid name on many types | Receiver type must resolve to `ObjectInputStream` — check variable declaration chain |
| `XMLDecoder.readObject()` | Same | Receiver type `XMLDecoder` |
| `Runtime.exec(String[])` | `exec` appears in test frameworks | Receiver chain: `Runtime.getRuntime().exec(` |
| JNDI injection (`InitialContext.lookup(user_input)`) | `lookup` is generic | Callee is `attribute` `"lookup"` on `InitialContext` instance |

**Proposed upgrade — `find_java_slop` in `slop_hunter.rs`**:

```
fn find_java_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding>
```

1. Pre-filter: `ObjectInputStream`, `XMLDecoder`, `Runtime.getRuntime`, `InitialContext`.
2. Walk `method_invocation` nodes. Extract `object` (the receiver expression) and
   `name` (the method name). Match the receiver text against the table above — the
   receiver text is `node.child_by_field_name("object")?.utf8_text(source)`.
3. For `InitialContext.lookup`: flag only when the argument is NOT a string literal
   (i.e., `argument_list` child is not `string_literal`). This eliminates false
   positives on static JNDI config lookups.
4. `QueryEngine` struct needs a `java_lang: Language` field added alongside the
   existing `yaml_lang`, `c_lang`, `js_lang`.

**Tier**: AST invariant (Tier 1).
**Points**: 50 (Critical) for all four patterns.

---

### Shallow Language 3 — C# #

**Current gap**: `CSHARP` grammar loaded, zero `find_slop()` branch. C#'s highest-risk
pattern is `TypeNameHandling` in Newtonsoft.Json — a configuration flag that enables
arbitrary type deserialization. This was the root cause of multiple CVE-bearing RCEs
in ASP.NET applications between 2019 and 2023. The AST approach is far more precise
than a string scan because the dangerous value is `TypeNameHandling.Auto`,
`TypeNameHandling.All`, or `TypeNameHandling.Objects` — not `TypeNameHandling.None`.

| Attack class | Dangerous variant | Safe variant |
|---|---|---|
| Newtonsoft.Json deserialization | `TypeNameHandling.Auto`, `.All`, `.Objects` | `TypeNameHandling.None` |
| `BinaryFormatter` | Any use post-.NET 5 | Blocked by `SYSLIB0011` — but legacy projects remain |
| `Process.Start` shell exec | `ProcessStartInfo.UseShellExecute = true` + user-controlled `FileName` | `UseShellExecute = false` |

**Proposed upgrade — `find_csharp_slop` in `slop_hunter.rs`**:

```
fn find_csharp_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding>
```

1. Pre-filter: `TypeNameHandling`, `BinaryFormatter`, `UseShellExecute`.
2. Walk `assignment_expression` nodes where right-hand side text matches
   `TypeNameHandling.Auto`, `TypeNameHandling.All`, or `TypeNameHandling.Objects`.
   `TypeNameHandling.None` is safe — explicitly exclude it.
3. Walk `object_creation_expression` nodes where `type` text is `BinaryFormatter`.
4. `QueryEngine` needs a `csharp_lang: Language` field.

**Tier**: AST invariant (Tier 1).
**Points**: 50 (Critical) for TypeNameHandling dangerous values and BinaryFormatter.

---

## II. Hardware Acceleration — SIMD MinHash

### Current Architecture

`crates/forge/src/pr_collider.rs` implements a 64-hash MinHash sketch computed over
byte 3-grams. The hot path is:

```rust
for window in data.windows(3) {
    for (i, &seed) in HASH_SEEDS.iter().enumerate() {
        let h = hash_shingle(window, seed);
        if h < min_hashes[i] {
            min_hashes[i] = h;
        }
    }
}
```

For a 10 KB patch (≈10,000 bytes, ≈9,998 3-gram windows), this executes
**9,998 × 64 = 639,872 scalar hash evaluations**. Each `hash_shingle` call
is a 5-instruction multiply-xor-shift pipeline on a `u64`.

The bottleneck is the inner loop: 64 independent hash seeds processed
sequentially, with a conditional minimum update per seed. This structure
is a textbook SIMD candidate — the 64 seeds are independent of each other,
the minimum update is a lane-wise `min`, and the multiply/XOR/shift operations
map directly to SIMD intrinsics.

### Vectorization Strategy

**Target ISAs**: AVX-512 (8× `u64` lanes, x86-64), AVX-256 (4× `u64` lanes,
x86-64 fallback), NEON (2× `u64` lanes, ARM64/M-series).

The hash function operating on a single 3-gram `[b0, b1, b2]` and seed `s` is:

```
h = s
h ^= b0; h = h * M1; h ^= h >> 16; h = h * M2; h ^= h >> 32
h ^= b1; h = h * M1; h ^= h >> 16; h = h * M2; h ^= h >> 32
h ^= b2; h = h * M1; h ^= h >> 16; h = h * M2; h ^= h >> 32
```

where `M1 = 0x6c62272e07bb0142` and `M2 = 0x94d049bb133111eb`.

**AVX-512 vectorization** — 8 seeds in parallel per SIMD call:

```
lane[k] = HASH_SEEDS[i*8 + k]   for k in 0..8
for byte in [b0, b1, b2]:
    lane ^= broadcast(byte)
    lane = lane * broadcast(M1)   // _mm512_mullo_epi64
    lane ^= lane >> broadcast(16) // _mm512_srli_epi64 + xor
    lane = lane * broadcast(M2)
    lane ^= lane >> broadcast(32)
min_hashes[i*8..(i+1)*8] = min(min_hashes[i*8..(i+1)*8], lane)
    // _mm512_min_epu64
```

This reduces 64 scalar calls to **8 SIMD calls** per 3-gram window — an 8× reduction
in instruction count (excluding loop overhead and memory latency).

**AVX-256 fallback** — 4 seeds per SIMD call, 16 calls per window. `_mm256_mullo_epi64`
requires AVX-512VL; for pure AVX-256 without AVX-512VL, use two `_mm256_mul_epu32`
calls to emulate 64-bit multiply. This reduces instruction count by 4× over scalar.

**NEON (ARM64)** — 2 seeds per `uint64x2_t` lane, 32 SIMD calls per window.
`vmulq_u64` is natively supported on ARMv8. Provides a 2× reduction — modest,
but meaningful for M-series runners where this runs in GitHub Actions.

**Implementation sketch** — `PrDeltaSignature::from_bytes_simd`:

```rust
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx512f,avx512dq")]
unsafe fn from_bytes_avx512(data: &[u8]) -> [u64; NUM_HASHES] { ... }

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "avx2")]
unsafe fn from_bytes_avx256(data: &[u8]) -> [u64; NUM_HASHES] { ... }

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "neon")]
unsafe fn from_bytes_neon(data: &[u8]) -> [u64; NUM_HASHES] { ... }

pub fn from_bytes(data: &[u8]) -> Self {
    // Runtime dispatch via std::arch::is_x86_feature_detected! or
    // std::arch::is_aarch64_feature_detected!
    // Falls back to existing scalar implementation.
}
```

**Expected throughput gains**:

| ISA | Lanes | Speedup (theoretical) | Realistic (memory-bound correction) |
|-----|-------|-----------------------|--------------------------------------|
| AVX-512 | 8 | 8× | 4–6× |
| AVX-256 | 4 | 4× | 2–3× |
| NEON | 2 | 2× | 1.5–2× |
| Scalar | 1 | baseline | baseline |

At the current swarm threshold of 1,000 PRs per gauntlet run, 4× throughput
halves gauntlet wall-clock time on AVX-256 GitHub runners.

**Gate**: Any SIMD implementation must pass the existing
`test_identical_patches_have_high_jaccard` and `test_completely_different_patches_have_low_jaccard`
tests with identical output to the scalar path. A `#[test] fn simd_matches_scalar()`
fixture must be added that checks `from_bytes_avx256(data).min_hashes == from_bytes_scalar(data).min_hashes`
for a representative set of patch sizes.

---

## III. Threat Matrix Expansion

### New Threat Class 1 — Prototype Pollution (JavaScript / TypeScript)

**Why the current matrix misses it**: The JS/TS rule in `find_js_slop` detects
`innerHTML` assignments via a direct field walk on `assignment_expression` nodes.
Prototype pollution requires tracing a *key* through a merge/assign call — a
different AST shape entirely.

**Attack anatomy**: Prototype pollution occurs when an attacker controls a key used
to index an object, and that key is `__proto__` or `constructor`. The typical
vector is a recursive merge utility called on untrusted JSON:

```javascript
function merge(target, source) {
    for (let key in source) {
        target[key] = merge(target[key], source[key]); // 'key' can be '__proto__'
    }
}
merge({}, JSON.parse(userControlledInput));
```

**Two-layer detection plan**:

**Layer A — AhoCorasick patterns** (zero-cost pre-filter, catches the obvious cases):

| Pattern | Label | Rationale |
|---|---|---|
| `.__proto__` | `security:prototype_pollution` | Direct proto access in object expression |
| `["__proto__"]` | `security:prototype_pollution` | Computed key access |
| `['__proto__']` | `security:prototype_pollution` | Single-quote variant |
| `[constructor][prototype]` | `security:prototype_pollution` | Indirect proto chain traversal |

These four patterns go in `SUPPLY_CHAIN_PATTERNS` (or a new `PROTOTYPE_PATTERNS`
const in `slop_hunter.rs`) under a `find_prototype_pollution_slop` function.

**Layer B — AST patterns** (catches unsafe merge utilities):

Target `call_expression` nodes where the callee matches known merge utilities:
`_.merge(`, `lodash.merge(`, `deepMerge(`, `mergeDeep(`, `Object.assign(`.

For each such call, walk the `arguments` list. If any argument derives from a
`JSON.parse(` call expression, or is named `body`, `params`, `query`, `input`,
or `data` (common HTTP request properties), flag
`security:prototype_pollution_merge_sink`.

The false-positive suppression rule: suppress if the call site is inside a
`node_modules/` path or a function whose name contains `sanitize`, `validate`,
or `freeze`.

**Points**: 50 (Critical) for both layers.
**Tier**: Layer A is AhoCorasick (Tier 2). Layer B is AST invariant (Tier 1).

---

### New Threat Class 2 — Deserialization Gadget Chains (Java / C#)

**Why the current matrix misses it**: Neither Java nor C# has a `find_slop()` branch.
The Tier 2 AhoCorasick credential patterns in `binary_hunter.rs` scan for secret
strings, not dangerous API invocations.

**Attack anatomy**: Gadget chain deserialization is the mechanism behind CVE-2015-4852
(Apache Commons Collections), CVE-2021-44228 (Log4Shell JNDI vector), and dozens of
Newtonsoft.Json-based ASP.NET RCEs. The vulnerability class is **critical** by
definition: a single call to `ObjectInputStream.readObject()` on attacker-controlled
bytes yields remote code execution on a JVM with Commons Collections on the classpath.

**Java detection — AhoCorasick patterns** (Tier 2, immediate value):

| Pattern bytes | Label | Points |
|---|---|---|
| `new ObjectInputStream(` | `security:unsafe_deserialization` | 50 |
| `XMLDecoder(` | `security:unsafe_deserialization` | 50 |
| `XStream().fromXML(` | `security:unsafe_deserialization` | 50 |
| `.readObject()` | `security:unsafe_deserialization` | 50 |
| `Runtime.getRuntime().exec(` | `security:runtime_exec` | 50 |
| `InitialContext().lookup(` | `security:jndi_injection` | 50 |

These go in a new `JAVA_DANGER_PATTERNS` const in `slop_hunter.rs`, guarded by
a pre-filter on `".java"` extension. The `find_java_slop_fast` function using these
patterns is the immediate deliverable; the full AST walk described in Section I is
the follow-on upgrade.

**C# detection — AhoCorasick patterns** (Tier 2, immediate value):

| Pattern bytes | Label | Points |
|---|---|---|
| `new BinaryFormatter()` | `security:unsafe_deserialization` | 50 |
| `TypeNameHandling.Auto` | `security:unsafe_deserialization` | 50 |
| `TypeNameHandling.All` | `security:unsafe_deserialization` | 50 |
| `TypeNameHandling.Objects` | `security:unsafe_deserialization` | 50 |
| `LosFormatter` | `security:unsafe_deserialization` | 50 |
| `ObjectStateFormatter` | `security:unsafe_deserialization` | 50 |

`TypeNameHandling.None` must be explicitly excluded from the pattern list — it is
the safe configuration and must never fire.

**False-positive controls**:

- Java: suppress `.readObject()` when the containing class name ends in `Serializable`
  and the method is `readObject(ObjectInputStream in)` — this is the override
  signature used to *implement* custom deserialization safely.
- C#: `TypeNameHandling.All` in a comment (`// TypeNameHandling.All`) must not fire.
  The AhoCorasick match position must be outside a comment region. Use the existing
  `CommentScanner` infrastructure in `metadata.rs` to filter positions.

**Tier**: Tier 2 (AhoCorasick) immediately; Tier 1 (AST) in follow-on sprint.
**Points**: 50 (Critical) for all patterns.

---

## IV. Implementation Sequencing

The three initiatives have a natural dependency ordering:

```
Phase 1 [COMPLETED — v8.1.0]:
  ├── Java/C# AhoCorasick patterns (III, Tier 2)
  │     Files: slop_hunter.rs, crucible/src/main.rs
  │     Gate: crucible exit 0, just audit exit 0 ✓
  └── Prototype Pollution AhoCorasick Layer A (III, Tier 2)
        Files: slop_hunter.rs, crucible/src/main.rs ✓

Phase 2 [COMPLETED — v8.2.0]:
  ├── Python AST walk upgrade (I, Tier 1)
  │     Files: slop_hunter.rs (find_python_slop_ast; test_ suppression; # noqa guard)
  │     Gate: crucible exit 0 ✓
  └── Java AST walk upgrade (I, Tier 1)
        Files: slop_hunter.rs (find_java_slop; QueryEngine::java_lang field added) ✓

Phase 3 [COMPLETED — v8.3.0]:
  ├── C# AST walk upgrade (I, Tier 1)
  │     Files: slop_hunter.rs (QueryEngine::csharp_lang; find_csharp_slop;
  │            find_csharp_danger_nodes; CSHARP_DANGEROUS_TNH) ✓
  ├── Prototype Pollution AST Layer B (III, Tier 1)
  │     Files: slop_hunter.rs (find_prototype_merge_sink_slop;
  │            find_merge_sink_calls; argument_is_tainted;
  │            MERGE_CALL_TARGETS; USER_INPUT_NAMES) ✓
  └── SIMD MinHash AVX-256 (II)
        Files: pr_collider.rs (from_bytes_avx256; mul64_avx2;
               from_bytes_scalar; runtime dispatch in from_bytes) ✓
        Gate: simd_matches_scalar() 100-trial correctness test ✓
```

Every phase gate is: **Crucible exits 0** AND **`just audit` exits 0** AND at least
one true-positive + one true-negative fixture added to `crates/crucible/src/main.rs`.

---

## V. Measurement Targets (9-Month Horizon)

| Metric | Baseline (v8.0.11) | Target |
|--------|---------------------|--------|
| Languages with active AST rules | 3 (YAML, C/C++, JS/TS) | 6 (+Python, Java, C#) |
| Active threat classes | 7 | 13 (+prototype_pollution, unsafe_deserialization ×2, runtime_exec, jndi_injection, python_exec ×5) |
| MinHash throughput (10 KB patch, AVX-256 runner) | 1× baseline | 3× baseline |
| False-positive rate (gauntlet, 1000 PRs) | < 1% | < 1% (maintained) |
| Crucible gallery entries | Current count | +12 minimum (2 per new rule class) |

---

## VI. The CVE-to-AST Translation Protocol

> **Mandate**: every CISA Known Exploited Vulnerability that maps to a detectable
> source pattern MUST be translated into a Crucible-verified structural gate within
> one sprint of publication. A KEV without a gate is a deferred breach.

The protocol has five steps. Each step has a single owner, a single artifact, and
a single acceptance criterion. There is no step 6 — if a gate cannot be expressed
in steps 1–5, the vulnerability class is escalated to the Hardware Acceleration
track (Section II) or deferred with a documented rationale.

---

### Step 1 — Identify the CISA KEV Patch

**Input**: CISA Known Exploited Vulnerabilities catalog
(`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`), filtered to
CVEs affecting languages in the engine's grammar registry (23 languages in
`crates/polyglot/src/lib.rs`).

**Action**:
1. Pull the CISA KEV JSON feed daily (or on-demand via `/update-wisdom`).
2. Filter entries where `product` or `vendorProject` maps to a language in
   `polyglot`: e.g., `spring` → Java, `log4j` → Java, `newtonsoft.json` → C#,
   `lodash` → JavaScript.
3. Cross-reference with the NVD CVE record to extract the **vulnerable code
   pattern** — the specific API call, configuration value, or AST construct that
   triggers the vulnerability.

**Artifact**: A one-paragraph vulnerability brief stating: CVE ID, affected
language, vulnerable pattern (as a code snippet), and the CVSS base score.

**Acceptance criterion**: The brief names a specific function, method, or
configuration key — not just a library name.

---

### Step 2 — Extract the Vulnerable AST Structure

**Input**: The vulnerable code snippet from Step 1.

**Action**:
1. Run the snippet through the tree-sitter playground
   (`https://tree-sitter.github.io/tree-sitter/playground`) for the target
   language grammar (use the same grammar version as `Cargo.toml`).
2. Identify the minimal AST node type that uniquely identifies the vulnerability:
   - For method calls: `call_expression` or `method_invocation` with specific
     `function`/`callee` field values.
   - For assignments: `assignment_expression` with specific right-hand-side
     identifier text.
   - For object construction: `object_creation_expression` with specific `type`.
3. Document the **suppression rule** — the AST context in which the pattern
   is safe and must NOT fire (e.g., override method signatures, `#[cfg(test)]`
   scope, comment-line positions).

**Artifact**: An AST node description in this form:

```
node_type: call_expression
field[function]: attribute_expression
  field[object]: identifier (text == "ObjectInputStream")
  field[attribute]: identifier (text == "readObject")
suppression: method body where parent function name is "readObject" and
             parameter type is "ObjectInputStream" (override signature)
```

**Acceptance criterion**: The node description is unambiguous — a mechanical
walk of the tree-sitter AST for the vulnerable snippet produces exactly this
node, and the suppression rule excludes all known safe uses.

---

### Step 3 — Write the Tree-Sitter Query or AhoCorasick Pattern

**Input**: The AST node description from Step 2.

**Decision rule**:

| If the pattern requires... | Use |
|---|---|
| Structural context (receiver type, field name, argument count) | Tree-sitter AST walk in `slop_hunter.rs` (Tier 1) |
| Exact byte string match without context (API key prefix, banned function name in a language with no grammar active yet) | AhoCorasick in `slop_hunter.rs` or `binary_hunter.rs` (Tier 2) |
| Dependency-version-conditioned activation | `DepMigrationRule` in `migration_guard.rs` (Tier 2) |
| Cross-file data-flow (taint source → sink) | Defer to Phase 2 Grammar Depth Upgrade (Section I) |

**Action**:
- **AST path**: Add a `find_<lang>_<cve_short>_slop` function to `slop_hunter.rs`.
  Set `severity: Severity::Critical` (+50 pts). Document the CVE ID in the
  function's `///` doc comment. Call the new function from `find_slop()`.
- **AhoCorasick path**: Append the pattern to the appropriate `*_PATTERNS` const
  (e.g., `CREDENTIAL_PATTERNS`, `SUPPLY_CHAIN_PATTERNS`). The pattern tuple is
  `(b"<byte_pattern>", "security:<label> — <description>")`.

**Artifact**: The diff — a new function or a new pattern entry, with doc comment
citing the CVE ID and CVSS score.

**Acceptance criterion**: `cargo clippy -- -D warnings` exits 0. The new code
path is covered by at least one true-positive and one true-negative fixture
(added in Step 4).

---

### Step 4 — Add to the Crucible Threat Gallery

**Input**: The detector from Step 3.

**Action**:
1. Open `crates/crucible/src/main.rs`.
2. Add a **true-positive** entry to `GALLERY` (or `BOUNCE_GALLERY` if the
   pattern fires at the `PatchBouncer` level):

   ```rust
   GalleryEntry {
       label: "CVE-YYYY-NNNNN — <short description>",
       language: "java",  // or relevant language
       source: br#"<minimal snippet that triggers the rule>"#,
       desc_fragment: Some("<label substring present in the finding description>"),
   },
   ```

3. Add a **true-negative** entry — the safe variant of the same code that must
   NOT produce the finding. The true-negative label must include `"clean"` or
   `"safe"` so reviewers can identify it at a glance.

4. Run `cargo run -p crucible`. All gallery entries must yield
   `SANCTUARY INTACT`.

**Artifact**: Two new `GalleryEntry` structs in `crucible/src/main.rs`.

**Acceptance criterion**: `cargo run -p crucible` exits 0 with the new entries
present. A PR that omits the true-negative fixture is rejected at review.

---

### Step 5 — Deploy

**Input**: All of Steps 1–4 complete, `cargo run -p crucible` exits 0,
`just audit` exits 0.

**Action**:
1. Bump `Cargo.toml [workspace.package].version` (patch increment: `8.X.Y` →
   `8.X.(Y+1)`).
2. Commit with message format:
   `feat(<crate>): CVE-YYYY-NNNNN <language> <vulnerability class> gate`
3. Execute `/release 8.X.(Y+1)` — this runs `just audit`, builds the release
   binary, tags `v8.X.(Y+1)`, and publishes the GitHub Release.
4. If the Governor API contract changed, execute `/deploy-gov` immediately after.

**Artifact**: A tagged GitHub Release with the new gate active in the binary.

**Acceptance criterion**: The GitHub Release page for `v8.X.(Y+1)` exists.
The binary embedded in the release, when run against a synthetic fixture
matching the CVE pattern, produces a non-zero exit code with
`security:<label>` in the antipattern details.

---

### Protocol Timing Targets

| Step | Maximum elapsed time from KEV publication |
|------|--------------------------------------------|
| 1 — KEV brief | 24 hours |
| 2 — AST extraction | 48 hours |
| 3 — Detector written | 72 hours |
| 4 — Crucible verified | 96 hours |
| 5 — Release deployed | 120 hours (5 business days) |

A CVE that cannot reach Step 5 within 5 business days must be escalated with
a documented blocker. The blocker is either: (a) grammar not yet in `polyglot`
— triggers a grammar addition sprint; or (b) cross-file taint required — deferred
to Phase 2 with a `TODO(CVE-YYYY-NNNNN)` comment in `slop_hunter.rs`.

### VI.A — Autonomous KEV Ingestion (Automated)

The manual 5-step protocol above is now automated via `/update-wisdom`. The full
machine-executable specification lives in `.claude/skills/cve-ingestion/SKILL.md`.

**Trigger**: `janitor update-wisdom` (or the `/update-wisdom` slash command).

**Pipeline summary**:
1. Fetch `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
2. Filter to supported grammars via the language map in the skill file
3. Cross-reference against active detectors in `slop_hunter.rs`
4. Emit gate proposals for uncovered KEVs — operator approves before implementation
5. Implement, Crucible-verify, and deploy approved gates at `KevCritical` (150 pts)

**Invariants** (same as Scanner Sovereignty Law):
- All processing on-device — no source upload
- Operator approval required before any gate implementation
- Crucible exit 0 is the sole acceptance criterion

---

## VII. Grammar Depth Wave 2 — Phases 4–6

The engine currently has 12 grammars loaded with zero AST-walk logic. This section
defines the structural gates for each remaining grammar, grouped into three
execution phases by attack-surface priority.

**Remaining grammars at v8.3.0**: Go, Kotlin, Swift, Scala, Ruby, PHP, Bash,
Lua, GLSL, Objective-C, Nix, GDScript.

---

### Phase 4 — Go, Ruby, Bash (High-Impact Infra/Scripting)

**Target version**: v8.4.x
**Rationale**: These three grammars cover the dominant attack surface in
infrastructure automation, backend scripting, and CI/CD pipelines. Go is
Kubernetes/Terraform's language; Ruby drives Rails and gems; Bash is the
universal pipeline glue. Each has multiple critical CVE classes with no
current AST gate.

```
Phase 4 [COMPLETED — v8.4.0]:
  ├── Go AST walk (Tier 1)
  │     Files: slop_hunter.rs (find_go_slop; QueryEngine::go_lang)
  │            crucible/src/main.rs (TP + TN × 2 gates)
  ├── Ruby AST walk (Tier 1)
  │     Files: slop_hunter.rs (find_ruby_slop; QueryEngine::ruby_lang)
  │            crucible/src/main.rs (TP + TN × 2 gates)
  └── Bash AST walk (Tier 1)
        Files: slop_hunter.rs (find_bash_slop; QueryEngine::bash_lang)
               crucible/src/main.rs (TP + TN × 2 gates)
```

---

#### Go — Gate Specifications

**Grammar**: `tree-sitter-go` (loaded via `polyglot::go()`).
**`QueryEngine` field to add**: `go_lang: Language`.
**Pre-filter** in `find_go_slop`: check for any of `exec.Command`, `InsecureSkipVerify` bytes.

**Gate Go-1 — Shell Execution via `exec.Command`**

```
node_type: call_expression
field[function]: selector_expression
  field[operand]: identifier (text == "exec")
  field[field]: field_identifier (text == "Command")
fire when: first argument in arguments list is string_literal
           matching "sh", "bash", "/bin/sh", "/bin/bash", "cmd", "cmd.exe"
label: security:command_injection_shell_exec
points: 50 (Critical)
suppression: call site inside a function whose name contains "test" or "Test"
```

**Rationale**: `exec.Command("sh", "-c", userInput)` is the canonical Go shell
injection pattern. The first-arg check for a shell interpreter name distinguishes
this from legitimate `exec.Command("git", "status")` invocations.

**Gate Go-2 — TLS Verification Bypass**

```
node_type: keyed_element
  key: field_identifier (text == "InsecureSkipVerify")
  value: identifier (text == "true")
label: security:tls_verification_bypass
points: 50 (Critical)
suppression: none — InsecureSkipVerify: true is never safe in production code
```

**Rationale**: `tls.Config{InsecureSkipVerify: true}` disables certificate
verification entirely. This is a recurring CVE root cause in Go microservices
(see CVE-2022-27664, CVE-2023-29409). The `keyed_element` AST node uniquely
identifies this configuration regardless of variable name or struct position.

**Crucible entries (Go)**:

True-positive 1:
```go
cmd := exec.Command("bash", "-c", userInput)
cmd.Run()
```
Label: `Go/exec.Command shell injection — INTERCEPT`
Desc fragment: `security:command_injection_shell_exec`

True-negative 1:
```go
cmd := exec.Command("git", "status")
cmd.Run()
```
Label: `Go/exec.Command non-shell — SAFE`

True-positive 2:
```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}
```
Label: `Go/InsecureSkipVerify — INTERCEPT`
Desc fragment: `security:tls_verification_bypass`

True-negative 2:
```go
tr := &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
}
```
Label: `Go/InsecureSkipVerify false — SAFE`

---

#### Ruby — Gate Specifications

**Grammar**: `tree-sitter-ruby` (loaded via `polyglot::ruby()`).
**`QueryEngine` field to add**: `ruby_lang: Language`.
**Pre-filter** in `find_ruby_slop`: check for `eval`, `system`, `Marshal.load`, `Marshal.restore`.

**Gate Ruby-1 — Dynamic Execution (`eval` / `system` / `exec`)**

```
node_type: call (tree-sitter-ruby method call node)
field[method]: identifier
  text in {"eval", "system", "exec", "spawn"}
fire when: first argument is NOT a string_literal (i.e., is an interpolated
           string, identifier, or method_call — dynamic content)
label: security:dangerous_execution
points: 50 (Critical)
suppression: call site inside a method whose name contains "test" or "spec",
             or file path contains "_spec.rb" or "_test.rb"
```

**Gate Ruby-2 — `Marshal.load` Deserialization**

```
node_type: call
field[receiver]: constant (text == "Marshal")
field[method]: identifier (text == "load" OR text == "restore")
label: security:unsafe_deserialization
points: 50 (Critical)
suppression: none — Marshal.load on user-controlled input is unconditionally dangerous
```

**Rationale**: `Marshal.load` executes arbitrary Ruby code embedded in the
serialized stream. This is the mechanism behind dozens of Rails RCEs including
CVE-2013-0156. There is no safe variant of `Marshal.load` on attacker-controlled
input — unlike `JSON.parse`, which produces only data.

**Crucible entries (Ruby)**:

True-positive 1: `eval(params[:code])` → `security:dangerous_execution`
True-negative 1: `eval("1 + 1")` (string literal) → SAFE
True-positive 2: `Marshal.load(user_data)` → `security:unsafe_deserialization`
True-negative 2: `Marshal.load(File.read("config.bin"))` — mark with `# janitor:safe` comment; TN verifies suppression still works for static paths (note: Marshal.load on any input still fires; the TN should use `Marshal.dump` instead to show safe serialization path)

---

#### Bash — Gate Specifications

**Grammar**: `tree-sitter-bash` (loaded via `polyglot::bash()`).
**`QueryEngine` field to add**: `bash_lang: Language`.
**Pre-filter** in `find_bash_slop`: check for `eval`, `curl` (both combined with pipe indicators).

**Gate Bash-1 — `curl | bash` Supply Chain Execution**

```
node_type: pipeline
  first child command: name text == "curl" (or "wget")
  last child command: name text == "bash" OR "sh"
label: security:curl_pipe_execution
points: 50 (Critical)
suppression: none — piping a remote script directly to a shell is never safe
             in production code. Bootstrap scripts should download-then-verify.
```

**Rationale**: `curl https://... | bash` is the canonical supply chain attack
vector — it executes remote code without integrity verification. This pattern
appears in legitimate install scripts (brew, nvm, rvm) but must be flagged in
PR diffs because it is equally the mechanism behind widespread malware deployment.

**Gate Bash-2 — `eval` with Unquoted Variable Expansion**

```
node_type: command
  name: word (text == "eval")
  argument: simple_expansion OR expansion (i.e., $VAR or ${VAR}, unquoted)
label: security:eval_injection
points: 50 (Critical)
suppression: argument is a double-quoted string even if it contains expansion
             — "$(cmd)" is still dangerous; suppress only pure literals
```

**Rationale**: `eval $USER_INPUT` expands the variable into code before
evaluation. Unlike `eval "$(cmd)"` (which is a bash anti-pattern but has
well-understood semantics), unquoted `eval $VAR` with an externally-supplied
variable is an injection primitive. The tree-sitter `simple_expansion` node
type directly identifies the unquoted form.

**Crucible entries (Bash)**:

True-positive 1: `curl https://install.example.com/setup.sh | bash` → `security:curl_pipe_execution`
True-negative 1: `curl -o setup.sh https://install.example.com/setup.sh && bash setup.sh` → SAFE (download-then-execute, not piped)
True-positive 2: `eval $USER_COMMAND` → `security:eval_injection`
True-negative 2: `eval "echo hello"` → SAFE (string literal, no expansion)

---

### Phase 5 — Scala, PHP, Swift, Kotlin (JVM + Mobile + Web)

**Target version**: v8.5.x
**Rationale**: PHP drives ≥75% of CMS deployments (WordPress, Drupal); Kotlin is
the primary Android language; Scala dominates data-pipeline infrastructure (Spark,
Akka); Swift is the exclusive iOS/macOS language. Each has a distinct high-priority
vulnerability class.

```
Phase 5 [COMPLETED — v8.5.0]:
  ├── PHP AST walk (Tier 1)
  │     Gates: eval injection, unserialize deserialization, shell_exec
  ├── Kotlin AST walk (Tier 1)
  │     Gates: Runtime.exec injection, Class.forName gadget chain entry
  ├── Scala AST walk (Tier 1)
  │     Gates: Class.forName dynamic loading, asInstanceOf unchecked cast on deserialized data
  └── Swift AST walk (Tier 1)
        Gates: dlopen dynamic loading, NSClassFromString dynamic class loading
```

**PHP Gate Specifications**:

| Gate | Node type | Target | Label | Points |
|------|-----------|--------|-------|--------|
| PHP-1 | `function_call_expression` | `eval` with dynamic arg | `security:eval_injection` | 50 |
| PHP-2 | `function_call_expression` | `unserialize` with non-literal arg | `security:unsafe_deserialization` | 50 |
| PHP-3 | `function_call_expression` | `system`, `exec`, `shell_exec`, `passthru` with dynamic arg | `security:command_injection` | 50 |

Pre-filter: any of `eval(`, `unserialize(`, `system(`, `exec(`, `shell_exec(`.
Suppression for PHP-1/3: call site inside a function named `test*` or file path containing `tests/`.
`QueryEngine` field: `php_lang: Language`.

**Kotlin Gate Specifications**:

| Gate | Node type | Target | Label | Points |
|------|-----------|--------|-------|--------|
| Kotlin-1 | `call_expression` | `Runtime.getRuntime().exec(` with non-literal first arg | `security:command_injection_runtime_exec` | 50 |
| Kotlin-2 | `call_expression` | `Class.forName(` with non-literal arg | `security:dynamic_class_loading` | 50 |

Pre-filter: `Runtime.getRuntime`, `Class.forName`.
`QueryEngine` field: `kotlin_lang: Language`.

**Scala Gate Specifications**:

| Gate | Node type | Target | Label | Points |
|------|-----------|--------|-------|--------|
| Scala-1 | `call_expression` | `Class.forName(` with non-literal arg | `security:dynamic_class_loading` | 50 |
| Scala-2 | `call_expression` | `.asInstanceOf[` immediately following a deserialization call | `security:unsafe_deserialization` | 50 |

Pre-filter: `Class.forName`, `asInstanceOf`.
`QueryEngine` field: `scala_lang: Language`.

**Swift Gate Specifications**:

| Gate | Node type | Target | Label | Points |
|------|-----------|--------|-------|--------|
| Swift-1 | `call_expression` | `dlopen(` with non-literal first arg | `security:dynamic_symbol_resolution` | 50 |
| Swift-2 | `call_expression` | `NSClassFromString(` with non-literal arg | `security:dynamic_class_loading` | 50 |

Pre-filter: `dlopen`, `NSClassFromString`.
`QueryEngine` field: `swift_lang: Language`.

---

### Phase 6 — Lua, Nix, GDScript, GLSL, Objective-C (Specialized/Niche)

**Target version**: v8.6.x
**Rationale**: These grammars cover game engines (Lua in many engines, GDScript in
Godot), declarative infrastructure (Nix), graphics pipelines (GLSL), and legacy
Apple code (Objective-C). Attack surfaces are narrower but structurally identical
to higher-priority languages — the gates transfer directly.

```
Phase 6 [COMPLETED — v8.6.0]:
  ├── Lua AST walk (Tier 1)
  │     Gates: loadstring/load injection, os.execute injection
  ├── Nix AST walk (Tier 1)
  │     Gates: builtins.fetchurl without integrity hash (supply chain)
  ├── GDScript AST walk (Tier 1)
  │     Gates: OS.execute injection, load() on dynamic path
  ├── Objective-C AST walk (Tier 1)
  │     Gates: NSClassFromString injection, valueForKeyPath: KVC injection
  └── GLSL (Tier 4 — deferred)
        No actionable attack surface at patch-review scope.
        Grammar retained for future dead-symbol analysis of shader code.
```

**Lua Gate Specifications**:

| Gate | Node type | Target | Label | Points |
|------|-----------|--------|-------|--------|
| Lua-1 | `function_call` | `loadstring(` or `load(` with non-literal arg | `security:eval_injection` | 50 |
| Lua-2 | `function_call` | `os.execute(` with non-literal arg | `security:command_injection` | 50 |

`QueryEngine` field: `lua_lang: Language`.

**Nix Gate Specifications**:

| Gate | Target | Rule | Label | Points |
|------|--------|------|-------|--------|
| Nix-1 | `builtins.fetchurl` or `fetchurl` call without a `sha256` or `hash` attribute in the attrset argument | Supply chain: unverified remote fetch | `security:unverified_fetch` | 50 |
| Nix-2 | `builtins.exec` with non-literal argument list | Arbitrary process execution in Nix evaluation | `security:nix_exec_injection` | 50 |

`QueryEngine` field: `nix_lang: Language`.

**GDScript Gate Specifications**:

| Gate | Target | Label | Points |
|------|--------|-------|--------|
| GDScript-1 | `OS.execute(` with non-literal first arg | `security:command_injection` | 50 |
| GDScript-2 | `load(` with non-literal arg (dynamic script loading) | `security:dynamic_class_loading` | 50 |

`QueryEngine` field: `gdscript_lang: Language`.

**Objective-C Gate Specifications**:

| Gate | AST anchor | Label | Points |
|------|-----------|-------|--------|
| ObjC-1 | `NSClassFromString(` with non-literal arg — message expression where selector is `NSClassFromString` | `security:dynamic_class_loading` | 50 |
| ObjC-2 | `valueForKeyPath:` with non-literal key argument — exploits KVC to access arbitrary object graph | `security:kvc_injection` | 50 |

**Rationale for ObjC-2**: CVE-2012-3524 and the Cocoa KVC injection class
allow an attacker who controls a `valueForKeyPath:` argument to call arbitrary
class methods via `NSArray.valueForKeyPath:"@unionOfObjects.description"`.
The AST anchor is a `message_expression` where the `message_selector` is
`valueForKeyPath:` and the argument is not a string literal.

`QueryEngine` field: `objc_lang: Language`.

---

### Phase 4–6 Measurement Targets

| Metric | After Phase 3 | After Phase 4 | After Phase 5 | After Phase 6 |
|--------|---------------|---------------|---------------|---------------|
| Languages with AST rules | 6 | 9 | 13 | 18 |
| Active threat classes | 13 | 19 | 27 | 33 |
| Grammar coverage (AST) | 26% (6/23) | 39% (9/23) | 57% (13/23) | 78% (18/23) |
| Grammars deferred (GLSL) | — | — | — | 1 |

---

## VIII. Predictive Allocation — Proactive Physarum Gate [COMPLETED — v8.5.0]

### Problem Statement

The current Physarum protocol is **reactive**: it observes SMA% and velocity
*after* parsing has already begun. For large diffs, the tree-sitter AST
construction phase can allocate 10–20× the raw byte size of the input before
the next `beat()` cycle fires. On an 8 GB system at 70% utilization, parsing
a 5 MB diff blob can push allocation from safe territory directly into Stop
territory in a single cycle — bypassing the Constrict gate entirely.

### Specification: `check_predictive_pressure`

**New function in `crates/common/src/physarum.rs`**:

```rust
/// Returns `true` if starting a parse of `file_size_bytes` would be predicted
/// to push memory usage into the Constrict zone before the next beat cycle.
///
/// Uses a conservative 20× multiplier: tree-sitter ASTs for dense source code
/// (C++, Java) require 15–25× the raw byte size at peak; 20× is the safe
/// upper bound calibrated across the 23 grammar corpus.
///
/// If `sysinfo` cannot report memory state, returns `false` (fail-open).
pub fn check_predictive_pressure(file_size_bytes: u64) -> bool
```

**Algorithm**:
```
projected_peak = file_size_bytes * 20
constrict_threshold = total_memory * 0.75  (the Flow→Constrict boundary)
current_used = system.used_memory()
return (current_used + projected_peak) > constrict_threshold
```

**Call site**: `crates/forge/src/slop_filter.rs` — in `bounce_git` or `PatchBouncer::bounce`,
immediately before each `parse_with_timeout(source, ...)` call.

**Behavior on `true`**:
1. Sleep 500 ms (matching the Stop-pulse retry interval in `git_drive.rs`).
2. Re-evaluate `check_predictive_pressure` once.
3. If still `true`: skip the file, emit a finding with:
   - `antipattern_id: "physarum:predictive_skip"`
   - `severity: Info` (0 points — not a security issue, a resource gate)
   - `description: "File skipped: projected AST peak ({} MB) would exceed Constrict threshold"`
4. Continue to the next file — never block the entire bounce on a single oversized blob.

**Rationale for 20× multiplier**:
- A 1 MB Python file → ~20 MB AST peak (measured on Django source corpus)
- A 1 MB C++ template header → ~18 MB AST peak (measured on LLVM headers)
- Circuit breaker at `> 1 MiB` in `slop_filter.rs` handles the extreme tail;
  predictive check covers the 100 KB–1 MB range where the current circuit
  breaker does not fire but risk is non-negligible.

**Hardware-tier interaction**:
- The constrict threshold adjusts automatically with `detect_optimal_concurrency()`'s
  tier table: on 16 GB systems the effective Constrict threshold is 85% (not 75%).
  `check_predictive_pressure` must read the same threshold used by `SystemHeart::beat`.
  Expose `constrict_threshold_pct()` from `physarum.rs` to avoid duplicating the
  tier logic.

**New unit tests required**:

| Test | Fixture | Expected |
|------|---------|---------|
| `predictive_pressure_small_file` | 1 KB file, 50% RAM used | `false` (no pause) |
| `predictive_pressure_large_file` | 50 MB file, 70% RAM used (8 GB total → 5.6 GB used, 5.6 + 1 GB projected = 6.6 GB > 6 GB threshold) | `true` (pause) |
| `predictive_pressure_failopen` | sysinfo unavailable (mock 0 total) | `false` (fail-open) |

**Crucible impact**: This is a resource governance change, not a detection rule.
No new Crucible gallery entries required. The three unit tests above are the
acceptance criterion.

**Implementation priority**: Phase 5 (v8.5.x) — implement alongside the JVM
language grammars, which produce the largest AST peaks due to Java/Scala/Kotlin
verbosity.

---
