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
Phase 1 (Immediate — 1 sprint):
  ├── Java/C# AhoCorasick patterns (III, Tier 2)
  │     Files: slop_hunter.rs, crucible/src/main.rs
  │     Gate: crucible exit 0, just audit exit 0
  └── Prototype Pollution AhoCorasick Layer A (III, Tier 2)
        Files: slop_hunter.rs, crucible/src/main.rs

Phase 2 (Short-term — 2 sprints):
  ├── Python AST walk upgrade (I, Tier 1)
  │     Files: slop_hunter.rs, polyglot/src/lib.rs (python() already exists)
  │     Gate: crucible exit 0
  └── Java AST walk upgrade (I, Tier 1)
        Files: slop_hunter.rs (add QueryEngine::java_lang field)

Phase 3 (Medium-term — 3 sprints):
  ├── C# AST walk upgrade (I, Tier 1)
  │     Files: slop_hunter.rs (add QueryEngine::csharp_lang field)
  ├── Prototype Pollution AST Layer B (III, Tier 1)
  └── SIMD MinHash (II)
        Files: pr_collider.rs
        Gate: simd_matches_scalar() test passes
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
