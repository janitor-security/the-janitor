# Slop Hunter: Antipattern Detection Engine

The **Slop Hunter** (`crates/forge/src/slop_hunter.rs`) is The Janitor's tree-sitter-powered antipattern scanner. It runs on every PR diff that passes through the bounce pipeline, parsing the changed source with a language-appropriate grammar and detecting structural code patterns that indicate low-quality, hallucinated, or unsafe authorship.

Unlike grep-based scanners, the Slop Hunter operates on the **parse tree** — it sees function boundaries, block nesting, and statement types, not byte sequences. This eliminates false positives from comments and string literals.

---

## How It Works

```
PR diff → extract_patch_blobs() → [for each blob]
    → polyglot::LazyGrammarRegistry::get(ext)
    → tree_sitter::Parser::parse(source)
    → find_slop(lang, source) → Vec<SlopFinding>
    → SlopScore.antipatterns_found += findings.len()
    → SlopScore.antipattern_details += finding.description
```

Each `SlopFinding` carries a `description` string that is surfaced verbatim in the `janitor bounce` JSON output and the `.janitor/bounce_log.ndjson` entry. The penalty per antipattern finding is **×50 points** — the second-highest weight in the scoring system.

---

## Detected Antipatterns by Language

### Python — Hallucinated Imports

**Pattern**: An `import` statement appears *inside* a function body and the imported name is never referenced within that function.

```python
# Detected: import inside function, 'otel_context' never used
def process_request(req):
    import otel_context  # hallucinated — no call site in scope
    return req.handle()
```

This pattern is the strongest signal of AI hallucination in Python code. The model knows that OpenTelemetry context propagation is appropriate here, generates the import, then fails to wire the actual call — leaving a dead import at function scope. The Slop Hunter walks the function body's AST, collects all `import_statement` and `import_from_statement` nodes, and cross-references each imported name against identifier nodes in the same scope.

**Penalty**: `antipatterns_found += 1` per import (×50 each).

---

### Rust — Vacuous `unsafe` Blocks

**Pattern**: An `unsafe` block contains no raw pointer dereferences, no `extern "C"` function calls, and no `asm!()` invocations.

```rust
// Detected: unsafe block with no unsafe operations
unsafe {
    let x = compute_offset(base, stride);  // safe arithmetic
    buffer[x] = value;                     // bounds-checked index
}
```

Every `unsafe` block is a contract: the author asserts they have manually verified the invariants that the compiler cannot. A vacuous `unsafe` block invokes that contract for code that needs no such verification. It degrades the meaning of `unsafe` as a review signal and inflates the unsafe surface that soundness auditors must examine.

The Slop Hunter walks `unsafe_block` nodes in the parse tree and checks for:

- Raw pointer dereferences: `*ptr` followed by an identifier or `_`
- FFI calls: presence of `extern` in scope
- Inline assembly: `asm` keyword

If none are present, the block is flagged.

**Real finding from this audit**: PR #153239 in `rust-lang/rust` — 8 vacuous `unsafe` blocks, **score 1,235**.

---

### Go — Goroutine Closure Traps

**Pattern**: A goroutine launched inside a loop captures a loop variable by reference rather than by value.

```go
// Detected: goroutine closure captures loop variable 'v' directly
for _, v := range items {
    go func() {
        process(v)  // v will be the last value by the time goroutine runs
    }()
}
```

This is a classic Go concurrency bug: by the time the goroutine executes, the loop variable `v` has advanced to its final value (or is invalidated). The fix is to shadow the variable at goroutine entry:

```go
for _, v := range items {
    v := v  // shadow: goroutine captures its own copy
    go func() {
        process(v)
    }()
}
```

The Slop Hunter detects this via direct AST walking — it does not use a stored tree-sitter query for Go (the query is evaluated dynamically). It identifies `for_statement` nodes containing `go_statement` children whose bodies reference variables bound in the enclosing `range` clause.

---

### C++ — Raw `new` Allocation

**Pattern**: A `new` expression appears outside of a `make_unique` or `make_shared` call.

```cpp
// Detected: raw new — not exception-safe
Widget* w = new Widget(config);
```

```cpp
// Correct: exception-safe RAII
auto w = std::make_unique<Widget>(config);
```

Raw `new` is not exception-safe in the presence of multiple evaluated arguments. `std::make_unique<T>()` provides atomic allocation and initialization. In any codebase targeting C++14 or later, raw `new` in new code is a code quality regression.

**Real finding from this audit**: `electron/electron` — 68 antipatterns across 100 PRs, predominantly raw `new` (×7 in the top-scoring PR alone).

---

### Java — `System.out.println` in Production Code

**Pattern**: `System.out.println(` appears in a `.java` file.

```java
// Detected: console debug logging in production
System.out.println("Processing request: " + req.getId());
```

`System.out` is synchronised on the `PrintStream` monitor, is not configurable by log level, and writes to stdout with no structured metadata. In any production Java codebase — Spring, Kafka, Elasticsearch — the invariant is: use SLF4J or Log4j. `System.out.println` in committed code is debug logging that was never cleaned up.

**Real finding from this audit**: `apache/kafka` — PR #21580 by `aliehsaeedii`, score **800**, antipattern: `System.out.println`.

---

## The Curl Defense: Semantic Sanity Checking

In early 2026, the [curl](https://curl.se) project announced it was closing its bug bounty program due to an overwhelming volume of AI-generated vulnerability reports — PRs and issues that used authoritative security language (CVE references, buffer overflow claims, RCE disclosures) but described changes with no actual security relevance. The volume of hallucinated reports consumed more maintainer time than the real vulnerabilities the program was designed to catch.

The Curl Defense is The Janitor's response.

### What It Detects

A **Hallucinated Security Fix** is a PR that:

1. Claims to address a security issue in its description (CVE number, vulnerability class, exploit technique), **and**
2. Changes only non-code files — documentation, images, manifests, lock files, configuration.

A real security fix requires modifying source code. A PR that claims to fix a CVE while only touching `README.md` is either a documentation update that was mislabelled, or an adversarial submission designed to appear high-priority.

### Security Keywords Monitored

```
CVE-<digits>    buffer overflow    memory leak    RCE
vulnerability   exploit            XSS            SQLi
```

The `CVE-` pattern requires at least one digit immediately after the hyphen — `CVE-2026-9999` triggers; `CVE-reporting process` does not.

Matching is case-insensitive via AhoCorasick multi-pattern search (O(n + m), no regex engine).

### Non-Code File Extensions

A PR is flagged only if **all** changed files have a non-code extension:

```
.md  .txt  .png  .jpg  .jpeg  .gif  .svg  .webp
.json  .yaml  .yml  .toml  .lock  .sum  .csv  .xml
(extensionless: LICENSE, OWNERS, CODEOWNERS, NOTICE)
```

If any changed file has a code extension (`.rs`, `.py`, `.go`, `.ts`, `.cpp`, `.java`, …), the check does not fire — the PR is changing real code, and the security claim may be legitimate.

### Penalty

**×100 points** — the highest per-finding weight in the system. A single Hallucinated Security Fix detection produces a score of 100, which exceeds The Janitor GitHub Action's default gate threshold of 100 and blocks the merge.

### Example

```bash
# PR body: "Fixes CVE-2026-9999: critical buffer overflow in the auth module."
# Changed files: README.md

janitor bounce . --patch pr.patch \
  --pr-body "Fixes CVE-2026-9999: critical buffer overflow in the auth module."
```

```json
{
  "slop_score": 100,
  "hallucinated_security_fix": 1,
  "antipattern_details": [
    "Hallucinated Security Fix: PR body claims 'CVE-' but only non-code files changed (md). A real security fix requires modifying source code."
  ],
  "is_clean": false
}
```

The PR is blocked. The maintainer receives a clear explanation. The signal-to-noise ratio of the security review queue is preserved.

### Implementation

| Component | Location |
|:----------|:---------|
| Keyword detection | `crates/forge/src/metadata.rs` → `detect_hallucinated_fix()` |
| Pipeline integration | `crates/forge/src/slop_filter.rs` → `check_hallucinated_fix()` |
| Patch extension extraction | `crates/forge/src/slop_filter.rs` → `extract_all_patch_exts()` |
| CLI wiring (git + patch modes) | `crates/cli/src/main.rs` → `cmd_bounce()` |

---

## The Universal Bot Shield

Automated dependency bots (`dependabot`, `renovate`, `r-ryantm`, GitHub Apps) submit high volumes
of lockfile and manifest PRs. Before v6.12.1, these PRs were analysed identically to human PRs —
resulting in high antipattern noise from hallucinated security fix detections on yml-only patches.

The Universal Bot Shield classifies author accounts across four layers before any bounce analysis:

| Layer | Pattern | Example |
|:------|:--------|:--------|
| 1 | `app/` prefix — GitHub Apps API format | `app/dependabot`, `app/copilot-swe-agent` |
| 2 | `[bot]` suffix — legacy naming | `renovate-bot`, `dependabot[bot]` |
| 3 | `trusted_bot_authors` — global allowlist | Configured in `janitor.toml` |
| 4 | `[forge].automation_accounts` — per-repo | `r-ryantm`, `app/nixpkgs-ci` |

**Bot PRs still receive full structural analysis.** Dead symbols, logic clones, zombie deps,
antipatterns — all signals are computed and reported. The Universal Bot Shield classifies the
author for reporting purposes; it does not exempt bot code from review.

### Why This Matters

In the Global Audit 2026, `app/renovate` and `app/dependabot` each appeared in multiple Toxic PR
top-3 lists — predominantly Hallucinated Security Fix detections on yaml-only patches. With the
Universal Bot Shield in place, these are correctly attributed as bot behaviour and separated from
human-authored structural slop in audit reports.

### Configuration

```toml
# janitor.toml — per-repo automation account list
[forge]
automation_accounts = ["r-ryantm", "app/nixpkgs-ci", "myorg-bot"]
```

---

## The Agnostic IaC Shield

Not every patch can be parsed by a tree-sitter grammar. The `ByteLatticeAnalyzer`
(`crates/forge/src/agnostic_shield.rs`) provides language-agnostic byte-level classification for
any file type — no grammar required.

### Detection Algorithm

1. **Null-byte detection** — Binary files and embedded binary blobs contain null bytes (`\0`).
   Well-formed source code never does. Any null byte → `AnomalousBlob`.

2. **Windowed entropy analysis** — Shannon entropy computed over 512-byte windows (stride 256).
   `max_window_entropy` tracks the highest single-window value across the entire input. Any window
   exceeding **7.0 bits/byte** → `AnomalousBlob` (compressed, encrypted, or shellcode payload).

3. **IaC bypass** — Files with extensions `.nix`, `.lock`, `.json`, `.toml`, `.yaml`, `.yml`,
   `.csv` skip `ByteLatticeAnalyzer` entirely. These formats contain legitimate high-entropy
   content (nix sha256 hashes, lockfile digests) that is definitively not anomalous binary content.

### What It Catches

- Encrypted blobs embedded in source patches ("1Campaign"-style cloaking)
- Base64-decoded secrets injected into large, mostly normal files
- Binary files disguised as source (null byte detection)
- Shellcode hidden inside low-entropy surrounding code (windowed max entropy, not file average)

### Classification

| Condition | Result |
|:----------|:-------|
| Null byte present | `AnomalousBlob` — binary content |
| Any window entropy > 7.0 bits/byte | `AnomalousBlob` — compressed/encrypted payload |
| IaC extension (`.nix`, `.lock`, `.json`, `.toml`, etc.) | Bypass — no entropy check |
| Otherwise | `ProbableCode` |

### Penalty

`AnomalousBlob` detection contributes **×50 points** via `antipatterns_found`. The
`antipattern_details` field carries the description verbatim in all bounce output modes.

---

## Output Format

Antipattern details are included verbatim in all bounce output modes:

```bash
janitor bounce . --patch pr.patch --format json
```

```json
{
  "schema_version": "6.9.0",
  "slop_score": 150,
  "antipatterns_found": 3,
  "antipattern_details": [
    "Vacuous unsafe block: contains no raw pointer dereferences, FFI calls, or inline assembly",
    "Vacuous unsafe block: contains no raw pointer dereferences, FFI calls, or inline assembly",
    "Hallucinated import: 'otel_context' imported inside function but never used"
  ]
}
```

Text output (`--format text`) lists each violation in a formatted table alongside the score breakdown.

---

> **See what the Slop Hunter catches in your PRs.**
>
> ```bash
> janitor bounce . --repo . --base main --head HEAD
> ```
>
> [Global Audit 2026 →](case-studies/global-audit-2026.md) · [Pricing](pricing.md)
