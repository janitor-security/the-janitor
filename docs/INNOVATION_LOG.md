# Innovation Log

Autonomous architectural insights, structural gap observations, and
forward-looking feature proposals. Maintained by the Evolution Tracker skill.
Entries are append-only and dated. Proposals range from incremental hardening
to wild architectural pivots.

---

## 2026-04-03 — Initial Seeding

### IDEA-001: Semantic CST Diff Engine — Structural Patch Analysis

**Class:** Core Engine Enhancement  
**Priority:** P1  
**Inspired by:** `crates/forge/src/hashing.rs::AstSimHasher`, VULN-04 blind spots

**Observation:**  
The current bounce engine operates on line-level unified diffs. Two diffs that
are semantically identical (e.g., a variable rename + reorder of function
arguments) produce different line hashes, inflating the `LshIndex` clone
detection false-negative rate. Conversely, a malicious payload inserted via a
whitespace-only formatting change can evade the diff pre-filter.

**Proposal:**  
Replace the line-diff input to `find_slop()` with a **Concrete Syntax Tree
(CST) diff** computed via tree-sitter's built-in incremental parsing. Given
the old and new source for each file:

1. Parse both versions with the appropriate grammar.
2. Compute the minimal edit sequence on the CST (node insertions, deletions,
   replacements) using a tree-edit-distance algorithm (Zhang-Shasha, O(n²)).
3. Feed only the *changed subtrees* into the slop detectors — not the whole
   file diff.

**Security impact:**  
- Eliminates whitespace-padding evasion (VULN-04 class).
- Reduces false positive `logic_erasure` flags for pure refactors that
  preserve branch structure.
- Enables sub-file granularity: a 10 MiB file with a 3-node AST change is
  no longer circuit-breakered by the 1 MiB limit.

**Implementation path:**  
`crates/forge/src/cst_diff.rs` (new) → `CstDelta { added: Vec<Node>, removed: Vec<Node> }` → wire into `PatchBouncer::bounce()` as an optional fast path when `--cst-diff` flag is active.

---

### IDEA-002: Provenance-Aware KEV Escalation

**Class:** Threat Intelligence Integration  
**Priority:** P0  
**Inspired by:** `crates/forge/src/slop_hunter.rs::find_kev_slop`,
`crates/anatomist/src/manifest.rs::find_version_silos_from_lockfile`,
`docs/ENTERPRISE_GAPS.md::VULN-02`

**Observation:**  
The KEV gate (`Severity::KevCritical`, 150 pts) currently fires only when
a patch contains a *syntactic pattern* matching a known exploit class (SQLi
concatenation, SSRF, path traversal). This requires the attacker to introduce
code that *uses* the vulnerable function. But the most common real-world
scenario is different: a dependency upgrade silently introduces a version that
*contains* a CVE-listed vulnerability, with no change to the calling code.

**Proposal:**  
Extend `janitor_dep_check` to correlate the resolved dependency tree against
the CISA KEV catalog (already fetched via `update-wisdom`):

1. For each direct + transitive dep in `Cargo.lock`, query the local
   `wisdom.db` for KEV entries matching the crate + version range.
2. If a match is found, synthesize a `SlopFinding` with
   `severity: KevCritical`, `category: "supply_chain:kev_dependency"`, and
   the CVE ID in `description`.
3. The finding is emitted into the bounce result even if the patch itself
   contains no dangerous code.

**Security impact:**  
Closes the gap between "dep is vulnerable" and "patch uses the vulnerable
codepath." A `cargo add serde_json@1.0.94` that pulls in a KEV-listed transitive
dep becomes a hard block at `slop_score >= 150` before the PR is merged.

**Implementation path:**  
`crates/anatomist/src/manifest.rs::check_kev_deps(lockfile, wisdom_db)`  
→ returns `Vec<SlopFinding>` with `KevCritical` severity  
→ merged into `PatchBouncer::bounce()` result alongside structural findings.

---

### IDEA-003: Adversarial Grammar Stress Harness

**Class:** Defensive Hardening / Fuzzing  
**Priority:** P1  
**Inspired by:** `PARSER_TIMEOUT_MICROS`, `Severity::Exhaustion`, VULN-04

**Observation:**  
The 500 ms parse timeout (`Severity::Exhaustion`) exists because adversarially
crafted source can drive tree-sitter into O(n²) or O(n³) parse time on certain
grammar ambiguities. Currently, the only protection is the timeout itself — we
have no systematic way to discover *which* inputs trigger worst-case parse
behaviour across all 23 grammars before a real attacker does.

**Proposal:**  
Build a `crates/fuzz` target (cargo-fuzz / libFuzzer) for each grammar that:

1. Takes arbitrary bytes as input.
2. Attempts to parse with the grammar under a 100 ms budget.
3. If the parse exhausts the budget, records the input as a new
   `Severity::Exhaustion` Crucible fixture.
4. Runs as a scheduled CI job (nightly, 30 min budget per grammar).

Any input that causes Exhaustion becomes a permanent regression fixture in
`crates/crucible/src/main.rs`. The deep-scan mode (`--deep-scan`, VULN-04
solution) is then validated against these fixtures to confirm the extended
timeout handles them without OOM.

**Implementation path:**  
`crates/fuzz/fuzz_targets/fuzz_grammar_<lang>.rs` × 23  
→ `cargo fuzz run fuzz_grammar_py -- -max_total_time=1800`  
→ crash corpus committed to `crates/crucible/fixtures/exhaustion/`

**Wild pivot:**  
Feed the fuzzer corpus into an LLM-guided mutator that generates *semantically
valid* source (not random bytes) to probe higher-level ambiguities in the
grammar (e.g., deeply nested closures in Kotlin, recursive HCL modules).
This shifts the threat model from syntactic to semantic exhaustion attacks.
