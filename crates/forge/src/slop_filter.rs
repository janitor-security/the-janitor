//! PR Slop Filter — detect dead-code additions and logic clones in patches.
//!
//! [`PRBouncer`] is a trait for patch quality gatekeepers.
//! [`PatchBouncer`] is the default implementation: it parses a unified diff,
//! extracts added source for the detected language, and uses structural hashing
//! to detect duplication and re-introduction of known symbols.
//! [`GitBouncer`] is an alternative that drives analysis from git OIDs via
//! [`shadow_git::simulate_merge`], loading changed blobs from the pack index
//! without a working-directory checkout.
//!
//! ## Language Detection
//! The patch language is detected from the `+++ b/<path>` header line by
//! extension. Supported: `.py`, `.rs`, `.cpp/.cxx/.cc/.h/.hpp`, `.c`,
//! `.java`, `.cs`, `.go`, `.js/.jsx`, `.ts/.tsx`, `.glsl/.vert/.frag`.
//! For unsupported extensions, [`agnostic_shield`] classifies the added bytes
//! to detect embedded binary blobs.
//!
//! ## Parser Error Neutrality
//! If the tree-sitter parse of a file's added source contains any `ERROR` or
//! `MISSING` nodes, [`PatchBouncer`] returns a neutral [`SlopScore`] (all
//! zeros) for that file.  This prevents false positives when a grammar version
//! lags behind the language standard (e.g. TypeScript 6.0 syntax features not
//! yet supported by the bundled grammar).
//!
//! ## Scoring Formula
//! ```text
//! SlopScore = (logic_clones_found      ×  5)
//!           + (zombie_symbols_added    × 10)   // Warning tier
//!           + antipattern_score.min(500)        // sum of per-finding Severity::points()
//!           + (hallucinated_security_fix × 100)
//! ```
//! Antipattern scoring is stratified by [`crate::slop_hunter::Severity`]:
//! - `Critical` (50 pts): AST-Bombs, `gets()`, open CIDR rules, K8s wildcard hosts,
//!   compiled payload injection.
//! - `Warning`  (10 pts): NCD entropy anomaly (`antipattern:ncd_anomaly`).
//! - `Lint`     ( 0 pts): Reserved for future non-scoring informational rules.
//!
//! The `antipattern_score` field accumulates these per-finding values; `antipatterns_found`
//! remains the raw count for reporting purposes.  `antipattern_score` is capped at 500 pts
//! (equivalent to 10 Critical findings) to prevent runaway score inflation.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use anyhow::Result;
use tree_sitter::{Language, Query, StreamingIterator};

use common::registry::SymbolRegistry;

// ---------------------------------------------------------------------------
// SlopScore
// ---------------------------------------------------------------------------

/// Score representing the amount of "slop" detected in a patch.
///
/// ## Formula
/// ```text
/// score = (logic_clones_found      ×  5)
///       + (zombie_symbols_added    × 10)   — Warning tier
///       + antipattern_score.min(500)        — sum of per-finding Severity::points()
///       + (comment_violations      ×  5)
///       + (unlinked_pr             × 20)
///       + (hallucinated_security_fix × 100)
///       + agentic_origin_penalty            — 0 or 50 flat surcharge
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlopScore {
    /// Number of added functions whose names already appear in the registry.
    ///
    /// Signals that the patch re-introduces or duplicates a known symbol —
    /// a common source of dead code accumulation.
    pub dead_symbols_added: u32,
    /// Number of structurally identical function pairs within the added code,
    /// plus functions whose structural hash matches a live (protected) registry entry
    /// (Global Logic Clones).
    ///
    /// Each "extra" clone beyond the first occurrence in a hash group counts
    /// as one clone (N functions sharing a hash → N−1 clones).
    pub logic_clones_found: u32,
    /// Number of added functions whose structural body hash matches a *dead*
    /// (unprotected) symbol in the registry.
    ///
    /// A zombie reintroduction proves the function body was copied from a previously
    /// deleted symbol — Warning-tier slop (weight ×10).
    pub zombie_symbols_added: u32,
    /// Number of language-specific antipatterns detected by [`crate::slop_hunter`]:
    /// hallucinated imports, vacuous unsafe blocks, goroutine closure traps, etc.
    ///
    /// Raw count for reporting; does not directly drive scoring.  See
    /// [`antipattern_score`](Self::antipattern_score) for the weighted total.
    pub antipatterns_found: u32,

    /// Weighted point sum for all accepted antipattern findings.
    ///
    /// Each finding contributes `severity.points()` to this total:
    /// - `Critical` → 50 pts (AST-Bombs, `gets()`, open CIDR, K8s wildcard hosts, compiled payload)
    /// - `Warning`  → 10 pts (`antipattern:ncd_anomaly` — NCD entropy gate)
    /// - `Lint`     →  0 pts (reserved)
    ///
    /// This field is what [`Self::score()`] uses, not `antipatterns_found × 50`.
    /// Capped at 500 in `score()` to prevent runaway inflation.
    pub antipattern_score: u32,
    /// Number of banned phrases (AI-isms, profanity) found in added comment lines.
    ///
    /// Detected by [`crate::metadata::CommentScanner::scan_patch`].
    /// Each violation carries a weight of ×5.
    pub comment_violations: u32,
    /// 1 if the PR body contains no issue link (`Closes #N`, `Fixes #N`, etc.),
    /// 0 otherwise.
    ///
    /// Detected by [`crate::metadata::CommentScanner::is_pr_unlinked`].
    /// Carries a fixed penalty of ×20 when set.
    pub unlinked_pr: u32,

    /// Human-readable description of each antipattern finding — one entry per
    /// [`antipatterns_found`](Self::antipatterns_found) count.
    ///
    /// Populated in patch mode (via [`PatchBouncer`]); empty in git-native mode
    /// where blobs are processed per-file without a unified surface string.
    pub antipattern_details: Vec<String>,

    /// Truncated matched phrase for each comment violation — one entry per
    /// [`comment_violations`](Self::comment_violations) count.
    ///
    /// Populated in patch mode only; empty in git-native mode.
    pub comment_violation_details: Vec<String>,

    /// `1` if the PR was flagged as a Hallucinated Security Fix, `0` otherwise.
    ///
    /// Detected by [`crate::metadata::detect_hallucinated_fix`] when the PR body
    /// contains security-claim keywords (`CVE-<N>`, `buffer overflow`, `RCE`, etc.)
    /// but every changed file has a non-code extension (`.md`, `.json`, `.png`, …).
    ///
    /// This is an adversarial signal — it indicates the PR description was crafted
    /// to exploit security-scanner bypass heuristics without shipping actual fixes.
    /// Carries a fixed penalty of ×100 — the highest per-finding weight.
    pub hallucinated_security_fix: u32,

    /// Number of antipattern findings suppressed by domain routing.
    ///
    /// When a file is classified as [`crate::metadata::DOMAIN_VENDORED`] or
    /// [`crate::metadata::DOMAIN_TEST`], memory-safety rules
    /// (e.g. raw `new`/`delete`, vacuous `unsafe`, hallucinated imports) with
    /// [`crate::metadata::DOMAIN_FIRST_PARTY`] domain masks are not applied.
    ///
    /// This counter records how many findings were withheld — surfaced in the
    /// intelligence report as "Domain Routing" context so the operator knows the
    /// engine is not blind, just selective.
    ///
    /// Does **not** contribute to [`Self::score()`].
    pub suppressed_by_domain: u32,

    /// PR numbers of previously-seen patches whose MinHash Jaccard similarity ≥ 0.85
    /// with this patch.
    ///
    /// Populated by `cmd_bounce` after querying the per-session [`LshIndex`].
    /// Empty when no prior entries are in the bounce log or when running without
    /// a populated MinHash index.
    ///
    /// Does **not** contribute to [`Self::score()`].
    pub collided_pr_numbers: Vec<u32>,

    /// Necrotic garbage-collection flag assigned by the Backlog Pruner.
    ///
    /// One of `"SEMANTIC_NULL"`, `"GHOST_COLLISION"`, or `"UNWIRED_ISLAND"`.
    /// `None` when no necrotic condition was detected or when the patch lacked
    /// sufficient context to run the pruner checks.
    ///
    /// Does **not** contribute to [`Self::score()`].
    pub necrotic_flag: Option<String>,

    /// Flat penalty applied when the PR is attributed to an autonomous coding agent.
    ///
    /// Set by `cmd_bounce` when [`common::policy::JanitorPolicy::is_agentic_actor`]
    /// returns `true` for the PR author or PR body.  The value is always `0` (inactive)
    /// or `50` (active) — no intermediate values.
    ///
    /// ## Rationale
    ///
    /// Machine-authored PRs bypass human authorship entirely.  The +50 surcharge
    /// forces agent code to be structurally flawless: a `copilot[bot]` PR with a
    /// single Critical antipattern scores 100 (50 antipattern + 50 surcharge) and
    /// fails the default 100-point gate.  A structurally clean agent PR scores 50
    /// and passes cleanly — the gate enforces a higher bar, not a blanket block.
    pub agentic_origin_penalty: u32,

    /// Crate/package names that appear at more than one distinct version across the PR's
    /// manifest files (`Cargo.toml`, `package.json`).
    ///
    /// Populated by `cmd_bounce` via [`anatomist::manifest::find_version_silos_in_blobs`].
    /// Each entry contributes **+20 points** to [`Self::score()`].
    ///
    /// A version silo indicates that the PR introduces or widens a dependency split —
    /// two workspace members (or two package.json dependency sections) pin the same
    /// crate at different versions.  This forces the Cargo resolver to maintain two
    /// parallel compilation artifacts and is a common source of diamond dependency
    /// conflicts in rapidly evolving monorepos.
    pub version_silo_details: Vec<String>,
}

impl SlopScore {
    /// Returns the weighted aggregate slop score.
    ///
    /// Higher scores indicate lower patch quality. A score of zero means the
    /// patch passes all checks cleanly.
    pub fn score(&self) -> u32 {
        // Clamp logic_clones_found to 50 before multiplication to prevent
        // runaway scores on adversarial or degenerate inputs (e.g. a PR that
        // copies the same function 10 000 times).  A real patch with 50+ clone
        // pairs is already conclusively slop at 250 points; the ceiling adds
        // no information beyond that.
        let clamped_clones = self.logic_clones_found.min(50);
        // Cap antipattern_score at 500 pts (equivalent to 10 Critical findings)
        // to prevent score explosion from generated FFI bindings or large
        // auto-templated files that legitimately trigger the same pattern many times.
        let capped_antipattern_score = self.antipattern_score.min(500);
        clamped_clones * 5
            + self.zombie_symbols_added * 10
            + capped_antipattern_score
            + self.comment_violations * 5
            + self.unlinked_pr * 20
            + self.hallucinated_security_fix * 100
            + self.agentic_origin_penalty
            + self.version_silo_details.len() as u32 * 20
    }

    /// Returns `true` when no slop was detected.
    pub fn is_clean(&self) -> bool {
        self.logic_clones_found == 0
            && self.zombie_symbols_added == 0
            && self.antipatterns_found == 0
            && self.comment_violations == 0
            && self.unlinked_pr == 0
            && self.hallucinated_security_fix == 0
            && self.agentic_origin_penalty == 0
            && self.version_silo_details.is_empty()
    }
}

// ---------------------------------------------------------------------------
// PRBouncer trait
// ---------------------------------------------------------------------------

/// Trait for patch-quality gatekeepers.
///
/// Implementors inspect a unified diff patch against an existing symbol registry
/// and return a [`SlopScore`] characterising the quality of the added code.
pub trait PRBouncer {
    /// Analyse `patch` (unified diff format) against `registry` and return a
    /// [`SlopScore`] quantifying dead-symbol additions and logic clones.
    ///
    /// # Errors
    /// Returns `Err` if the grammar fails to load or the patch cannot be parsed.
    fn bounce(&self, patch: &str, registry: &SymbolRegistry) -> Result<SlopScore>;
}

// ---------------------------------------------------------------------------
// Language configuration
// ---------------------------------------------------------------------------

/// Per-language configuration for function extraction from added patch lines.
struct LangConfig {
    /// Tree-sitter `Language` object for this grammar.
    language: Language,
    /// S-expression query that captures `@fn.name` and `@fn.body` for each
    /// function/method definition in the added source.
    query_src: &'static str,
}

/// Returns the `LangConfig` for the given file extension, or `None` if
/// the language is unsupported by the slop filter.
fn lang_for_ext(ext: &str) -> Option<LangConfig> {
    match ext {
        "py" => Some(LangConfig {
            language: tree_sitter_python::LANGUAGE.into(),
            query_src: "(function_definition name: (identifier) @fn.name body: (block) @fn.body)",
        }),
        "rs" => Some(LangConfig {
            language: tree_sitter_rust::LANGUAGE.into(),
            query_src: "(function_item name: (identifier) @fn.name body: (block) @fn.body)",
        }),
        "cpp" | "cxx" | "cc" | "h" | "hpp" | "c" => Some(LangConfig {
            // C++ grammar is a superset of C; use it for both.
            language: tree_sitter_cpp::LANGUAGE.into(),
            query_src: r#"
                (function_definition
                  declarator: (function_declarator
                    declarator: (identifier) @fn.name)
                  body: (compound_statement) @fn.body)
            "#,
        }),
        "java" => Some(LangConfig {
            language: tree_sitter_java::LANGUAGE.into(),
            query_src: "(method_declaration name: (identifier) @fn.name body: (block) @fn.body)",
        }),
        "cs" => Some(LangConfig {
            language: tree_sitter_c_sharp::LANGUAGE.into(),
            query_src: "(method_declaration name: (identifier) @fn.name body: (block) @fn.body)",
        }),
        "go" => Some(LangConfig {
            language: tree_sitter_go::LANGUAGE.into(),
            query_src: "(function_declaration name: (identifier) @fn.name body: (block) @fn.body)",
        }),
        "js" | "jsx" => Some(LangConfig {
            language: tree_sitter_javascript::LANGUAGE.into(),
            query_src: r#"
                (function_declaration
                  name: (identifier) @fn.name
                  body: (statement_block) @fn.body)
            "#,
        }),
        "glsl" | "vert" | "frag" => Some(LangConfig {
            // GLSL syntax is C-like; function bodies are compound_statement.
            language: tree_sitter_glsl::LANGUAGE_GLSL.into(),
            query_src: r#"
                (function_definition
                  declarator: (function_declarator
                    declarator: (identifier) @fn.name)
                  body: (compound_statement) @fn.body)
            "#,
        }),
        // Scala: captures def (function_definition), class, and object top-level entities.
        "scala" => Some(LangConfig {
            language: tree_sitter_scala::LANGUAGE.into(),
            query_src: r#"
                (function_definition
                  name: (identifier) @fn.name
                  body: (block) @fn.body)
            "#,
        }),
        // Bash / shell scripts: function definitions only.
        "sh" | "bash" | "cmd" | "zsh" => Some(LangConfig {
            language: tree_sitter_bash::LANGUAGE.into(),
            query_src: r#"
                (function_definition
                  name: (word) @fn.name
                  body: (compound_statement) @fn.body)
            "#,
        }),
        // Objective-C / Objective-C++: covers both C-style free functions and simple
        // unary ObjC method selectors (e.g. `dealloc`, `sharedInstance`).
        // Multi-keyword selectors are excluded — they are not in the dead-code hot path.
        "m" | "mm" => Some(LangConfig {
            language: tree_sitter_objc::LANGUAGE.into(),
            query_src: r#"
                (method_definition
                  (identifier) @fn.name
                  (compound_statement) @fn.body)

                (function_definition
                  declarator: (function_declarator
                    declarator: (identifier) @fn.name)
                  body: (compound_statement) @fn.body)
            "#,
        }),
        // Ruby: instance methods, singleton (class) methods. Body is body_statement.
        "rb" => Some(LangConfig {
            language: tree_sitter_ruby::LANGUAGE.into(),
            query_src: r#"
                (method
                  name: (_) @fn.name
                  body: (body_statement) @fn.body)
                (singleton_method
                  name: (_) @fn.name
                  body: (body_statement) @fn.body)
            "#,
        }),
        // PHP: top-level functions and class methods.
        "php" => Some(LangConfig {
            language: tree_sitter_php::LANGUAGE_PHP.into(),
            query_src: r#"
                (function_definition
                  name: (name) @fn.name
                  body: (compound_statement) @fn.body)
                (method_declaration
                  name: (name) @fn.name
                  body: (compound_statement) @fn.body)
            "#,
        }),
        // Swift: free functions and class/struct methods.
        "swift" => Some(LangConfig {
            language: tree_sitter_swift::LANGUAGE.into(),
            query_src: r#"
                (function_declaration
                  name: (simple_identifier) @fn.name
                  body: (function_body) @fn.body)
            "#,
        }),
        // Lua: named function declarations (simple identifier form).
        "lua" => Some(LangConfig {
            language: tree_sitter_lua::LANGUAGE.into(),
            query_src: r#"
                (function_declaration
                  name: (identifier) @fn.name
                  body: (block) @fn.body)
            "#,
        }),
        _ => None,
    }
}

/// Translate a byte offset within `source` to a 1-based line number.
///
/// Counts the number of `\n` bytes strictly before `offset` to derive the
/// line number.  The result is always ≥ 1.  If `offset` exceeds `source.len()`
/// the function clamps silently and returns the last line number.
///
/// Used to annotate AhoCorasick byte-offset matches and tree-sitter
/// `start_byte` values with a human-readable line number before the findings
/// are serialised into `antipattern_details`.
fn byte_offset_to_line(source: &[u8], offset: usize) -> u32 {
    let clamped = offset.min(source.len());
    source[..clamped].iter().filter(|&&b| b == b'\n').count() as u32 + 1
}

/// Extract the file extension from the `+++ b/<path>` line in a unified diff.
///
/// Returns `""` if no such header is found or the path has no extension.
fn extract_patch_ext(patch: &str) -> &str {
    for line in patch.lines() {
        if let Some(path) = line
            .strip_prefix("+++ b/")
            .or_else(|| line.strip_prefix("+++ "))
        {
            // Strip query strings or trailing whitespace that some diff tools add.
            let path = path.trim();
            if let Some(dot_pos) = path.rfind('.') {
                return &path[dot_pos + 1..];
            }
        }
    }
    ""
}

/// Extract the full file path from the `+++ b/<path>` line in a unified diff.
///
/// Returns an empty string when no `+++ b/` header is found or the path is
/// `/dev/null` (deleted-file sentinel).  Used by domain routing in
/// [`PatchBouncer`] to classify the file's context before rule application.
fn extract_patch_path(patch: &str) -> String {
    for line in patch.lines() {
        if let Some(path) = line
            .strip_prefix("+++ b/")
            .or_else(|| line.strip_prefix("+++ "))
        {
            let path = path.trim();
            if !path.is_empty() && path != "/dev/null" {
                return path.to_string();
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Multi-file patch splitting
// ---------------------------------------------------------------------------

/// Split a multi-file unified diff into individual per-file patch slices.
///
/// Splits on `diff --git ` boundary lines (the standard git unified-diff
/// separator).  If no such boundary is found, the whole patch is returned
/// as a single-element slice — this preserves backward compatibility with
/// single-file patches that begin directly at the `+++ b/` header.
///
/// Returned slices borrow from the input; no allocation beyond the `Vec`
/// itself.
pub fn split_patch_by_file(patch: &str) -> Vec<&str> {
    let marker = "diff --git ";
    let mut positions: Vec<usize> = Vec::new();

    // First section may start at byte 0 (no leading newline).
    if patch.starts_with(marker) {
        positions.push(0);
    }

    // Remaining sections are preceded by a newline.
    let mut search = 0usize;
    while let Some(rel) = patch[search..].find('\n') {
        let abs = search + rel + 1;
        if patch[abs..].starts_with(marker) {
            positions.push(abs);
        }
        search = abs;
        if search >= patch.len() {
            break;
        }
    }

    if positions.is_empty() {
        return if patch.is_empty() {
            vec![]
        } else {
            vec![patch]
        };
    }

    let mut sections = Vec::with_capacity(positions.len());
    for i in 0..positions.len() {
        let start = positions[i];
        let end = positions.get(i + 1).copied().unwrap_or(patch.len());
        sections.push(&patch[start..end]);
    }
    sections
}

// ---------------------------------------------------------------------------
// PatchBouncer (default implementation)
// ---------------------------------------------------------------------------

/// Default [`PRBouncer`] implementation — analyses added functions in a
/// unified diff using the language detected from the `+++` header.
///
/// # Algorithm
/// 1. Detect the patch language from the `+++ b/<path>` header extension.
/// 2. Extract all `+`-prefixed lines (excluding `+++` header lines) to
///    reconstruct the virtual added source.
/// 3. Parse the added source with the matching Tree-sitter grammar, locating
///    function definitions and computing structural hashes via
///    [`compute_structural_hash`][crate::compute_structural_hash].
/// 4. **`dead_symbols_added`**: functions whose names already exist in the
///    registry — likely re-introductions of known symbols.
/// 5. **`logic_clones_found`**: for each hash group with N > 1 members,
///    contribute N − 1 to the clone count.
#[derive(Debug, Default)]
pub struct PatchBouncer;

impl PRBouncer for PatchBouncer {
    fn bounce(&self, patch: &str, registry: &SymbolRegistry) -> Result<SlopScore> {
        // ── Multi-file patch dispatch ─────────────────────────────────────────
        //
        // If the patch contains `diff --git ` boundaries (standard git output),
        // split it into per-file sections and aggregate the scores.  This
        // ensures that a multi-file PR diff is correctly analysed file-by-file
        // rather than treating the entire diff as a single-language blob where
        // only the first `+++ b/` header drives language detection.
        let sections = split_patch_by_file(patch);
        if sections.len() > 1 {
            let mut total = SlopScore::default();
            for section in sections {
                // Errors are non-fatal: a parse failure in one file section does
                // not invalidate the analysis of the remaining sections.
                if let Ok(s) = self.bounce(section, registry) {
                    total.dead_symbols_added += s.dead_symbols_added;
                    total.logic_clones_found += s.logic_clones_found;
                    total.zombie_symbols_added += s.zombie_symbols_added;
                    total.antipatterns_found += s.antipatterns_found;
                    total.antipattern_score += s.antipattern_score;
                    total.suppressed_by_domain += s.suppressed_by_domain;
                    total.antipattern_details.extend(s.antipattern_details);
                }
            }
            return Ok(total);
        }

        // Detect language from the +++ header extension.
        let ext = extract_patch_ext(patch);

        // Extract file path early — reused by the generated-asset bypass, the
        // None-arm AnomalousBlob guard, and domain routing in the Some arm.
        let file_path = extract_patch_path(patch);

        // ── Generated-asset bypass ────────────────────────────────────────────
        // Files in these path contexts or with these compound extensions exhibit
        // high NCD compressibility or binary-level entropy by construction —
        // not slop.  Bypass all analysis early, before tree-sitter is loaded.
        const GENERATED_PATH_SUBSTRINGS: &[&str] = &[
            "/fixtures/",
            "/testdata/",
            "/__snapshots__/",
            "vendor/",
            "thirdparty/",
        ];
        if GENERATED_PATH_SUBSTRINGS
            .iter()
            .any(|s| file_path.contains(s))
        {
            return Ok(SlopScore::default());
        }
        // Compound extension bypass: rfind('.') resolves only the last dot, so
        // "foo.min.js" → ext="js" (hits the JS grammar path).  Check the full
        // path string for known generated multi-dot suffixes and skip entirely.
        const GENERATED_COMPOUND_EXTS: &[&str] = &["min.js", "min.css", "pb.go", "pb.rs"];
        if GENERATED_COMPOUND_EXTS
            .iter()
            .any(|s| file_path.ends_with(s))
        {
            return Ok(SlopScore::default());
        }

        // ── Pre-language binary_hunter scan ───────────────────────────────────
        //
        // Runs BEFORE language dispatch so that the Compiled Payload Shield fires
        // for ALL file types — including SOURCE_TEXT_EXTS (YAML, JSON, TOML, Nix,
        // lock files) that have no grammar and take an early-return path.  This
        // prevents an attacker from hiding a mining-pool stratum URI in a .yml
        // config that bypasses the grammar check.
        //
        // The circuit breaker (64 KiB) is intentionally NOT applied here —
        // AhoCorasick is O(N) and fast; a 100 KiB YAML file embedding a stratum
        // URI must still be flagged even though it would exceed the tree-sitter limit.
        let pre_lang_payload_findings: Vec<String> = {
            let raw_added: String = patch
                .lines()
                .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                .map(|l| &l[1..])
                .collect::<Vec<_>>()
                .join("\n");
            if raw_added.trim().is_empty() {
                vec![]
            } else {
                advanced_threats::binary_hunter::scan(raw_added.as_bytes())
                    .into_iter()
                    .map(|t| {
                        let line = byte_offset_to_line(raw_added.as_bytes(), t.byte_offset);
                        format!("{} (line={line})", t.description)
                    })
                    .collect()
            }
        };

        let cfg = match lang_for_ext(ext) {
            Some(c) => c,
            None => {
                // Source-text bypass: extensions that are definitively human-readable
                // source or configuration — never binary blobs.  Two categories:
                //
                // (A) IaC / data formats: routinely contain high-entropy content
                //     (sha256 hashes, base64 digests, lockfile checksums) that sits
                //     outside the agnostic shield's entropy band but is text.
                //
                // (B) Polyglot-known grammars not wired into lang_for_ext (e.g. bash,
                //     TypeScript, Kotlin) plus other well-known source extensions
                //     (Scala, Gradle, PowerShell, Windows batch, Go module files…).
                //     Rule: if our polyglot registry has a grammar for the extension,
                //     it is definitively source — never run the binary classifier.
                //
                // Keep in sync with `polyglot::LazyGrammarRegistry::get` arm list.
                const SOURCE_TEXT_EXTS: &[&str] = &[
                    // ── IaC / data formats ────────────────────────────────────
                    "nix",
                    "lock",
                    "json",
                    "toml",
                    "yaml",
                    "yml",
                    "csv",
                    "md",
                    "rst",
                    "xml",
                    // ── Polyglot-known grammars not in lang_for_ext ───────────
                    "ts",
                    "tsx",
                    "mjs",
                    "cjs", // TypeScript / JS variants
                    // "sh" | "bash" | "cmd" | "zsh" — now wired into lang_for_ext (Bash grammar)
                    // "scala" — now wired into lang_for_ext (Scala grammar)
                    "tf",
                    "hcl", // Terraform / HCL
                    "gd",  // GDScript
                    "kt",
                    "kts", // Kotlin
                    // ── Explicitly whitelisted source extensions ──────────────
                    "gradle", // Gradle build (Groovy/Kotlin DSL) — no grammar crate
                    // "scala" moved to lang_for_ext
                    "mod", // Go module files — tree-sitter-gomod (^0.20) incompatible with ts 0.26
                    "go-version", // Go toolchain pin files
                    "properties", // Java .properties config
                    "env", // .env config files
                    "bat",
                    "ps1",
                    // "cmd" moved to lang_for_ext (bash grammar covers Windows cmd-like scripts)
                    "patch",            // Diff/patch files (text diffs, may contain hashes)
                    "permitted-images", // Kubernetes allowed-image list files
                    // ── Generated / snapshot text files ──────────────────────
                    "snap", // Jest / insta snapshot files (serialised JS/Rust values)
                    "svg",  // Scalable Vector Graphics (XML text)
                    "map",  // Source map files (JSON text, high-entropy base64 chunks)
                ];
                if SOURCE_TEXT_EXTS.contains(&ext) {
                    // Even though we have no grammar for this extension, the
                    // binary_hunter scan must still surface any payload findings.
                    if !pre_lang_payload_findings.is_empty() {
                        let count = pre_lang_payload_findings.len() as u32;
                        return Ok(SlopScore {
                            antipatterns_found: count,
                            antipattern_score: count * 50, // Critical tier
                            antipattern_details: pre_lang_payload_findings,
                            ..SlopScore::default()
                        });
                    }
                    return Ok(SlopScore::default());
                }

                // Binary asset bypass: known binary formats always trigger the
                // ByteLatticeAnalyzer entropy classifier as AnomalousBlob, producing
                // false positives for font files, images, archives, and WASM blobs.
                // Skip them entirely before the entropy gate runs.
                const BINARY_ASSET_EXTS: &[&str] = &[
                    "wasm", "woff", "woff2", "eot", "ttf", "png", "jpg", "jpeg", "gif", "ico",
                    "zip", "gz", "tar", "pdf",
                ];
                if BINARY_ASSET_EXTS.contains(&ext) {
                    return Ok(SlopScore::default());
                }

                // Unknown / unsupported language — run agnostic shield on added bytes.
                let added: String = patch
                    .lines()
                    .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
                    .map(|l| &l[1..])
                    .collect::<Vec<_>>()
                    .join("\n");
                // Test domain exemption: test code is permitted to contain
                // high-entropy mock data, binary fixtures, or generated vectors
                // that would otherwise trigger AnomalousBlob.
                let path_domain = crate::metadata::DomainRouter::classify(&file_path);
                if !added.trim().is_empty() && path_domain != crate::metadata::DOMAIN_TEST {
                    use crate::agnostic_shield::{ByteLatticeAnalyzer, TextClass};
                    if matches!(
                        ByteLatticeAnalyzer::classify(added.as_bytes()),
                        TextClass::AnomalousBlob
                    ) {
                        // Include a description so antipatterns.len() == antipatterns_found
                        // (data-integrity invariant: the stored score must be reconstructible
                        // from the stored detail fields).
                        return Ok(SlopScore {
                            antipatterns_found: 1,
                            antipattern_score: 50, // Critical — embedded binary / generated data
                            antipattern_details: vec![format!(
                                "AnomalousBlob: high-entropy or non-text content detected \
                                 in .{ext} patch section — possible embedded binary or \
                                 generated data."
                            )],
                            ..SlopScore::default()
                        });
                    }
                }
                return Ok(SlopScore::default());
            }
        };

        // Reconstruct added source from `+` diff lines.
        let added: String = patch
            .lines()
            .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
            .map(|l| &l[1..]) // strip the leading '+'
            .collect::<Vec<_>>()
            .join("\n");

        if added.trim().is_empty() {
            return Ok(SlopScore::default());
        }

        let source = added.as_bytes();

        // Circuit breaker: skip tree-sitter AST work for patch sections > 64 KB.
        // The Rust compiler test suite contains AST bombs (auto-generated match
        // arms, macro expansions) that trigger tree-sitter stack overflows even
        // below 256 KB.  64 KB is the empirical safe ceiling for hand-authored
        // diffs; beyond it the content is overwhelmingly generated (P/Invoke
        // bindings, protobuf stubs, WASM glue, test fixtures).
        if source.len() > 64 * 1024 {
            return Ok(SlopScore::default());
        }

        // NCD Entropy Gate — O(N) compressibility check before the AST crawl.
        //
        // zstd-compress the added source at level 3.  A compression ratio below
        // MIN_ENTROPY_RATIO (0.05) means the patch is highly self-similar: the
        // canonical signal for AI-generated boilerplate or auto-templated code.
        // The finding is accumulated here and merged into the final antipattern
        // list at score assembly — the AST analysis still runs to capture all
        // co-present slop signals.
        let ncd_findings: Vec<String> = {
            use crate::slop_hunter::{check_entropy, MIN_ENTROPY_RATIO};
            let ratio = check_entropy(source);
            if ratio < MIN_ENTROPY_RATIO {
                vec!["antipattern:ncd_anomaly".to_owned()]
            } else {
                vec![]
            }
        };

        // Compiled Payload Shield — reuses the pre-language scan result.
        //
        // `pre_lang_payload_findings` was computed above over the same `+` lines
        // (before the circuit breaker).  The source bytes used there are identical
        // to `source` here because both extract the `+`-prefixed added lines from
        // the same single-file patch section.  No second AhoCorasick pass needed.
        let payload_findings: Vec<String> = pre_lang_payload_findings;

        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&cfg.language)
            .map_err(|e| anyhow::anyhow!("Failed to load grammar for .{ext}: {e}"))?;

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Ok(SlopScore::default()),
        };

        // Parser Error Neutrality: if the AST contains ERROR or MISSING nodes the
        // grammar could not fully understand this file (e.g. new TS 6.0 syntax not yet
        // in our grammar version).  Structural analysis on a broken AST produces false
        // positives — abort and return a neutral score rather than penalise the author.
        if tree.root_node().has_error() {
            return Ok(SlopScore::default());
        }

        let query = Query::new(&cfg.language, cfg.query_src)
            .map_err(|e| anyhow::anyhow!("Query compile error for .{ext}: {e}"))?;

        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        let cap_names = query.capture_names();

        // Collect (name, blake3_hash, simhash) triples for all added functions.
        let mut fn_data: Vec<(String, u64, u64)> = Vec::new();
        while let Some(m) = matches.next() {
            let name_cap = m
                .captures
                .iter()
                .find(|c| cap_names[c.index as usize] == "fn.name");
            let body_cap = m
                .captures
                .iter()
                .find(|c| cap_names[c.index as usize] == "fn.body");

            if let (Some(name_c), Some(body_c)) = (name_cap, body_cap) {
                if let Ok(name) = name_c.node.utf8_text(source) {
                    let blake3 = crate::compute_structural_hash(body_c.node, source);
                    let simhash = crate::hashing::compute_simhash(body_c.node, source);
                    fn_data.push((name.to_string(), blake3, simhash));
                }
            }
        }

        // Domain routing: classify this file's context so memory-safety rules are
        // not applied to vendored or test code.  Supply-chain rules (DOMAIN_ALL)
        // fire regardless of domain.
        // `file_path` was extracted at the top of `bounce()` and is already in scope.
        let file_domain = crate::metadata::DomainRouter::classify(&file_path);

        // Test domain immunity: NCD anomalies and AnomalousBlob findings are
        // expected in test code — mock data, generated test vectors, and binary
        // fixtures are legitimate.  Shadow `ncd_findings` to empty for DOMAIN_TEST
        // so these do not inflate the ledger with spurious $150 Critical Threats.
        // LotL and Unicode checks (in `payload_findings` / `unicode_gate`) remain
        // active — those are true supply-chain attacks regardless of domain.
        let ncd_findings = if file_domain == crate::metadata::DOMAIN_TEST {
            vec![]
        } else {
            ncd_findings
        };

        // Language-specific antipattern detection via slop_hunter.
        // Apply the domain bitmask matrix, then the severity-based test-domain filter.
        let raw_findings = crate::slop_hunter::find_slop(ext, source);
        let mut suppressed_by_domain: u32 = 0;
        let mut antipattern_score: u32 = 0;
        let mut accepted: Vec<crate::slop_hunter::SlopFinding> =
            Vec::with_capacity(raw_findings.len());
        for f in raw_findings {
            let passes_domain = (f.domain & file_domain) != 0;
            // Test domain exemption (Phase 3): on test-path files, Warning and Lint
            // findings are suppressed — test code is allowed to be structurally
            // vacuous or cloned.  Only Critical findings fire unconditionally.
            let passes_severity = file_domain != crate::metadata::DOMAIN_TEST
                || f.severity == crate::slop_hunter::Severity::Critical;
            if passes_domain && passes_severity {
                antipattern_score += f.severity.points();
                accepted.push(f);
            } else {
                suppressed_by_domain += 1;
            }
        }
        let antipatterns_found = accepted.len() as u32;
        let antipattern_details: Vec<String> = accepted
            .into_iter()
            .map(|f| {
                let line = byte_offset_to_line(source, f.start_byte);
                format!("{} (line={line})", f.description)
            })
            .collect();

        // Dead symbols added — name already exists in registry.
        let registry_names: HashSet<&str> =
            registry.entries.iter().map(|e| e.name.as_str()).collect();
        let dead_symbols_added = fn_data
            .iter()
            .filter(|(name, _, _)| registry_names.contains(name.as_str()))
            .count() as u32;

        // Exact logic clones — BLAKE3 hash collisions within added code.
        // For a group of N functions sharing the same hash, contribute N − 1.
        let mut hash_counts: HashMap<u64, u32> = HashMap::new();
        for (_, blake3, _) in &fn_data {
            *hash_counts.entry(*blake3).or_insert(0) += 1;
        }
        let patch_internal_clones: u32 = hash_counts
            .values()
            .filter(|&&c| c > 1)
            .map(|&c| c - 1)
            .sum();

        // Fuzzy near-clone detection via SimHash.
        //
        // For function pairs where BLAKE3 does NOT match (not already counted as an
        // exact clone), compute the SimHash Hamming similarity. Pairs in the Zombie
        // band (0.85 < similarity ≤ 0.95) are penalised as near-clone logic duplications.
        // Pairs in the Refactor band (> 0.95) are ignored — they are trivially similar.
        let n = fn_data.len();
        let mut fuzzy_near_clones: u32 = 0;
        for i in 0..n {
            for j in (i + 1)..n {
                let (_, b1, s1) = fn_data[i];
                let (_, b2, s2) = fn_data[j];
                if b1 == b2 {
                    // Already counted as an exact clone — skip.
                    continue;
                }
                if matches!(
                    crate::hashing::classify_similarity(crate::hashing::compute_similarity(s1, s2)),
                    crate::hashing::Similarity::Zombie
                ) {
                    fuzzy_near_clones += 1;
                }
            }
        }

        // Derive a (name, blake3_hash) view for the registry lookups below.
        let fn_hashes: Vec<(String, u64)> =
            fn_data.iter().map(|(n, b, _)| (n.clone(), *b)).collect();

        // Global registry hash checks: Zombie Reintroduction and Global Logic Clone.
        //
        // Build a map: structural_hash → is_dead (protected_by is None).
        // Skip entries with hash == 0 (classes / assignments carry no structural hash).
        let mut registry_hash_index: HashMap<u64, bool> = HashMap::new();
        for entry in &registry.entries {
            if entry.structural_hash != 0 {
                let is_dead = entry.protected_by.is_none();
                registry_hash_index
                    .entry(entry.structural_hash)
                    .and_modify(|dead| {
                        // If any entry sharing this hash is dead, treat the hash as dead.
                        if is_dead {
                            *dead = true;
                        }
                    })
                    .or_insert(is_dead);
            }
        }

        let mut zombie_symbols_added: u32 = 0;
        let mut global_clone_count: u32 = 0;
        for (_, hash) in &fn_hashes {
            match registry_hash_index.get(hash) {
                // Hash matches a dead (unprotected) symbol — Zombie Reintroduction.
                Some(true) => zombie_symbols_added += 1,
                // Hash matches a live (protected) symbol — Global Logic Clone.
                Some(false) => global_clone_count += 1,
                None => {}
            }
        }

        // ── Necrotic Pruning Matrix ──────────────────────────────────────────────
        // Invokes the three Backlog Pruner garbage-collection checks.  Results are
        // attached as a non-scoring `necrotic_flag` for downstream reporting.
        //
        // Check priority (first match wins): GHOST_COLLISION > UNWIRED_ISLAND > SEMANTIC_NULL
        let necrotic_flag: Option<String> = 'necrotic: {
            // Extract removed source from `-` diff lines (excluding `---` header).
            let removed: String = patch
                .lines()
                .filter(|l| l.starts_with('-') && !l.starts_with("---"))
                .map(|l| &l[1..])
                .collect::<Vec<_>>()
                .join("\n");
            let removed_bytes = removed.as_bytes();

            // Parse removed source with the same grammar.
            let base_tree: Option<tree_sitter::Tree> =
                if !removed.trim().is_empty() && removed_bytes.len() <= 1_048_576 {
                    let mut bp = tree_sitter::Parser::new();
                    if bp.set_language(&cfg.language).is_ok() {
                        bp.parse(removed_bytes, None)
                    } else {
                        None
                    }
                } else {
                    None
                };

            // Collect function names extracted from removed source.
            let removed_fn_names: HashSet<String> = {
                let mut names = HashSet::new();
                if let Some(ref bt) = base_tree {
                    if !bt.root_node().has_error() {
                        if let Ok(q) = Query::new(&cfg.language, cfg.query_src) {
                            let mut rc = tree_sitter::QueryCursor::new();
                            let mut rm = rc.matches(&q, bt.root_node(), removed_bytes);
                            let cnames = q.capture_names();
                            while let Some(m) = rm.next() {
                                if let Some(nc) = m
                                    .captures
                                    .iter()
                                    .find(|c| cnames[c.index as usize] == "fn.name")
                                {
                                    if let Ok(name) = nc.node.utf8_text(removed_bytes) {
                                        names.insert(name.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
                names
            };

            // ── 1. GHOST_COLLISION ─────────────────────────────────────────────
            // Fires when >50% of modified functions (present in both removed and
            // added lines) are absent from the master registry — the PR is targeting
            // architecture that has decayed on master.
            if !fn_data.is_empty() && !registry.entries.is_empty() {
                let modified_fns: Vec<String> = fn_data
                    .iter()
                    .filter(|(n, _, _)| removed_fn_names.contains(n.as_str()))
                    .map(|(n, _, _)| n.clone())
                    .collect();
                if !modified_fns.is_empty() {
                    use backlog_pruner::ghost_collision::{
                        is_ghost_collision, MasterEntry, MasterIndex,
                    };
                    // Use zero hashes on both sides — only the name-presence
                    // check contributes to decay ratio (divergence is suppressed).
                    let null_hash = [0u8; 32];
                    let pr_hashes = vec![null_hash; modified_fns.len()];
                    let master = MasterIndex::new(
                        registry
                            .entries
                            .iter()
                            .map(|e| MasterEntry {
                                qualified_name: e.name.clone(),
                                structural_hash: null_hash,
                            })
                            .collect(),
                    );
                    if is_ghost_collision(&modified_fns, &pr_hashes, &master) {
                        break 'necrotic Some("GHOST_COLLISION".to_string());
                    }
                }
            }

            // ── 2. UNWIRED_ISLAND ──────────────────────────────────────────────
            // Fires when the patch introduces truly new functions (not in removed
            // lines, not known to the registry) with no lifecycle-hook exemption.
            // An empty MasterCallGraph means all non-lifecycle new functions have
            // in_degree == 0 — they have no callers in the tracked codebase.
            if !fn_data.is_empty() && !registry.entries.is_empty() {
                use backlog_pruner::unwired_island::{is_unwired_island, MasterCallGraph};
                let known_names: HashSet<&str> =
                    registry.entries.iter().map(|e| e.name.as_str()).collect();
                let island_candidates: Vec<String> = fn_data
                    .iter()
                    .filter(|(n, _, _)| {
                        !removed_fn_names.contains(n.as_str()) && !known_names.contains(n.as_str())
                    })
                    .map(|(n, _, _)| n.clone())
                    .collect();
                if !island_candidates.is_empty() {
                    let empty_graph = MasterCallGraph::new(&[]);
                    if is_unwired_island(&island_candidates, &empty_graph) {
                        break 'necrotic Some("UNWIRED_ISLAND".to_string());
                    }
                }
            }

            // ── 3. SEMANTIC_NULL ───────────────────────────────────────────────
            // Fires when the removed source and added source share identical
            // structural skeletons — the PR changes only cosmetic tokens.
            if let Some(ref bt) = base_tree {
                if !bt.root_node().has_error() && !tree.root_node().has_error() {
                    use backlog_pruner::semantic_null::is_semantic_null;
                    if is_semantic_null(bt.root_node(), tree.root_node()) {
                        break 'necrotic Some("SEMANTIC_NULL".to_string());
                    }
                }
            }

            None
        };

        // Net-Negative Exemption — waive the structural clone penalty for cleanup PRs.
        //
        // Mass-deletion of identical boilerplate (e.g. removing duplicate initialisers,
        // clearing auto-generated constants) hashes to the same structural skeleton and
        // spuriously inflates `logic_clones_found`.  If the PR removes more than twice
        // as many lines as it adds, it is overwhelmingly a cleanup: waive the clone
        // penalty so human maintainers are not penalised for good hygiene work.
        let lines_added = patch
            .lines()
            .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
            .count() as u64;
        let lines_deleted = patch
            .lines()
            .filter(|l| l.starts_with('-') && !l.starts_with("---"))
            .count() as u64;
        let raw_clone_count = patch_internal_clones + fuzzy_near_clones + global_clone_count;
        let logic_clones_found = if lines_deleted > lines_added.saturating_mul(2) {
            0
        } else {
            raw_clone_count
        };

        // Recursive Boilerplate — topology-hash flood detection.
        //
        // Fires Critical (+50 pts) when >5 added functions share identical AST
        // topology in the same source blob.  This is the canonical AI context-bloat
        // signature: a context-exhausted agent scaffolds the same function body N
        // times with distinct names but identical structure.
        let boilerplate_finding = crate::slop_hunter::detect_recursive_boilerplate(ext, source);
        let boilerplate_count = boilerplate_finding.is_some() as u32;
        let boilerplate_details: Vec<String> = boilerplate_finding
            .map(|f| f.description)
            .into_iter()
            .collect();

        // Merge NCD entropy gate, Compiled Payload Shield, and Recursive Boilerplate
        // findings into the antipattern totals.
        //
        // Severity split (v7.9.0 Threat Demotion):
        //   NCD (antipattern:ncd_anomaly)  → Warning tier: 10 pts.
        //     Generative verbosity is an antipattern, not a supply-chain attack.
        //     It MUST NOT trigger the $150 Critical Threat billing ledger in
        //     report.rs::is_critical_threat (which gates on "security:" prefix).
        //   Payload (binary_hunter)         → Critical tier: 50 pts.
        //     ELF magic, mining stratum URIs, shell NULs are active supply-chain
        //     signals — Critical billing is correct and intentional.
        //   Recursive Boilerplate           → Critical tier: 50 pts.
        //     Structural topology flood is a direct AI-generation artefact;
        //     Critical billing is correct and intentional.
        let ncd_count = ncd_findings.len() as u32;
        let payload_count = payload_findings.len() as u32;
        let antipatterns_found = antipatterns_found + ncd_count + payload_count + boilerplate_count;
        let antipattern_score =
            antipattern_score + ncd_count * 10 + payload_count * 50 + boilerplate_count * 50;
        let mut antipattern_details = antipattern_details;
        antipattern_details.extend(ncd_findings);
        antipattern_details.extend(payload_findings);
        antipattern_details.extend(boilerplate_details);

        Ok(SlopScore {
            dead_symbols_added,
            logic_clones_found,
            zombie_symbols_added,
            antipatterns_found,
            antipattern_score,
            antipattern_details,
            suppressed_by_domain,
            necrotic_flag,
            ..SlopScore::default()
        })
    }
}

// ---------------------------------------------------------------------------
// GitBouncer — shadow_git-backed PR analysis
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Hallucinated-security-fix integration helpers
// ---------------------------------------------------------------------------

/// Extract all unique file extensions from every `+++ b/<path>` header in a
/// unified diff.
///
/// Unlike the private [`extract_patch_ext`] which returns only the first
/// extension, this function collects one entry per changed file.  Extensionless
/// files (e.g. `LICENSE`, `OWNERS`) produce an empty-string entry `""`.
///
/// The returned `Vec` is deduplicated but unordered.
pub fn extract_all_patch_exts(patch: &str) -> Vec<String> {
    let mut seen: HashSet<String> = HashSet::new();
    for line in patch.lines() {
        if let Some(path) = line
            .strip_prefix("+++ b/")
            .or_else(|| line.strip_prefix("+++ "))
        {
            let path = path.trim();
            // Skip /dev/null (deleted-file sentinel).
            if path == "/dev/null" {
                continue;
            }
            // Take the last path component then its extension.
            let filename = path.rsplit('/').next().unwrap_or(path);
            let ext = filename
                .rfind('.')
                .map(|i| filename[i + 1..].to_string())
                .unwrap_or_default(); // "" for files without extension
            seen.insert(ext);
        }
    }
    seen.into_iter().collect()
}

/// Apply the hallucinated-security-fix check to an existing [`SlopScore`].
///
/// Called by `cmd_bounce` after the main slop analysis, with the PR body and
/// the list of unique changed file extensions (from the patch headers or the
/// [`MergeSnapshot`](crate::shadow_git::MergeSnapshot) blob map).
///
/// When a hallucinated fix is detected:
/// - `score.hallucinated_security_fix` is set to `1` (+100 pts).
/// - The human-readable description is appended to `score.antipattern_details`
///   so it surfaces in the bounce output alongside other antipatterns.
///
/// This function is a no-op when `pr_body` is empty or no security keyword is
/// found, so it is always safe to call unconditionally.
pub fn check_hallucinated_fix(
    score: &mut SlopScore,
    pr_body: &str,
    changed_exts: &[String],
    repo_slug: &str,
) {
    if let Some(finding) =
        crate::metadata::detect_hallucinated_fix(pr_body, changed_exts, repo_slug)
    {
        score.hallucinated_security_fix = 1;
        score.antipattern_details.push(finding.description);
    }
}

/// Extract per-file added content from a unified diff.
///
/// Parses `+`-prefixed lines (excluding `+++` headers) per `+++ b/<path>` section
/// and returns a `HashMap` mapping each changed file path to its added byte content.
///
/// Used by `cmd_bounce` (patch mode) to build the blob map for
/// [`anatomist::manifest::find_zombie_deps_in_blobs`] without any extra I/O.
pub fn extract_patch_blobs(patch: &str) -> HashMap<std::path::PathBuf, Vec<u8>> {
    let mut blobs: HashMap<std::path::PathBuf, Vec<u8>> = HashMap::new();
    let mut current_path: Option<std::path::PathBuf> = None;
    let mut current_content: Vec<u8> = Vec::new();

    for line in patch.lines() {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            // Flush the previous file's accumulated content.
            if let Some(path) = current_path.take() {
                if !current_content.is_empty() {
                    blobs.insert(path, std::mem::take(&mut current_content));
                }
            }
            let path_str = rest.trim();
            if path_str != "/dev/null" {
                current_path = Some(std::path::PathBuf::from(path_str));
            }
            current_content = Vec::new();
        } else if line.starts_with('+') && !line.starts_with("+++") && current_path.is_some() {
            // Strip the leading '+' and preserve the original line.
            current_content.extend_from_slice(&line.as_bytes()[1..]);
            current_content.push(b'\n');
        }
    }
    // Flush the last file.
    if let Some(path) = current_path {
        if !current_content.is_empty() {
            blobs.insert(path, current_content);
        }
    }

    blobs
}

// ---------------------------------------------------------------------------
// Full-blob Semantic Null pre-check
// ---------------------------------------------------------------------------

/// Map a file extension to a tree-sitter [`Language`] for full-blob semantic null
/// analysis.  Returns `None` for unsupported extensions — those files are skipped
/// by [`semantic_null_pr_check`] (neither classified as null nor as structural).
fn lang_for_ext_semantic(ext: &str) -> Option<tree_sitter::Language> {
    match ext {
        "py" => Some(tree_sitter_python::LANGUAGE.into()),
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        "cpp" | "cxx" | "cc" | "h" | "hpp" | "c" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "cs" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "js" | "jsx" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "rb" => Some(tree_sitter_ruby::LANGUAGE.into()),
        "php" => Some(tree_sitter_php::LANGUAGE_PHP.into()),
        "swift" => Some(tree_sitter_swift::LANGUAGE.into()),
        "lua" => Some(tree_sitter_lua::LANGUAGE.into()),
        "scala" => Some(tree_sitter_scala::LANGUAGE.into()),
        "sh" | "bash" => Some(tree_sitter_bash::LANGUAGE.into()),
        "m" | "mm" => Some(tree_sitter_objc::LANGUAGE.into()),
        _ => None,
    }
}

/// Returns `true` if **all** modified source files in the PR have structurally
/// identical AST skeletons between their base-commit blob and head-commit blob.
///
/// Uses `git2` to compute `diff_tree_to_tree` between `merge_base_sha` and
/// `pr_sha`, then for each modified file with a supported extension loads both
/// blobs from the ODB and calls
/// [`backlog_pruner::semantic_null::is_semantic_null_blobs`].
///
/// Returns `false` (not semantic null) if:
/// - The repository cannot be opened.
/// - No supported source files are modified.
/// - Any modified source file differs structurally.
/// - Any blob exceeds the 256 KiB circuit breaker.
/// - Any parse produces error nodes.
pub fn semantic_null_pr_check(repo_path: &Path, merge_base_sha: &str, pr_sha: &str) -> bool {
    use backlog_pruner::semantic_null::is_semantic_null_blobs;

    const BLOB_LIMIT: usize = 256 * 1024;

    let repo = match git2::Repository::open(repo_path) {
        Ok(r) => r,
        Err(_) => return false,
    };

    let base_oid = match git2::Oid::from_str(merge_base_sha) {
        Ok(o) => o,
        Err(_) => return false,
    };
    let head_oid = match git2::Oid::from_str(pr_sha) {
        Ok(o) => o,
        Err(_) => return false,
    };

    let base_commit = match repo.find_commit(base_oid) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let head_commit = match repo.find_commit(head_oid) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let base_tree = match base_commit.tree() {
        Ok(t) => t,
        Err(_) => return false,
    };
    let head_tree = match head_commit.tree() {
        Ok(t) => t,
        Err(_) => return false,
    };

    let diff = match repo.diff_tree_to_tree(Some(&base_tree), Some(&head_tree), None) {
        Ok(d) => d,
        Err(_) => return false,
    };

    // Collect all deltas for modified source files.
    let mut checked_any = false;
    for delta in diff.deltas() {
        use git2::Delta;
        // Only examine modifications — additions/deletions are not semantic-null candidates.
        if delta.status() != Delta::Modified {
            continue;
        }
        let path = match delta.new_file().path() {
            Some(p) => p,
            None => continue,
        };
        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
        let lang = match lang_for_ext_semantic(ext) {
            Some(l) => l,
            None => continue, // unsupported extension — skip
        };

        let old_oid = delta.old_file().id();
        let new_oid = delta.new_file().id();

        let old_blob = match repo.find_blob(old_oid) {
            Ok(b) => b,
            Err(_) => return false,
        };
        let new_blob = match repo.find_blob(new_oid) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let old_bytes = old_blob.content();
        let new_bytes = new_blob.content();

        // 256 KiB circuit breaker — over-large blobs are not safe to assume null.
        if old_bytes.len() > BLOB_LIMIT || new_bytes.len() > BLOB_LIMIT {
            return false;
        }

        if !is_semantic_null_blobs(old_bytes, new_bytes, &lang) {
            return false;
        }
        checked_any = true;
    }

    // If no supported source files were modified, do not classify as semantic null.
    checked_any
}

/// Analyse a pull request's changes against `registry` by loading changed blobs
/// directly from the git pack index via [`shadow_git::simulate_merge`].
///
/// Unlike [`PatchBouncer`] which requires a pre-extracted unified diff, `bounce_git`
/// accepts repository coordinates and loads each changed file as an in-memory
/// blob, then synthesises a virtual patch per file and runs the full slop pipeline
/// over it.
///
/// # Arguments
/// - `repo_path`: Filesystem path to the git repository root.
/// - `base_sha`: 40-hex OID of the base (target-branch head) commit.
/// - `head_sha`: 40-hex OID of the head (feature-branch head) commit.
/// - `registry`: Symbol registry for dead-symbol and zombie checks.
///
/// # Returns
/// A tuple of `(SlopScore, blobs)` where `blobs` is the `HashMap<PathBuf, Vec<u8>>`
/// of changed files loaded from the git pack index.  The caller uses `blobs` to run
/// [`anatomist::manifest::find_zombie_deps_in_blobs`] without re-opening the pack.
///
/// # Errors
/// Returns `Err` if the repository cannot be opened, the OIDs are invalid, or
/// libgit2 cannot read a blob from the pack.
pub fn bounce_git(
    repo_path: &Path,
    base_sha: &str,
    head_sha: &str,
    registry: &SymbolRegistry,
) -> Result<(SlopScore, HashMap<std::path::PathBuf, Vec<u8>>)> {
    let repo = git2::Repository::open(repo_path).map_err(|e| {
        anyhow::anyhow!("bounce_git: cannot open repo {}: {e}", repo_path.display())
    })?;

    let base_oid = git2::Oid::from_str(base_sha)
        .map_err(|e| anyhow::anyhow!("bounce_git: invalid base SHA '{base_sha}': {e}"))?;
    let head_oid = git2::Oid::from_str(head_sha)
        .map_err(|e| anyhow::anyhow!("bounce_git: invalid head SHA '{head_sha}': {e}"))?;

    let snapshot = crate::shadow_git::simulate_merge(&repo, base_oid, head_oid)
        .map_err(|e| anyhow::anyhow!("bounce_git: merge simulation failed: {e}"))?;

    let mut total = SlopScore::default();

    // Files > 1 MB are almost exclusively auto-generated bindings, compiled assets,
    // or massive monolithic stubs.  Tree-sitter AST allocation on multi-megabyte
    // inputs can exhaust the 8 GB heap on large corpora; real "slop" is never in
    // these files.  Skip them entirely.
    const MAX_BLOB_BYTES: usize = 1_048_576; // 1 MiB

    // Chemotaxis: process high-calorie slop vectors (.rs, .py, .js, .ts, .go)
    // before low-calorie files (.md, .txt) so structural violations surface early.
    for (path, blob_bytes) in snapshot.iter_by_priority() {
        if blob_bytes.len() > MAX_BLOB_BYTES {
            continue; // Circuit breaker — skip oversized blobs.
        }

        // Hard binary-asset bypass: check the full path string so multi-dot
        // extensions (e.g. `.woff2`) and paths without OS-reported extensions
        // are caught reliably, regardless of how path.extension() resolves them.
        {
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.ends_with(".wasm")
                || path_str.ends_with(".woff")
                || path_str.ends_with(".woff2")
                || path_str.ends_with(".eot")
                || path_str.ends_with(".ttf")
                || path_str.ends_with(".png")
                || path_str.ends_with(".jpg")
                || path_str.ends_with(".jpeg")
                || path_str.ends_with(".gif")
                || path_str.ends_with(".ico")
                || path_str.ends_with(".zip")
                || path_str.ends_with(".gz")
                || path_str.ends_with(".tar")
                || path_str.ends_with(".pdf")
            {
                continue;
            }
        }

        // ── Payload Bifurcation ───────────────────────────────────────────────
        //
        // `blob_bytes` is the full HEAD blob — the entire file as it exists at
        // the PR's head commit.  Passing the full blob to PatchBouncer was the
        // root cause of false positives on small PRs in large files: NCD entropy
        // and clone detection evaluated the entire file history, not the diff.
        //
        // `snapshot.patches` holds the actual unified diff per file — only the
        // lines git reports as added, removed, or context in this PR.  This is
        // the ONLY payload that PatchBouncer, SlopHunter, and AstSimHasher may
        // receive.  The full blob (`blob_bytes`) is returned to the caller for
        // use by IncludeGraphBuilder and SemanticNull.
        let patch = match snapshot.patches.get(path) {
            Some(p) if !p.trim().is_empty() => p.as_str(),
            _ => continue, // no diff lines for this file — skip
        };

        if let Ok(mut score) = PatchBouncer.bounce(patch, registry) {
            total.dead_symbols_added += score.dead_symbols_added;
            total.logic_clones_found += score.logic_clones_found;
            total.zombie_symbols_added += score.zombie_symbols_added;
            total.antipatterns_found += score.antipatterns_found;
            total.antipattern_score += score.antipattern_score;
            total.suppressed_by_domain += score.suppressed_by_domain;
            total
                .antipattern_details
                .append(&mut score.antipattern_details);
        }
    }

    Ok((total, snapshot.blobs))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use common::registry::{SymbolEntry, SymbolRegistry};

    fn empty_registry() -> SymbolRegistry {
        SymbolRegistry::new()
    }

    fn registry_with(names: &[&str]) -> SymbolRegistry {
        let mut r = SymbolRegistry::new();
        for (i, &name) in names.iter().enumerate() {
            r.entries.push(SymbolEntry {
                id: i as u64,
                name: name.to_string(),
                qualified_name: name.to_string(),
                file_path: "test.py".to_string(),
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                end_line: 3,
                entity_type: 0,
                structural_hash: 0,
                protected_by: None,
            });
        }
        r
    }

    fn make_patch(filename: &str, added_lines: &str) -> String {
        let mut patch = format!("--- a/{filename}\n+++ b/{filename}\n@@ -0,0 +1 @@\n");
        for line in added_lines.lines() {
            patch.push('+');
            patch.push_str(line);
            patch.push('\n');
        }
        patch
    }

    #[test]
    fn test_empty_patch_is_clean() {
        let bouncer = PatchBouncer;
        let score = bouncer.bounce("", &empty_registry()).unwrap();
        assert!(score.is_clean());
        assert_eq!(score.score(), 0);
    }

    #[test]
    fn test_unknown_language_is_clean() {
        let patch = make_patch("foo.unknown", "some code here\n");
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert!(score.is_clean(), "unknown ext must produce zero score");
    }

    #[test]
    fn test_new_python_symbol_clean_registry() {
        let patch = make_patch("utils.py", "def brand_new():\n    return 42\n");
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(score.dead_symbols_added, 0);
        assert_eq!(score.logic_clones_found, 0);
    }

    #[test]
    fn test_dead_symbol_detected_python() {
        let patch = make_patch("utils.py", "def old_helper():\n    return 1\n");
        let registry = registry_with(&["old_helper"]);
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &registry).unwrap();
        assert_eq!(score.dead_symbols_added, 1);
        // dead_symbols_added no longer contributes to score (Necrotic Pruning Matrix handles dead-code).
        assert_eq!(score.score(), 0);
    }

    #[test]
    fn test_logic_clone_python() {
        let patch = make_patch(
            "utils.py",
            "def add(a, b):\n    return a + b\ndef plus(x, y):\n    return x + y\n",
        );
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(score.logic_clones_found, 1);
        assert_eq!(score.score(), 5);
    }

    #[test]
    fn test_logic_clone_cpp() {
        // Two C++ functions with identical logic but different names.
        let patch = make_patch(
            "math.cpp",
            "int add(int a, int b) { return a + b; }\nint sum(int x, int y) { return x + y; }\n",
        );
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(
            score.logic_clones_found, 1,
            "C++ logic clones must be detectable"
        );
    }

    #[test]
    fn test_logic_clone_csharp() {
        // Two C# methods with identical logic — SlopFilter must detect them.
        let patch = make_patch(
            "Service.cs",
            "class A { int Add(int a, int b) { return a + b; } int Sum(int x, int y) { return x + y; } }",
        );
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(
            score.logic_clones_found, 1,
            "C# logic clones must be detectable"
        );
    }

    // C++ raw new/delete rule was removed in v7.1.11.
    // These integration tests verify the end-to-end pipeline produces zero
    // antipattern findings for C++ new expressions (regression guard).

    #[test]
    fn test_vendored_cpp_raw_new_not_flagged() {
        let src = "void* p = new MyClass();\n";
        let patch = make_patch("vendor/somelib/src/alloc.cpp", src);
        let score = PatchBouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(
            score.antipatterns_found, 0,
            "C++ raw new must not fire (rule removed v7.1.11)"
        );
        assert_eq!(score.suppressed_by_domain, 0);
    }

    #[test]
    fn test_first_party_cpp_raw_new_not_flagged() {
        let src = "void* p = new MyClass();\n";
        let patch = make_patch("src/engine/alloc.cpp", src);
        let score = PatchBouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(
            score.antipatterns_found, 0,
            "C++ raw new must not fire in first-party code either (rule removed v7.1.11)"
        );
        assert_eq!(score.suppressed_by_domain, 0);
    }

    #[test]
    fn test_score_formula() {
        let s = SlopScore {
            dead_symbols_added: 2,
            logic_clones_found: 3,
            ..SlopScore::default()
        };
        // dead_symbols_added no longer contributes to score.
        assert_eq!(s.score(), 3 * 5); // 15

        // Zombie weight is ×10 (Warning tier).
        let z = SlopScore {
            zombie_symbols_added: 2,
            ..SlopScore::default()
        };
        assert_eq!(z.score(), 2 * 10); // 20
        assert!(!z.is_clean());

        // Antipattern score drives the formula, not antipatterns_found × 50.
        // One Critical finding = 50 pts.
        let a = SlopScore {
            antipatterns_found: 1,
            antipattern_score: 50,
            ..SlopScore::default()
        };
        assert_eq!(a.score(), 50);
        assert!(!a.is_clean());

        // One Warning finding = 10 pts.
        let w = SlopScore {
            antipatterns_found: 1,
            antipattern_score: 10,
            ..SlopScore::default()
        };
        assert_eq!(w.score(), 10);
        assert!(!w.is_clean());

        // Lint findings = 0 pts, but still count for is_clean.
        let l = SlopScore {
            antipatterns_found: 1,
            antipattern_score: 0,
            ..SlopScore::default()
        };
        assert_eq!(l.score(), 0);
        assert!(!l.is_clean()); // antipatterns_found != 0

        // Comment violation weight is ×5.
        let c = SlopScore {
            comment_violations: 2,
            ..SlopScore::default()
        };
        assert_eq!(c.score(), 2 * 5); // 10
        assert!(!c.is_clean());

        // Unlinked PR weight is ×20.
        let u = SlopScore {
            unlinked_pr: 1,
            ..SlopScore::default()
        };
        assert_eq!(u.score(), 20);
        assert!(!u.is_clean());
    }

    #[test]
    fn test_zombie_reintroduction_detected() {
        // Compute the structural hash of the function body we are about to patch in.
        let fn_src = "def zombie_fn():\n    return 42\n";
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(fn_src.as_bytes(), None).unwrap();
        let query = Query::new(
            &lang,
            "(function_definition name: (identifier) @fn.name body: (block) @fn.body)",
        )
        .unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), fn_src.as_bytes());
        let cap_names = query.capture_names();
        let mut body_hash = 0u64;
        while let Some(m) = matches.next() {
            if let Some(body_cap) = m
                .captures
                .iter()
                .find(|c| cap_names[c.index as usize] == "fn.body")
            {
                body_hash = crate::compute_structural_hash(body_cap.node, fn_src.as_bytes());
                break;
            }
        }
        assert_ne!(
            body_hash, 0,
            "hash must be non-zero for this test to be meaningful"
        );

        // Registry entry: same hash, no protection → DEAD symbol.
        let mut registry = SymbolRegistry::new();
        registry.entries.push(SymbolEntry {
            id: 1,
            name: "deleted_helper".to_string(),
            qualified_name: "deleted_helper".to_string(),
            file_path: "old.py".to_string(),
            start_byte: 0,
            end_byte: 50,
            start_line: 1,
            end_line: 3,
            entity_type: 0,
            structural_hash: body_hash,
            protected_by: None, // DEAD
        });

        let patch = make_patch("utils.py", fn_src);
        let score = PatchBouncer.bounce(&patch, &registry).unwrap();
        assert_eq!(
            score.zombie_symbols_added, 1,
            "zombie reintroduction must be detected"
        );
        assert_eq!(score.score(), 10, "zombie weight is ×10 (Warning tier)");
        assert!(!score.is_clean());
    }

    #[test]
    fn test_global_registry_clone_detected() {
        use common::Protection;

        // Same setup but registry entry is PROTECTED → Global Logic Clone, not zombie.
        let fn_src = "def live_clone():\n    return 99\n";
        let lang: tree_sitter::Language = tree_sitter_python::LANGUAGE.into();
        let mut parser = tree_sitter::Parser::new();
        parser.set_language(&lang).unwrap();
        let tree = parser.parse(fn_src.as_bytes(), None).unwrap();
        let query = Query::new(
            &lang,
            "(function_definition name: (identifier) @fn.name body: (block) @fn.body)",
        )
        .unwrap();
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), fn_src.as_bytes());
        let cap_names = query.capture_names();
        let mut body_hash = 0u64;
        while let Some(m) = matches.next() {
            if let Some(body_cap) = m
                .captures
                .iter()
                .find(|c| cap_names[c.index as usize] == "fn.body")
            {
                body_hash = crate::compute_structural_hash(body_cap.node, fn_src.as_bytes());
                break;
            }
        }
        assert_ne!(body_hash, 0);

        let mut registry = SymbolRegistry::new();
        registry.entries.push(SymbolEntry {
            id: 2,
            name: "live_helper".to_string(),
            qualified_name: "live_helper".to_string(),
            file_path: "existing.py".to_string(),
            start_byte: 0,
            end_byte: 50,
            start_line: 1,
            end_line: 3,
            entity_type: 0,
            structural_hash: body_hash,
            protected_by: Some(Protection::Referenced), // ALIVE
        });

        let patch = make_patch("utils.py", fn_src);
        let score = PatchBouncer.bounce(&patch, &registry).unwrap();
        assert_eq!(
            score.zombie_symbols_added, 0,
            "protected entry must NOT be a zombie"
        );
        assert_eq!(
            score.logic_clones_found, 1,
            "protected hash match counts as global logic clone"
        );
        assert_eq!(score.score(), 5);
    }

    // --- Hallucinated security fix ---

    #[test]
    fn test_hallucinated_fix_cve_readme_only() {
        // The canonical test case from the mission mandate.
        let pr_body = "Fixes CVE-2026-9999: critical buffer overflow in the auth module.";
        let changed_exts = vec!["md".to_string()];
        let mut score = SlopScore::default();
        check_hallucinated_fix(&mut score, pr_body, &changed_exts, "");
        assert_eq!(
            score.hallucinated_security_fix, 1,
            "CVE claim + only README.md changed → hallucinated security fix"
        );
        assert_eq!(
            score.score(),
            100,
            "hallucinated fix carries a 100-point penalty"
        );
        assert!(!score.is_clean());
        assert_eq!(score.antipattern_details.len(), 1);
        assert!(score.antipattern_details[0].contains("Unverified Security Bump"));
    }

    #[test]
    fn test_hallucinated_fix_not_triggered_with_code_file() {
        let pr_body = "Fixes CVE-2026-9999: buffer overflow in allocator.";
        let changed_exts = vec!["rs".to_string(), "md".to_string()];
        let mut score = SlopScore::default();
        check_hallucinated_fix(&mut score, pr_body, &changed_exts, "");
        assert_eq!(
            score.hallucinated_security_fix, 0,
            "Rust file present — legitimate fix, must not flag"
        );
        assert_eq!(score.score(), 0);
    }

    #[test]
    fn test_hallucinated_fix_no_security_keyword() {
        let pr_body = "Update README with installation instructions.";
        let changed_exts = vec!["md".to_string()];
        let mut score = SlopScore::default();
        check_hallucinated_fix(&mut score, pr_body, &changed_exts, "");
        assert_eq!(
            score.hallucinated_security_fix, 0,
            "no security keyword → no flag"
        );
    }

    #[test]
    fn test_hallucinated_fix_json_and_yaml_only() {
        // yaml/yml are treated as CODE (Dependabot Action version bumps are legitimate
        // security fixes).  A changeset that includes a yaml file must NOT be flagged
        // even when the PR body contains a security keyword.
        let pr_body = "Patches a memory leak in the connection pool configuration.";
        let changed_exts = vec!["json".to_string(), "yaml".to_string()];
        let mut score = SlopScore::default();
        check_hallucinated_fix(&mut score, pr_body, &changed_exts, "");
        assert_eq!(
            score.hallucinated_security_fix, 0,
            "yaml is treated as code — json+yaml must not be flagged as hallucinated"
        );
    }

    #[test]
    fn test_extract_all_patch_exts_multi_file() {
        let patch = concat!(
            "--- a/README.md\n+++ b/README.md\n@@ -1 +1 @@\n-old\n+new\n",
            "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1 +1 @@\n-old\n+new\n",
            "--- a/config.json\n+++ b/config.json\n@@ -1 +1 @@\n-old\n+new\n",
        );
        let mut exts = extract_all_patch_exts(patch);
        exts.sort();
        assert_eq!(exts, vec!["json", "md", "rs"]);
    }

    #[test]
    fn test_extract_all_patch_exts_extensionless() {
        let patch = "--- a/LICENSE\n+++ b/LICENSE\n@@ -1 +1 @@\n-old\n+new\n";
        let exts = extract_all_patch_exts(patch);
        assert_eq!(exts, vec![""], "LICENSE has no extension → empty string");
    }

    // ── Compiled Payload Shield integration tests ─────────────────────────────

    #[test]
    fn test_payload_shield_stratum_in_rust_patch() {
        // A Rust source file embedding a stratum mining pool URI should trigger
        // the Compiled Payload Shield at the PatchBouncer level.
        let src = "const POOL: &str = \"stratum+tcp://pool.example.com:3333\";\n";
        let patch = make_patch("config.rs", src);
        let score = PatchBouncer.bounce(&patch, &empty_registry()).unwrap();
        assert!(
            score.antipatterns_found >= 1,
            "stratum+tcp:// must trigger payload shield: {:?}",
            score.antipattern_details
        );
        assert!(
            score
                .antipattern_details
                .iter()
                .any(|d| d.contains("stratum")),
            "stratum finding must appear in antipattern_details"
        );
        assert!(
            score.antipattern_score >= 50,
            "stratum finding must contribute Critical-tier pts (50)"
        );
    }

    #[test]
    fn test_payload_shield_clean_source_not_flagged() {
        // Ordinary Rust source code must not trigger the payload shield.
        let src = "fn compute(a: i32, b: i32) -> i32 { a + b }\n";
        let patch = make_patch("math.rs", src);
        let score = PatchBouncer.bounce(&patch, &empty_registry()).unwrap();
        // NCD and payload shields must both be silent on trivial clean source.
        let payload_flags: Vec<&String> = score
            .antipattern_details
            .iter()
            .filter(|d| d.contains("compiled_payload"))
            .collect();
        assert!(
            payload_flags.is_empty(),
            "clean source must not trigger payload shield: {payload_flags:?}"
        );
    }

    #[test]
    fn test_hallucinated_fix_score_formula() {
        // Verify the new ×100 weight integrates correctly with other fields.
        let s = SlopScore {
            dead_symbols_added: 1,        // +0 (dead_symbols no longer scored)
            hallucinated_security_fix: 1, // +100
            ..SlopScore::default()
        };
        assert_eq!(s.score(), 100);
        assert!(!s.is_clean());
    }

    #[test]
    fn test_extract_patch_ext_b_prefix() {
        assert_eq!(extract_patch_ext("+++ b/src/main.cpp\n"), "cpp");
        assert_eq!(extract_patch_ext("+++ b/utils.py\n"), "py");
        assert_eq!(extract_patch_ext("+++ b/service.cs\n"), "cs");
        assert_eq!(extract_patch_ext("+++ b/shader.glsl\n"), "glsl");
    }

    #[test]
    fn test_rust_logic_clone() {
        let patch = make_patch(
            "lib.rs",
            "fn add(a: i32, b: i32) -> i32 { a + b }\nfn sum(x: i32, y: i32) -> i32 { x + y }\n",
        );
        let bouncer = PatchBouncer;
        let score = bouncer.bounce(&patch, &empty_registry()).unwrap();
        assert_eq!(
            score.logic_clones_found, 1,
            "Rust logic clones must be detectable"
        );
    }
}
