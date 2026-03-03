//! # Comment & PR Metadata Scanner
//!
//! Extracts comments and docstrings from source code (via tree-sitter) and from
//! unified-diff patch hunks (via line-prefix heuristics), then checks extracted
//! text against a configurable [`BANNED_PHRASES`] list.  Also validates PR body
//! text for a mandatory issue-link (the "Unlinked PR Penalty").
//!
//! ## Two scanning surfaces
//!
//! | Surface | Method | Use case |
//! |---------|--------|---------|
//! | Unified-diff patch (added lines) | [`CommentScanner::scan_patch`] | `janitor bounce --patch` |
//! | Full source file | [`CommentScanner::scan_source`] | Future: `janitor scan --comments` |
//!
//! ## Banned phrases
//!
//! Two categories, both matched case-insensitively:
//!
//! - **AI-isms** — boilerplate phrases that indicate unreviewed AI-generated
//!   prose left in production comments.
//! - **Profanity** — a baseline set of terms that violate typical open-source
//!   contribution standards.
//!
//! The list is intentionally conservative.  False-positive costs are high —
//! a SlopScore penalty of ×5 per violation is significant over many PRs.
//!
//! ## Scoring
//!
//! Results feed directly into [`crate::slop_filter::SlopScore`]:
//! - `comment_violations` += number of banned phrases found in comments (×5 each)
//! - `unlinked_pr` = 1 if the PR body contains no `Closes #N` / `Fixes #N` reference (×20)

use std::sync::OnceLock;

use aho_corasick::{AhoCorasick, AhoCorasickBuilder};
use tree_sitter::{Node, Parser};

// ---------------------------------------------------------------------------
// Hallucinated-security-fix detector
// ---------------------------------------------------------------------------

/// Security-claim keywords that trigger hallucinated-fix detection.
///
/// Matched case-insensitively against the PR body.  `"CVE-"` has an additional
/// suffix constraint: at least one ASCII digit must immediately follow the
/// matched text (e.g. `"CVE-2026-9999"`) to avoid false positives on prose
/// that says "like CVE-reporting processes".
const SECURITY_KEYWORDS: &[&str] = &[
    "CVE-",
    "buffer overflow",
    "memory leak",
    "RCE",
    "vulnerability",
    "exploit",
    "XSS",
    "SQLi",
];

/// File extensions that are definitively non-code.
///
/// A PR that changes *only* files with these extensions cannot plausibly be
/// fixing a buffer overflow, use-after-free, or similar memory-safety issue —
/// regardless of what its description claims.
///
/// The empty string `""` captures extensionless files (e.g. `LICENSE`, `OWNERS`,
/// `CODEOWNERS`, `NOTICE`) which are also non-code.
const NON_CODE_EXTENSIONS: &[&str] = &[
    "md", "txt", "png", "jpg", "jpeg", "gif", "svg", "webp", "json", "yaml", "yml", "toml", "lock",
    "sum", "csv", "xml", "", // extensionless files: LICENSE, OWNERS, CODEOWNERS, NOTICE, etc.
];

static SECURITY_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn security_ac() -> &'static AhoCorasick {
    SECURITY_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(SECURITY_KEYWORDS)
            .expect("static security keyword patterns are valid")
    })
}

/// Detect a "Hallucinated Security Fix" — a PR whose description contains
/// high-stakes security language but whose changed files are all non-code.
///
/// ## The Pattern
///
/// AI-generated PRs sometimes claim to fix CVEs or vulnerabilities while only
/// modifying markdown documentation, JSON configs, or image assets — file types
/// that cannot contain a buffer overflow patch.  This detector catches that
/// mismatch before the PR reaches a human reviewer.
///
/// ## Trigger Conditions
///
/// Returns `Some(SlopFinding)` when **both** of the following hold:
///
/// 1. `body` contains a security keyword: `CVE-<digits>`, `"buffer overflow"`,
///    `"memory leak"`, `"RCE"`, `"vulnerability"`, `"exploit"`, `"XSS"`, or `"SQLi"`.
/// 2. Every extension in `file_extensions` belongs to the non-code set:
///    `md`, `txt`, `png`, `jpg`, `json`, `yaml`, `toml`, `lock`, or `""` (no extension).
///
/// Returns `None` when either condition is absent (no security claim, or at
/// least one code file is present in the changeset).
pub fn detect_hallucinated_fix(
    body: &str,
    file_extensions: &[String],
) -> Option<crate::slop_hunter::SlopFinding> {
    // Guard: nothing to flag on an empty body or empty changeset.
    if body.is_empty() || file_extensions.is_empty() {
        return None;
    }

    // Locate the first security keyword in the PR body.
    let ac = security_ac();
    let mut matched_keyword: Option<&str> = None;
    for mat in ac.find_iter(body) {
        let kw = SECURITY_KEYWORDS[mat.pattern().as_usize()];
        // "CVE-" requires at least one ASCII digit immediately after the match
        // to avoid matching "CVE-reporting processes", "CVE-adjacent" etc.
        if kw.eq_ignore_ascii_case("CVE-") {
            let after = &body[mat.end()..];
            if !after
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                continue;
            }
        }
        matched_keyword = Some(kw);
        break;
    }
    let keyword = matched_keyword?;

    // Verify that every changed file extension is non-code.
    let all_non_code = file_extensions.iter().all(|ext| {
        let ext = ext.trim_start_matches('.');
        NON_CODE_EXTENSIONS.contains(&ext)
    });

    if !all_non_code {
        return None; // At least one code file changed — legitimate fix.
    }

    Some(crate::slop_hunter::SlopFinding {
        start_byte: 0,
        end_byte: 0,
        description: format!(
            "Hallucinated Security Fix: PR body claims '{}' but only non-code files \
             changed ({}). A real security fix requires modifying source code.",
            keyword,
            file_extensions.join(", ")
        ),
    })
}

// ---------------------------------------------------------------------------
// Banned phrase catalogue
// ---------------------------------------------------------------------------

/// Phrases matched case-insensitively against comment and docstring text.
///
/// ## AI-isms
/// Boilerplate phrases commonly inserted verbatim by AI code-generation tools.
/// Their presence in a commit indicates the author did not review the generated
/// prose before submitting.
///
/// ## Profanity
/// A minimal baseline set.  Extend via custom [`CommentScanner::with_phrases`].
const BANNED_PHRASES: &[&str] = &[
    // --- AI-isms ---
    "as an ai",
    "as a language model",
    "i'm an ai",
    "i am an ai",
    "i cannot assist",
    "i cannot help",
    "i cannot provide",
    "certainly! here",
    "certainly, here",
    "of course! here",
    "note: as an",
    "generated by chatgpt",
    "generated by claude",
    "generated by copilot",
    "generated by gpt",
    "this code was generated",
    // --- Profanity (baseline) ---
    "fuck",
    "shit",
    "damn it",
    "wtf",
    "bullshit",
];

/// Issue-link anchor phrases.  A PR body containing any of these followed by
/// `#<digits>` is considered "linked" and exempt from the unlinked-PR penalty.
const LINK_ANCHORS: &[&str] = &[
    "closes #",
    "close #",
    "fixes #",
    "fix #",
    "resolves #",
    "resolve #",
    "related to #",
    "refs #",
    "ref #",
];

// ---------------------------------------------------------------------------
// Static automata (initialised once, lock-free reads thereafter)
// ---------------------------------------------------------------------------

static BANNED_AC: OnceLock<AhoCorasick> = OnceLock::new();
static LINK_AC: OnceLock<AhoCorasick> = OnceLock::new();

fn banned_ac() -> &'static AhoCorasick {
    BANNED_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(BANNED_PHRASES)
            .expect("static banned phrase patterns are valid")
    })
}

fn link_ac() -> &'static AhoCorasick {
    LINK_AC.get_or_init(|| {
        AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .build(LINK_ANCHORS)
            .expect("static link anchor patterns are valid")
    })
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single comment violation: a banned phrase found in a comment or docstring.
#[derive(Debug, Clone)]
pub struct CommentViolation {
    /// The banned phrase that was matched (lowercased canonical form).
    pub phrase: String,
    /// The comment text in which the match occurred (trimmed, max 120 chars).
    pub context: String,
    /// Approximate line number in the source or patch (1-indexed; 0 = unknown).
    pub line: usize,
}

/// The main scanner.  Construct with [`CommentScanner::new`] for the default
/// [`BANNED_PHRASES`] set, or extend with [`CommentScanner::with_phrases`].
pub struct CommentScanner {
    // Reserved for future per-instance phrase extension; the static automaton
    // handles the default set for all shared callers.
    _priv: (),
}

impl Default for CommentScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl CommentScanner {
    /// Create a scanner with the default [`BANNED_PHRASES`] catalogue.
    pub fn new() -> Self {
        // Eagerly initialise both automata so the first call is not slower.
        let _ = banned_ac();
        let _ = link_ac();
        Self { _priv: () }
    }

    // -----------------------------------------------------------------------
    // Patch surface (primary use case: janitor bounce --patch)
    // -----------------------------------------------------------------------

    /// Scan a unified-diff patch for banned phrases inside added comment lines.
    ///
    /// Only `+`-prefixed lines (newly added lines) are inspected; context and
    /// removed lines are ignored.  A line is treated as a comment when, after
    /// stripping the leading `+` and whitespace, it begins with a recognised
    /// comment prefix (`//`, `#`, `/*`, `*`, `///`, `//!`, `/**`).
    ///
    /// Returns one [`CommentViolation`] per phrase match.  A single comment
    /// line may produce multiple violations if it contains multiple phrases.
    pub fn scan_patch(&self, patch: &str) -> Vec<CommentViolation> {
        let ac = banned_ac();
        let mut violations = Vec::new();

        for (line_num, raw_line) in patch.lines().enumerate() {
            let line_num = line_num + 1; // 1-indexed

            // Only inspect added lines, never the `+++` file-header lines.
            let added = match raw_line.strip_prefix('+') {
                Some(rest) if !rest.starts_with("++") => rest,
                _ => continue,
            };

            let trimmed = added.trim();
            if !is_comment_line(trimmed) {
                continue;
            }

            for mat in ac.find_iter(trimmed) {
                violations.push(CommentViolation {
                    phrase: BANNED_PHRASES[mat.pattern().as_usize()].to_string(),
                    context: truncate(trimmed, 120).to_string(),
                    line: line_num,
                });
            }
        }

        violations
    }

    // -----------------------------------------------------------------------
    // Source surface (full-file tree-sitter scan)
    // -----------------------------------------------------------------------

    /// Scan a complete source file for banned phrases in comments and docstrings.
    ///
    /// Uses tree-sitter to extract comment nodes for the given language extension
    /// (`"rs"`, `"py"`, `"js"`, `"ts"`, `"go"`, `"cpp"`, `"c"`, `"java"`,
    /// `"cs"`).  Falls back to the patch-style line heuristic for unknown
    /// extensions.
    ///
    /// Returns one [`CommentViolation`] per phrase match.
    pub fn scan_source(&self, source: &[u8], lang_ext: &str) -> Vec<CommentViolation> {
        let language = lang_to_ts(lang_ext);
        match language {
            Some(lang) => self.scan_with_ts(source, lang),
            None => {
                // Fallback: treat every line as a potential comment and apply
                // the heuristic filter.
                let text = std::str::from_utf8(source).unwrap_or("");
                self.scan_patch(text)
            }
        }
    }

    // -----------------------------------------------------------------------
    // PR metadata surface
    // -----------------------------------------------------------------------

    /// Returns `true` when the PR body contains no recognisable issue link.
    ///
    /// An "unlinked" PR is one whose description does not contain any of the
    /// anchors in [`LINK_ANCHORS`] followed immediately by `#<digits>`.
    /// This signals that the change is not tied to a tracked issue — a
    /// workflow quality gap that contributes [`unlinked_pr`](crate::slop_filter::SlopScore::unlinked_pr) = 1 to the
    /// [`SlopScore`](crate::slop_filter::SlopScore).
    pub fn is_pr_unlinked(&self, body: &str) -> bool {
        let ac = link_ac();
        let lower = body.to_ascii_lowercase();
        for mat in ac.find_iter(&lower) {
            // The anchor must be immediately followed by one or more ASCII digits.
            let after = lower[mat.end()..].trim_start();
            if let Some(rest) = after.strip_prefix('#') {
                if rest
                    .chars()
                    .next()
                    .map(|c| c.is_ascii_digit())
                    .unwrap_or(false)
                {
                    return false; // found a valid link
                }
            } else if after
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
            {
                // some anchors already include '#' (e.g. "closes #"), handle both
                return false;
            }
        }
        true
    }

    // -----------------------------------------------------------------------
    // Internal: tree-sitter walk
    // -----------------------------------------------------------------------

    fn scan_with_ts(
        &self,
        source: &[u8],
        language: tree_sitter::Language,
    ) -> Vec<CommentViolation> {
        let mut parser = Parser::new();
        if parser.set_language(&language).is_err() {
            return Vec::new();
        }
        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Vec::new(),
        };

        let ac = banned_ac();
        let mut violations = Vec::new();
        collect_comments(tree.root_node(), source, ac, &mut violations);
        violations
    }
}

// ---------------------------------------------------------------------------
// Tree-sitter comment node walker
// ---------------------------------------------------------------------------

/// Comment node `kind()` strings across supported grammars.
///
/// | Grammar | Comment kinds |
/// |---------|--------------|
/// | Rust | `line_comment`, `block_comment` |
/// | Python | `comment` |
/// | JS/TS | `comment` |
/// | Go | `comment` |
/// | C/C++ | `comment` |
/// | Java | `line_comment`, `block_comment` |
/// | C# | `comment`, `multiline_comment` |
const COMMENT_KINDS: &[&str] = &[
    "comment",
    "line_comment",
    "block_comment",
    "multiline_comment",
    "doc_comment",
];

fn collect_comments(
    node: Node<'_>,
    source: &[u8],
    ac: &AhoCorasick,
    out: &mut Vec<CommentViolation>,
) {
    if COMMENT_KINDS.contains(&node.kind()) {
        if let Ok(text) = node.utf8_text(source) {
            // Strip comment delimiters so the search runs on readable prose.
            let stripped = strip_comment_markers(text);
            let line = node.start_position().row + 1;
            for mat in ac.find_iter(stripped.as_ref()) {
                out.push(CommentViolation {
                    phrase: BANNED_PHRASES[mat.pattern().as_usize()].to_string(),
                    context: truncate(stripped.as_ref(), 120).to_string(),
                    line,
                });
            }
        }
        // Do not recurse into comment nodes — they have no children.
        return;
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_comments(child, source, ac, out);
    }
}

/// Strip leading comment syntax so that `// as an AI` becomes `as an AI`.
fn strip_comment_markers(text: &str) -> std::borrow::Cow<'_, str> {
    let t = text.trim();
    // Rust/JS/TS/Go/C/C++/Java single-line variants.
    if let Some(rest) = t.strip_prefix("///") {
        return std::borrow::Cow::Borrowed(rest.trim());
    }
    if let Some(rest) = t.strip_prefix("//!") {
        return std::borrow::Cow::Borrowed(rest.trim());
    }
    if let Some(rest) = t.strip_prefix("//") {
        return std::borrow::Cow::Borrowed(rest.trim());
    }
    // Python single-line.
    if let Some(rest) = t.strip_prefix('#') {
        return std::borrow::Cow::Borrowed(rest.trim());
    }
    // Block comments: strip `/*` / `*/` and leading `*` on interior lines.
    if t.starts_with("/*") {
        let inner = t
            .trim_start_matches("/*")
            .trim_end_matches("*/")
            .lines()
            .map(|l| l.trim().trim_start_matches('*').trim())
            .collect::<Vec<_>>()
            .join(" ");
        return std::borrow::Cow::Owned(inner);
    }
    std::borrow::Cow::Borrowed(t)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` when a trimmed source line looks like a comment.
fn is_comment_line(line: &str) -> bool {
    line.starts_with("//")
        || line.starts_with('#')
        || line.starts_with("/*")
        || line.starts_with('*') // block-comment interior line
        || line.starts_with("\"\"\"") // Python docstring delimiter
        || line.starts_with("'''") // Python docstring (single-quote)
}

/// Truncate `s` to at most `max_chars` Unicode scalar values.
fn truncate(s: &str, max_chars: usize) -> &str {
    for (char_count, (byte_pos, _)) in s.char_indices().enumerate() {
        if char_count == max_chars {
            return &s[..byte_pos];
        }
    }
    s
}

/// Map a file extension to a tree-sitter `Language`.
fn lang_to_ts(ext: &str) -> Option<tree_sitter::Language> {
    match ext {
        "rs" => Some(tree_sitter_rust::LANGUAGE.into()),
        "py" | "pyi" => Some(tree_sitter_python::LANGUAGE.into()),
        "js" | "jsx" | "mjs" | "cjs" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" | "tsx" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        "c" | "h" => Some(tree_sitter_c::LANGUAGE.into()),
        "cpp" | "cxx" | "cc" | "hpp" | "hxx" => Some(tree_sitter_cpp::LANGUAGE.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "cs" => Some(tree_sitter_c_sharp::LANGUAGE.into()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Vouch identity scanner
// ---------------------------------------------------------------------------

/// Returns `true` when `author` appears in a Vouch identity file inside `repo_root`.
///
/// ## Files checked (in priority order)
/// 1. `<repo_root>/.vouched`
/// 2. `<repo_root>/trust.td`
/// 3. `<repo_root>/.github/vouched.td`
///
/// The first file that exists is read and every line is checked for a
/// case-insensitive occurrence of `author`.  If the file is found but the
/// author is not listed, the remaining files are also checked before giving up.
///
/// ## Zero-friction failure
/// Any I/O error (file missing, permission denied, etc.) is silently skipped
/// and the next candidate file is tried.  Returns `false` when no vouch file
/// exists or none of them list `author`.
pub fn is_author_vouched(repo_root: &std::path::Path, author: &str) -> bool {
    const VOUCH_FILES: &[&str] = &[".vouched", "trust.td", ".github/vouched.td"];
    let author_lower = author.to_ascii_lowercase();

    for &filename in VOUCH_FILES {
        let path = repo_root.join(filename);
        let contents = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(_) => continue, // file absent or unreadable — try next
        };
        for line in contents.lines() {
            if line.to_ascii_lowercase().contains(author_lower.as_str()) {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner() -> CommentScanner {
        CommentScanner::new()
    }

    // --- Patch scanning ---

    #[test]
    fn test_patch_detects_ai_ism_in_rust_line_comment() {
        let patch = "\
diff --git a/src/lib.rs b/src/lib.rs
--- a/src/lib.rs
+++ b/src/lib.rs
@@ -1,3 +1,4 @@
 fn foo() {}
+// As an AI language model, I recommend using this function.
+fn bar() {}
";
        let v = scanner().scan_patch(patch);
        assert!(!v.is_empty(), "should detect AI-ism");
        assert!(v[0].phrase.contains("as an ai") || v[0].phrase.contains("as a language model"));
    }

    #[test]
    fn test_patch_ignores_non_comment_added_lines() {
        let patch = "\
+fn bar() { let x = \"as an AI\"; }
";
        // String literal in code line — not a comment line, must be skipped.
        let v = scanner().scan_patch(patch);
        assert!(v.is_empty(), "non-comment lines must not be flagged");
    }

    #[test]
    fn test_patch_ignores_removed_and_context_lines() {
        let patch = "\
-// As an AI I would remove this
 // As an AI context line
";
        let v = scanner().scan_patch(patch);
        assert!(v.is_empty(), "removed/context lines must not be flagged");
    }

    #[test]
    fn test_patch_detects_python_hash_comment() {
        let patch = "+# generated by ChatGPT\n";
        let v = scanner().scan_patch(patch);
        assert!(!v.is_empty());
        assert_eq!(v[0].phrase, "generated by chatgpt");
    }

    #[test]
    fn test_patch_clean_comment() {
        let patch = "+// Calculate the Euclidean distance between two points.\n";
        let v = scanner().scan_patch(patch);
        assert!(v.is_empty(), "clean comment must produce no violations");
    }

    // --- PR link check ---

    #[test]
    fn test_pr_linked_closes() {
        assert!(!scanner().is_pr_unlinked("Closes #123\n\nThis PR adds a feature."));
    }

    #[test]
    fn test_pr_linked_fixes_lowercase() {
        assert!(!scanner().is_pr_unlinked("fixes #42: handle edge case in parser"));
    }

    #[test]
    fn test_pr_linked_resolves() {
        assert!(!scanner().is_pr_unlinked("Resolves #7"));
    }

    #[test]
    fn test_pr_unlinked_no_reference() {
        assert!(scanner().is_pr_unlinked("Added a cool new feature. No issue ref."));
    }

    #[test]
    fn test_pr_unlinked_mention_without_number() {
        // "closes" appears but no `#N` follows.
        assert!(scanner().is_pr_unlinked("This closes the debate about naming."));
    }

    // --- Hallucinated security fix detection ---

    #[test]
    fn test_hallucinated_fix_cve_readme_only() {
        let body = "Fixes CVE-2026-9999: critical buffer overflow in auth module.";
        let exts = vec!["md".to_string()];
        let finding = detect_hallucinated_fix(body, &exts);
        assert!(finding.is_some(), "CVE claim + only .md → hallucinated fix");
        let desc = finding.unwrap().description;
        assert!(desc.contains("Hallucinated Security Fix"));
        assert!(desc.contains("CVE-"));
    }

    #[test]
    fn test_hallucinated_fix_not_triggered_with_code_file() {
        let body = "Fixes CVE-2026-9999: critical buffer overflow.";
        let exts = vec!["rs".to_string(), "md".to_string()];
        assert!(
            detect_hallucinated_fix(body, &exts).is_none(),
            "code file present — should not flag"
        );
    }

    #[test]
    fn test_hallucinated_fix_no_keyword() {
        let body = "Update README with better installation instructions.";
        let exts = vec!["md".to_string()];
        assert!(
            detect_hallucinated_fix(body, &exts).is_none(),
            "no security keyword → no flag"
        );
    }

    #[test]
    fn test_hallucinated_fix_cve_without_digit_suffix() {
        // "CVE-" not followed by a digit — must not match.
        let body = "Follow the CVE-reporting process for disclosure.";
        let exts = vec!["md".to_string()];
        assert!(
            detect_hallucinated_fix(body, &exts).is_none(),
            "CVE- not followed by digit — no flag"
        );
    }

    #[test]
    fn test_hallucinated_fix_various_keywords() {
        let non_code = vec!["json".to_string(), "yaml".to_string()];
        let bodies = [
            (
                "buffer overflow",
                "This PR fixes a buffer overflow in the config parser.",
            ),
            ("memory leak", "Patch for a memory leak in the allocator."),
            ("RCE", "Fix RCE in the API endpoint."),
            ("XSS", "Mitigation for XSS in the frontend."),
            ("SQLi", "Closes SQLi in the database layer."),
            ("vulnerability", "Fixes a critical vulnerability in login."),
        ];
        for (kw, body) in &bodies {
            let finding = detect_hallucinated_fix(body, &non_code);
            assert!(finding.is_some(), "should flag keyword '{kw}' in: {body}");
        }
    }

    #[test]
    fn test_hallucinated_fix_empty_inputs() {
        assert!(detect_hallucinated_fix("", &["md".to_string()]).is_none());
        assert!(detect_hallucinated_fix("Fixes CVE-2026-1 buffer overflow", &[]).is_none());
    }

    // --- Source scanning (tree-sitter) ---

    #[test]
    fn test_source_scan_rust_line_comment() {
        let src = b"// As an AI I wrote this function.\nfn foo() {}\n";
        let v = scanner().scan_source(src, "rs");
        assert!(!v.is_empty(), "Rust line comment must be detected");
        assert_eq!(v[0].line, 1);
    }

    #[test]
    fn test_source_scan_python_hash_comment() {
        let src = b"# generated by ChatGPT\ndef foo():\n    pass\n";
        let v = scanner().scan_source(src, "py");
        assert!(!v.is_empty(), "Python hash comment must be detected");
    }

    #[test]
    fn test_source_scan_js_block_comment() {
        let src = b"/* As an AI language model, this is safe. */\nfunction foo() {}\n";
        let v = scanner().scan_source(src, "js");
        assert!(!v.is_empty(), "JS block comment must be detected");
    }

    #[test]
    fn test_source_scan_clean_file() {
        let src =
            b"// Compute the checksum of a byte slice.\nfn checksum(data: &[u8]) -> u32 { 0 }\n";
        let v = scanner().scan_source(src, "rs");
        assert!(v.is_empty(), "clean source must produce no violations");
    }
}
