//! PR Slop Filter — detect dead-code additions and logic clones in patches.
//!
//! [`PRBouncer`] is a trait for patch quality gatekeepers.
//! [`PatchBouncer`] is the default implementation: it parses a unified diff,
//! extracts added source for the detected language, and uses structural hashing
//! to detect duplication and re-introduction of known symbols.
//!
//! ## Language Detection
//! The patch language is detected from the `+++ b/<path>` header line by
//! extension. Supported: `.py`, `.rs`, `.cpp/.cxx/.cc/.h/.hpp`, `.c`,
//! `.java`, `.cs`, `.go`, `.js/.jsx`, `.glsl/.vert/.frag`.
//!
//! ## Scoring Formula
//! ```text
//! SlopScore = (dead_symbols_added * 10) + (logic_clones_found * 5)
//! ```
//! Dead-symbol additions are penalised more heavily (×10) than structural
//! duplication (×5) because re-introducing dead code degrades signal quality.

use std::collections::{HashMap, HashSet};

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
/// score = (dead_symbols_added × 10) + (logic_clones_found × 5)
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SlopScore {
    /// Number of added functions whose names already appear in the registry.
    ///
    /// Signals that the patch re-introduces or duplicates a known symbol —
    /// a common source of dead code accumulation.
    pub dead_symbols_added: u32,
    /// Number of structurally identical function pairs within the added code.
    ///
    /// Each "extra" clone beyond the first occurrence in a hash group counts
    /// as one clone (N functions sharing a hash → N−1 clones).
    pub logic_clones_found: u32,
}

impl SlopScore {
    /// Returns the weighted aggregate slop score.
    ///
    /// Higher scores indicate lower patch quality. A score of zero means the
    /// patch passes all checks cleanly.
    pub fn score(&self) -> u32 {
        self.dead_symbols_added * 10 + self.logic_clones_found * 5
    }

    /// Returns `true` when no slop was detected.
    pub fn is_clean(&self) -> bool {
        self.dead_symbols_added == 0 && self.logic_clones_found == 0
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
        _ => None,
    }
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
        // Detect language from the +++ header extension.
        let ext = extract_patch_ext(patch);
        let cfg = match lang_for_ext(ext) {
            Some(c) => c,
            // Unknown / unsupported language — skip scoring, not an error.
            None => return Ok(SlopScore::default()),
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
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&cfg.language)
            .map_err(|e| anyhow::anyhow!("Failed to load grammar for .{ext}: {e}"))?;

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => return Ok(SlopScore::default()),
        };

        let query = Query::new(&cfg.language, cfg.query_src)
            .map_err(|e| anyhow::anyhow!("Query compile error for .{ext}: {e}"))?;

        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), source);
        let cap_names = query.capture_names();

        // Collect (name, structural_hash) pairs for added functions.
        let mut fn_hashes: Vec<(String, u64)> = Vec::new();
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
                    let hash = crate::compute_structural_hash(body_c.node, source);
                    fn_hashes.push((name.to_string(), hash));
                }
            }
        }

        // Dead symbols added — name already exists in registry.
        let registry_names: HashSet<&str> =
            registry.entries.iter().map(|e| e.name.as_str()).collect();
        let dead_symbols_added = fn_hashes
            .iter()
            .filter(|(name, _)| registry_names.contains(name.as_str()))
            .count() as u32;

        // Logic clones — structural hash collisions within added code.
        // For a group of N functions sharing the same hash, contribute N − 1.
        let mut hash_counts: HashMap<u64, u32> = HashMap::new();
        for (_, hash) in &fn_hashes {
            *hash_counts.entry(*hash).or_insert(0) += 1;
        }
        let logic_clones_found: u32 = hash_counts
            .values()
            .filter(|&&c| c > 1)
            .map(|&c| c - 1)
            .sum();

        Ok(SlopScore {
            dead_symbols_added,
            logic_clones_found,
        })
    }
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
        assert_eq!(score.score(), 10);
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

    #[test]
    fn test_score_formula() {
        let s = SlopScore {
            dead_symbols_added: 2,
            logic_clones_found: 3,
        };
        assert_eq!(s.score(), 2 * 10 + 3 * 5); // 35
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
