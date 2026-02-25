//! # Slop Hunter — Tree-Sitter Antipattern Detection
//!
//! Detects language-specific code antipatterns (slop) in source file bytes
//! using tree-sitter structural queries.  Complements the BLAKE3/SimHash
//! clone-detection pipeline with semantic pattern matching.
//!
//! ## Supported Languages & Patterns
//!
//! | Language | Pattern | Description |
//! |----------|---------|-------------|
//! | Python   | Hallucinated imports | `import X` inside a function body where `X` is never used |
//! | Rust     | Vacuous unsafe | `unsafe { ... }` containing no genuinely unsafe operations |
//! | Go       | Goroutine closure trap | `go func()` in a loop that may capture loop variables |
//!
//! ## Usage
//! ```ignore
//! let findings = slop_hunter::find_slop("py", source_bytes);
//! for f in findings {
//!     eprintln!("[SLOP] {}:{}-{}", f.description, f.start_byte, f.end_byte);
//! }
//! ```

use std::sync::OnceLock;

use tree_sitter::{Language, Node, Query, QueryCursor, StreamingIterator};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single antipattern finding within a source file.
#[derive(Debug, Clone)]
pub struct SlopFinding {
    /// Byte offset of the finding's start in the source.
    pub start_byte: usize,
    /// Byte offset of the finding's end in the source.
    pub end_byte: usize,
    /// Human-readable description of the antipattern.
    pub description: String,
}

// ---------------------------------------------------------------------------
// Query strings
// ---------------------------------------------------------------------------

const PYTHON_IMPORT_QUERY: &str = r#"
(function_definition
  body: (block) @body
) @function
"#;

const RUST_UNSAFE_QUERY: &str = r#"
(unsafe_block
  (block) @body
) @unsafe_block
"#;

// ---------------------------------------------------------------------------
// Singleton query engine
// ---------------------------------------------------------------------------

struct QueryEngine {
    python_lang: Language,
    python_query: Query,
    rust_lang: Language,
    rust_query: Query,
    /// Go grammar language handle; Go slop detection uses direct AST walking
    /// rather than a query, so only the language object is needed.
    go_lang: Language,
}

impl QueryEngine {
    fn new() -> anyhow::Result<Self> {
        let python_lang: Language = tree_sitter_python::LANGUAGE.into();
        let python_query = Query::new(&python_lang, PYTHON_IMPORT_QUERY)
            .map_err(|e| anyhow::anyhow!("slop_hunter: Python query error: {e}"))?;

        let rust_lang: Language = tree_sitter_rust::LANGUAGE.into();
        let rust_query = Query::new(&rust_lang, RUST_UNSAFE_QUERY)
            .map_err(|e| anyhow::anyhow!("slop_hunter: Rust query error: {e}"))?;

        let go_lang: Language = tree_sitter_go::LANGUAGE.into();
        // Go detection uses direct AST walking; no query compilation needed.

        Ok(Self {
            python_lang,
            python_query,
            rust_lang,
            rust_query,
            go_lang,
        })
    }
}

static ENGINE: OnceLock<Option<QueryEngine>> = OnceLock::new();

fn engine() -> Option<&'static QueryEngine> {
    ENGINE.get_or_init(|| QueryEngine::new().ok()).as_ref()
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Detect language-specific antipatterns in `source`.
///
/// `language` should be the file extension (`"py"`, `"rs"`, `"go"`).
/// Returns an empty [`Vec`] for unsupported languages — never an error.
pub fn find_slop(language: &str, source: &[u8]) -> Vec<SlopFinding> {
    let Some(eng) = engine() else {
        return Vec::new();
    };

    match language {
        "py" => find_python_slop(eng, source),
        "rs" => find_rust_slop(eng, source),
        "go" => find_go_slop(eng, source),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Python: hallucinated imports
// ---------------------------------------------------------------------------

fn find_python_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.python_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&eng.python_query, tree.root_node(), source);
    let cap_names = eng.python_query.capture_names();

    let mut findings = Vec::new();

    while let Some(m) = matches.next() {
        let body_cap = m
            .captures
            .iter()
            .find(|c| cap_names[c.index as usize] == "body");

        if let Some(body) = body_cap {
            // Walk the block to find direct import statements.
            let mut block_cursor = body.node.walk();
            for child in body.node.children(&mut block_cursor) {
                if child.kind() != "import_statement" && child.kind() != "import_from_statement" {
                    continue;
                }
                let imported_names = extract_imported_names(child, source);
                for name in imported_names {
                    if !is_name_used_in_body(body.node, source, &name) {
                        findings.push(SlopFinding {
                            start_byte: child.start_byte(),
                            end_byte: child.end_byte(),
                            description: format!(
                                "Hallucinated import: '{name}' imported inside function but never used"
                            ),
                        });
                    }
                }
            }
        }
    }

    findings
}

/// Extract the bound names from an import node (what you would call in code).
fn extract_imported_names(import_node: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    match import_node.kind() {
        "import_statement" => {
            // import foo          → "foo"
            // import foo.bar      → "foo"
            // import foo as baz   → "baz"
            let mut cursor = import_node.walk();
            for child in import_node.children(&mut cursor) {
                match child.kind() {
                    "aliased_import" => {
                        // import X as Y → bind "Y"
                        if let Some(alias) = child.child_by_field_name("alias") {
                            if let Ok(s) = alias.utf8_text(source) {
                                names.push(s.to_string());
                            }
                        }
                    }
                    "dotted_name" => {
                        // import foo.bar → bind "foo"
                        if let Some(first) = child.child(0) {
                            if let Ok(s) = first.utf8_text(source) {
                                names.push(s.to_string());
                            }
                        }
                    }
                    "identifier" => {
                        if let Ok(s) = child.utf8_text(source) {
                            names.push(s.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        "import_from_statement" => {
            // from foo import bar        → "bar"
            // from foo import bar as b   → "b"
            // from foo import *          → skip (wildcard)
            let mut after_import = false;
            let mut cursor = import_node.walk();
            for child in import_node.children(&mut cursor) {
                match child.kind() {
                    "import" => after_import = true,
                    "wildcard_import" => {
                        // from foo import * — nothing bindable to check
                        after_import = false;
                    }
                    "aliased_import" if after_import => {
                        if let Some(alias) = child.child_by_field_name("alias") {
                            if let Ok(s) = alias.utf8_text(source) {
                                names.push(s.to_string());
                            }
                        } else if let Some(name_node) = child.child_by_field_name("name") {
                            if let Ok(s) = name_node.utf8_text(source) {
                                names.push(s.to_string());
                            }
                        }
                    }
                    "identifier" if after_import => {
                        if let Ok(s) = child.utf8_text(source) {
                            names.push(s.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
    names
}

/// Check if `name` is used as an identifier anywhere in `body_node`,
/// excluding the import statements themselves.
fn is_name_used_in_body(body_node: Node<'_>, source: &[u8], name: &str) -> bool {
    identifier_used_recursive(body_node, source, name)
}

fn identifier_used_recursive(node: Node<'_>, source: &[u8], name: &str) -> bool {
    // Skip import nodes — they define the name, not use it.
    if node.kind() == "import_statement" || node.kind() == "import_from_statement" {
        return false;
    }
    if node.kind() == "identifier" {
        if let Ok(text) = node.utf8_text(source) {
            if text == name {
                return true;
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if identifier_used_recursive(child, source, name) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Rust: vacuous unsafe blocks
// ---------------------------------------------------------------------------

fn find_rust_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.rust_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&eng.rust_query, tree.root_node(), source);
    let cap_names = eng.rust_query.capture_names();

    let mut findings = Vec::new();

    while let Some(m) = matches.next() {
        let block_cap = m
            .captures
            .iter()
            .find(|c| cap_names[c.index as usize] == "body");
        let unsafe_cap = m
            .captures
            .iter()
            .find(|c| cap_names[c.index as usize] == "unsafe_block");

        if let (Some(body), Some(ub)) = (block_cap, unsafe_cap) {
            if !contains_unsafe_operations(body.node, source) {
                findings.push(SlopFinding {
                    start_byte: ub.node.start_byte(),
                    end_byte: ub.node.end_byte(),
                    description: "Vacuous unsafe block: contains no raw pointer dereferences, \
                                  FFI calls, or inline assembly"
                        .to_string(),
                });
            }
        }
    }

    findings
}

/// Returns `true` if the block contains operations that genuinely require `unsafe`.
fn contains_unsafe_operations(block_node: Node<'_>, source: &[u8]) -> bool {
    let start = block_node.start_byte();
    let end = block_node.end_byte().min(source.len());
    if start >= end {
        return false;
    }
    let text = &source[start..end];

    // Patterns that legitimately require unsafe:
    // raw pointer dereferences, extern blocks, inline/global assembly, mutable statics.
    const UNSAFE_INDICATORS: &[&[u8]] = &[
        b"*mut ",
        b"*const ",
        b"unsafe fn ",
        b"extern \"C\"",
        b"asm!(",
        b"global_asm!(",
        b"static mut ",
        b"transmute(",
        b"from_raw(",
        b"as_mut_ptr()",
        b"as_ptr()",
    ];

    if UNSAFE_INDICATORS
        .iter()
        .any(|pat| text.windows(pat.len()).any(|w| w == *pat))
    {
        return true;
    }

    // Raw pointer dereference: `*ptr` — `*` immediately followed by an identifier
    // character (letter or `_`), indicating a dereference rather than multiplication
    // (which has whitespace around `*`) or a type annotation (already caught above).
    for i in 0..text.len().saturating_sub(1) {
        if text[i] == b'*' {
            let next = text[i + 1];
            if next.is_ascii_alphabetic() || next == b'_' {
                return true;
            }
        }
    }

    false
}

// ---------------------------------------------------------------------------
// Go: goroutine closure trap
// ---------------------------------------------------------------------------

fn find_go_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.go_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    // Walk the AST looking for `for` loops that contain `go` statements
    // with function literals — these are candidates for the closure capture trap.
    let mut findings = Vec::new();
    find_go_goroutine_loops(tree.root_node(), source, &mut findings);
    findings
}

/// Recursively walk the Go AST looking for `for` loops containing `go func()` calls.
fn find_go_goroutine_loops(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "for_statement" {
        if let Some(body) = node.child_by_field_name("body") {
            if for_body_has_go_func_literal(body, source) {
                let loop_vars = extract_go_loop_vars(node, source);
                // Flag as slop if there are loop variables that might be captured.
                // Even without definitive proof, this is the pattern that causes bugs.
                if !loop_vars.is_empty() {
                    findings.push(SlopFinding {
                        start_byte: node.start_byte(),
                        end_byte: node.end_byte(),
                        description: format!(
                            "Goroutine closure trap: `go func()` in loop may capture loop \
                             variable(s) {:?} by reference — use explicit parameter passing",
                            loop_vars
                        ),
                    });
                    return; // Don't recurse into the same loop
                }
            }
        }
    }

    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_go_goroutine_loops(child, source, findings);
    }
}

/// Check if a `for` loop body directly contains a `go` statement with a func literal.
fn for_body_has_go_func_literal(body_node: Node<'_>, source: &[u8]) -> bool {
    let body_text_start = body_node.start_byte();
    let body_text_end = body_node.end_byte().min(source.len());
    if body_text_start >= body_text_end {
        return false;
    }
    let text = &source[body_text_start..body_text_end];
    // Heuristic: look for `go func(` pattern in the body text.
    text.windows(8).any(|w| w == b"go func(")
}

/// Extract variable names from a Go `for` loop's range clause or for clause.
fn extract_go_loop_vars(for_node: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut vars = Vec::new();
    let mut cursor = for_node.walk();

    for child in for_node.children(&mut cursor) {
        match child.kind() {
            "range_clause" | "for_clause" => {
                // Walk the clause looking for identifiers on the left side
                let mut inner = child.walk();
                for inner_child in child.children(&mut inner) {
                    if inner_child.kind() == "identifier" {
                        if let Ok(name) = inner_child.utf8_text(source) {
                            if !name.is_empty() && name != "_" {
                                vars.push(name.to_string());
                            }
                        }
                    }
                    // Stop after := or = (right-hand side vars aren't loop vars)
                    if matches!(inner_child.kind(), ":=" | "=") {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    vars
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unknown_language_returns_empty() {
        let findings = find_slop("unknown_lang_xyz", b"some code");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_python_hallucinated_import_detected() {
        let src = b"def process():\n    import requests\n    return 42\n";
        let findings = find_slop("py", src);
        assert!(
            !findings.is_empty(),
            "hallucinated 'requests' import must be detected"
        );
        assert!(findings[0].description.contains("requests"));
    }

    #[test]
    fn test_python_used_import_not_flagged() {
        let src = b"def process():\n    import os\n    return os.getcwd()\n";
        let findings = find_slop("py", src);
        assert!(
            findings.is_empty(),
            "used import should not be flagged, got: {:?}",
            findings
        );
    }

    #[test]
    fn test_rust_vacuous_unsafe_detected() {
        let src = b"fn foo() {\n    unsafe {\n        let x = 1 + 1;\n    }\n}\n";
        let findings = find_slop("rs", src);
        assert!(
            !findings.is_empty(),
            "vacuous unsafe block must be detected"
        );
    }

    #[test]
    fn test_rust_real_unsafe_not_flagged() {
        let src = b"fn foo(p: *mut u8) {\n    unsafe {\n        *p = 42;\n    }\n}\n";
        let findings = find_slop("rs", src);
        assert!(
            findings.is_empty(),
            "unsafe with raw pointer dereference must not be flagged"
        );
    }
}
