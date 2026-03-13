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
//! | YAML     | Wildcard Kubernetes host | `VirtualService`/`Ingress` with `hosts: ["*"]` — exposes all routes publicly |
//! | Java     | Empty catch block | `catch (E e) {}` — silently swallows exceptions |
//! | Java     | `System.out.println` | Console debug logging leaking to production |
//! | C#       | `async void` method | Cannot be awaited; unhandled exceptions crash the process |
//! | C++      | Raw `new`/`delete` | Manual memory management instead of RAII smart pointers |
//! | Bash     | Unquoted variable | `$VAR` without quotes — word-splitting and glob-expansion hazard |
//! | JavaScript | `eval()` call | Executes arbitrary code from a string — code injection risk |
//! | TypeScript | `eval()` call | Same as JavaScript |
//! | C        | `gets()` call | Removed in C11; unbounded buffer overflow — use `fgets()` |
//! | HCL/Terraform | Open CIDR `0.0.0.0/0` | Wildcard ingress rule exposes resource to the entire internet |
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

use crate::metadata::{DOMAIN_ALL, DOMAIN_FIRST_PARTY};

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
    /// Domain bitmask indicating which file origins this finding is relevant for.
    ///
    /// Most antipatterns are [`crate::metadata::DOMAIN_FIRST_PARTY`] — they flag
    /// memory-safety or code-quality issues that only apply to code you own.
    /// Infrastructure and supply-chain rules use [`crate::metadata::DOMAIN_ALL`]
    /// so they fire on vendored and test files too.
    pub domain: u8,
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

/// Java: empty catch blocks + System.out.print* calls.
/// Loaded from `queries/java.scm` — embedded at compile time.
const JAVA_SLOP_QUERY: &str = include_str!("../queries/java.scm");

/// C#: `async void` method declarations.
/// Loaded from `queries/c_sharp.scm` — embedded at compile time.
const CSHARP_SLOP_QUERY: &str = include_str!("../queries/c_sharp.scm");

/// C++: raw `new` and `delete` expressions.
/// Loaded from `queries/cpp.scm` — embedded at compile time.
const CPP_SLOP_QUERY: &str = include_str!("../queries/cpp.scm");

/// Bash: unquoted variable expansions as command arguments.
/// Loaded from `queries/bash.scm` — embedded at compile time.
const BASH_SLOP_QUERY: &str = include_str!("../queries/bash.scm");

// Equivalent to queries/kubernetes.scm — documents the targeted structure.
// Direct AST walking is used instead of this query because tree-sitter
// predicates cannot correlate sibling pairs (kind: X AND hosts: ["*"]) in a
// single match expression.
#[allow(dead_code)]
const YAML_K8S_WILDCARD_HOSTS_QUERY: &str = r#"
; Matches a block-sequence item whose scalar value is the bare wildcard "*".
; Used to locate wildcard host entries inside Kubernetes VirtualService/Ingress specs.
(block_sequence_item
  (flow_node
    (plain_scalar
      (string_scalar) @wildcard_host)))
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
    /// YAML grammar handle; Kubernetes detection uses direct AST walking for
    /// the same reason as Go — cross-sibling predicate matching is unsupported.
    yaml_lang: Language,
    java_lang: Language,
    java_query: Query,
    csharp_lang: Language,
    csharp_query: Query,
    cpp_lang: Language,
    cpp_query: Query,
    bash_lang: Language,
    bash_query: Query,
    /// JavaScript/JSX — AST walk, no query needed.
    js_lang: Language,
    /// TypeScript — AST walk.
    ts_lang: Language,
    /// TSX (TypeScript + JSX) — AST walk.
    tsx_lang: Language,
    /// Plain C — AST walk for banned libc calls.
    c_lang: Language,
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
        let yaml_lang: Language = tree_sitter_yaml::LANGUAGE.into();

        let java_lang: Language = tree_sitter_java::LANGUAGE.into();
        let java_query = Query::new(&java_lang, JAVA_SLOP_QUERY)
            .map_err(|e| anyhow::anyhow!("slop_hunter: Java query error: {e}"))?;

        let csharp_lang: Language = tree_sitter_c_sharp::LANGUAGE.into();
        let csharp_query = Query::new(&csharp_lang, CSHARP_SLOP_QUERY)
            .map_err(|e| anyhow::anyhow!("slop_hunter: C# query error: {e}"))?;

        let cpp_lang: Language = tree_sitter_cpp::LANGUAGE.into();
        let cpp_query = Query::new(&cpp_lang, CPP_SLOP_QUERY)
            .map_err(|e| anyhow::anyhow!("slop_hunter: C++ query error: {e}"))?;

        let bash_lang: Language = tree_sitter_bash::LANGUAGE.into();
        let bash_query = Query::new(&bash_lang, BASH_SLOP_QUERY)
            .map_err(|e| anyhow::anyhow!("slop_hunter: Bash query error: {e}"))?;

        let js_lang: Language = tree_sitter_javascript::LANGUAGE.into();
        let ts_lang: Language = tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into();
        let tsx_lang: Language = tree_sitter_typescript::LANGUAGE_TSX.into();
        let c_lang: Language = tree_sitter_c::LANGUAGE.into();

        Ok(Self {
            python_lang,
            python_query,
            rust_lang,
            rust_query,
            go_lang,
            yaml_lang,
            java_lang,
            java_query,
            csharp_lang,
            csharp_query,
            cpp_lang,
            cpp_query,
            bash_lang,
            bash_query,
            js_lang,
            ts_lang,
            tsx_lang,
            c_lang,
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
        "yaml" | "yml" => find_yaml_slop(eng, source),
        "java" => find_java_slop(eng, source),
        "cs" => find_csharp_slop(eng, source),
        "cpp" | "cxx" | "cc" | "hpp" => find_cpp_slop(eng, source),
        "sh" | "bash" => find_bash_slop(eng, source),
        "js" | "jsx" | "mjs" | "cjs" => find_javascript_slop(eng, source),
        "ts" => find_typescript_slop(eng, source, false),
        "tsx" => find_typescript_slop(eng, source, true),
        "c" | "h" => find_c_slop(eng, source),
        "hcl" | "tf" => find_hcl_slop(source),
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
                            domain: DOMAIN_FIRST_PARTY,
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
                    domain: DOMAIN_FIRST_PARTY,
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
                             variable(s) {loop_vars:?} by reference — use explicit parameter passing"
                        ),
                        domain: DOMAIN_FIRST_PARTY,
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
// YAML: Kubernetes wildcard-host misconfiguration
// ---------------------------------------------------------------------------

/// Kubernetes resource kinds that govern traffic routing.
const K8S_ROUTING_KINDS: &[&str] = &["VirtualService", "Ingress", "HTTPRoute", "Gateway"];

fn find_yaml_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files that can't possibly contain the pattern.
    let has_k8s_kind = K8S_ROUTING_KINDS
        .iter()
        .any(|k| source.windows(k.len()).any(|w| w == k.as_bytes()));
    if !has_k8s_kind {
        return Vec::new();
    }

    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.yaml_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut findings = Vec::new();
    detect_k8s_wildcard_hosts(tree.root_node(), source, &mut findings);
    findings
}

/// Walk the YAML AST looking for Kubernetes documents where a routing resource
/// (`VirtualService`, `Ingress`, etc.) exposes a wildcard host (`"*"` or `*`).
///
/// Strategy (two-pass per document):
/// 1. Walk the top-level block mapping to extract the `kind` scalar.
/// 2. If `kind` is a routing resource, walk the same mapping depth-first to
///    find any sequence item whose scalar is `*` or `"*"`.
fn detect_k8s_wildcard_hosts(root: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    let mut doc_cursor = root.walk();
    for child in root.children(&mut doc_cursor) {
        // Each child of `stream` is a `document`.
        walk_yaml_document(child, source, findings);
    }
}

fn walk_yaml_document(doc_node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    // Find the top-level block_mapping inside this document.
    let Some(mapping) = find_first_block_mapping(doc_node) else {
        return;
    };

    // Pass 1: collect `kind` value from the top-level mapping pairs.
    let kind = extract_mapping_scalar(mapping, source, "kind");
    let is_routing_kind = kind
        .as_deref()
        .is_some_and(|k| K8S_ROUTING_KINDS.contains(&k));

    if !is_routing_kind {
        return;
    }

    // Pass 2: find any sequence item whose scalar equals `*` under `hosts`.
    let mut cursor = mapping.walk();
    for pair in mapping.children(&mut cursor) {
        if pair.kind() != "block_mapping_pair" {
            continue;
        }
        let Some(key_text) = pair_key_text(pair, source) else {
            continue;
        };
        // `hosts` may appear at top-level (Gateway) or inside `spec` (VirtualService/Ingress).
        // We accept `hosts` at any depth by recursively scanning `spec`.
        if key_text == "hosts" {
            if let Some(start) = find_wildcard_in_sequence(pair, source) {
                findings.push(SlopFinding {
                    start_byte: start,
                    end_byte: start + 1,
                    description: format!(
                        "Kubernetes wildcard host: `{k}` exposes all routes publicly via \
                         `hosts: [\"*\"]`; restrict to explicit hostnames",
                        k = kind.as_deref().unwrap_or("unknown")
                    ),
                    domain: DOMAIN_ALL,
                });
            }
        } else if key_text == "spec" {
            // Recurse one level into `spec` to find a nested `hosts` key.
            if let Some(inner_mapping) = find_first_block_mapping(pair) {
                let mut inner_cursor = inner_mapping.walk();
                for inner_pair in inner_mapping.children(&mut inner_cursor) {
                    if inner_pair.kind() != "block_mapping_pair" {
                        continue;
                    }
                    if pair_key_text(inner_pair, source).as_deref() == Some("hosts") {
                        if let Some(start) = find_wildcard_in_sequence(inner_pair, source) {
                            findings.push(SlopFinding {
                                start_byte: start,
                                end_byte: start + 1,
                                description: format!(
                                    "Kubernetes wildcard host: `{k}` exposes all routes publicly \
                                     via `spec.hosts: [\"*\"]`; restrict to explicit hostnames",
                                    k = kind.as_deref().unwrap_or("unknown")
                                ),
                                domain: DOMAIN_ALL,
                            });
                        }
                    }
                }
            }
        }
    }
}

/// Return the scalar text of the value for a given `key` in a `block_mapping` node.
fn extract_mapping_scalar<'a>(mapping: Node<'a>, source: &'a [u8], key: &str) -> Option<String> {
    let mut cursor = mapping.walk();
    for pair in mapping.children(&mut cursor) {
        if pair.kind() != "block_mapping_pair" {
            continue;
        }
        if pair_key_text(pair, source).as_deref() == Some(key) {
            return pair_value_scalar(pair, source);
        }
    }
    None
}

/// Extract the text of a `block_mapping_pair`'s key.
fn pair_key_text(pair: Node<'_>, source: &[u8]) -> Option<String> {
    let key_node = pair.child_by_field_name("key")?;
    scalar_text(key_node, source)
}

/// Extract the scalar text of a `block_mapping_pair`'s value.
fn pair_value_scalar(pair: Node<'_>, source: &[u8]) -> Option<String> {
    let val_node = pair.child_by_field_name("value")?;
    scalar_text(val_node, source)
}

/// Walk a node tree to find the first string scalar text.
fn scalar_text(node: Node<'_>, source: &[u8]) -> Option<String> {
    let kind = node.kind();
    // Direct scalar kinds.
    if matches!(
        kind,
        "string_scalar" | "plain_scalar" | "double_quote_scalar" | "single_quote_scalar"
    ) {
        return node
            .utf8_text(source)
            .ok()
            .map(|s| s.trim_matches('"').trim_matches('\'').to_string());
    }
    // Wrapper nodes — recurse into children.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(text) = scalar_text(child, source) {
            return Some(text);
        }
    }
    None
}

/// Find the first `block_mapping` node that is a descendant of `node`.
fn find_first_block_mapping(node: Node<'_>) -> Option<Node<'_>> {
    if node.kind() == "block_mapping" {
        return Some(node);
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(m) = find_first_block_mapping(child) {
            return Some(m);
        }
    }
    None
}

/// Search a `block_mapping_pair`'s value for a sequence item whose scalar is `*`.
/// Returns the start byte of the wildcard item when found.
fn find_wildcard_in_sequence(pair: Node<'_>, source: &[u8]) -> Option<usize> {
    find_wildcard_recursive(pair, source)
}

fn find_wildcard_recursive(node: Node<'_>, source: &[u8]) -> Option<usize> {
    // Check if this node is a scalar with value `*`.
    if matches!(
        node.kind(),
        "string_scalar" | "plain_scalar" | "double_quote_scalar" | "single_quote_scalar"
    ) {
        let text = node.utf8_text(source).ok()?;
        let trimmed = text.trim_matches('"').trim_matches('\'');
        if trimmed == "*" {
            return Some(node.start_byte());
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if let Some(pos) = find_wildcard_recursive(child, source) {
            return Some(pos);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Java: empty catch blocks + System.out.print*
// ---------------------------------------------------------------------------

fn find_java_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.java_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&eng.java_query, tree.root_node(), source);
    let cap_names = eng.java_query.capture_names();

    let mut findings = Vec::new();

    while let Some(m) = matches.next() {
        match m.pattern_index {
            0 => {
                // Pattern 0: empty_catch — only flag when the block has no statements.
                let Some(body_cap) = m
                    .captures
                    .iter()
                    .find(|c| cap_names[c.index as usize] == "catch_body")
                else {
                    continue;
                };
                let Some(outer_cap) = m
                    .captures
                    .iter()
                    .find(|c| cap_names[c.index as usize] == "empty_catch")
                else {
                    continue;
                };
                // An empty block has no named children (only `{` and `}` tokens).
                if body_cap.node.named_child_count() == 0 {
                    findings.push(SlopFinding {
                        start_byte: outer_cap.node.start_byte(),
                        end_byte: outer_cap.node.end_byte(),
                        description: "Empty catch block: exception is silently swallowed — \
                                      log or rethrow it"
                            .to_string(),
                        domain: DOMAIN_FIRST_PARTY,
                    });
                }
            }
            1 => {
                // Pattern 1: sysout_call — filter to System.out.print* in Rust.
                let sys_text = m
                    .captures
                    .iter()
                    .find(|c| cap_names[c.index as usize] == "sys")
                    .and_then(|c| c.node.utf8_text(source).ok())
                    .unwrap_or("");
                let out_text = m
                    .captures
                    .iter()
                    .find(|c| cap_names[c.index as usize] == "out")
                    .and_then(|c| c.node.utf8_text(source).ok())
                    .unwrap_or("");
                let method_text = m
                    .captures
                    .iter()
                    .find(|c| cap_names[c.index as usize] == "method")
                    .and_then(|c| c.node.utf8_text(source).ok())
                    .unwrap_or("");

                // Text predicate: System.out.print*
                if sys_text != "System" || out_text != "out" || !method_text.starts_with("print") {
                    continue;
                }

                let Some(call_cap) = m
                    .captures
                    .iter()
                    .find(|c| cap_names[c.index as usize] == "sysout_call")
                else {
                    continue;
                };
                findings.push(SlopFinding {
                    start_byte: call_cap.node.start_byte(),
                    end_byte: call_cap.node.end_byte(),
                    description: format!(
                        "System.out.{method_text}: console debug logging in production — \
                         use a structured logger (SLF4J, Log4j, etc.)"
                    ),
                    domain: DOMAIN_FIRST_PARTY,
                });
            }
            _ => {}
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// C#: async void methods
// ---------------------------------------------------------------------------

fn find_csharp_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.csharp_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&eng.csharp_query, tree.root_node(), source);
    let cap_names = eng.csharp_query.capture_names();

    let mut findings = Vec::new();

    while let Some(m) = matches.next() {
        let Some(cap) = m
            .captures
            .iter()
            .find(|c| cap_names[c.index as usize] == "async_void_method")
        else {
            continue;
        };

        // Text-level predicate: method text must contain "async " AND " void "
        // (checks both modifier and return type without relying on grammar field names).
        let node_text = cap.node.utf8_text(source).unwrap_or("");
        if !node_text.contains("async ") {
            continue;
        }
        // Detect void return type: " void " between modifier list and method name.
        // Simple substring check is safe because "void" as a return type always has
        // surrounding whitespace in C# syntax.
        if !node_text.contains(" void ") && !node_text.starts_with("void ") {
            continue;
        }

        // Extract the method name for a useful error message.
        let method_name = find_method_name(cap.node, source);
        findings.push(SlopFinding {
            start_byte: cap.node.start_byte(),
            end_byte: cap.node.end_byte(),
            description: format!(
                "async void method `{method_name}`: unhandled exceptions crash the process — \
                 use async Task instead (or async void only for event handlers)"
            ),
            domain: DOMAIN_FIRST_PARTY,
        });
    }

    findings
}

/// Walk a method_declaration node to extract the method name identifier.
fn find_method_name(node: Node<'_>, source: &[u8]) -> String {
    // tree-sitter-c-sharp: method_declaration has a `name` field (identifier).
    if let Some(name_node) = node.child_by_field_name("name") {
        if let Ok(text) = name_node.utf8_text(source) {
            return text.to_string();
        }
    }
    // Fallback: walk direct children for the first identifier.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        if child.kind() == "identifier" {
            if let Ok(text) = child.utf8_text(source) {
                return text.to_string();
            }
        }
    }
    "<unknown>".to_string()
}

// ---------------------------------------------------------------------------
// C++: raw new / delete
// ---------------------------------------------------------------------------

fn find_cpp_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.cpp_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&eng.cpp_query, tree.root_node(), source);
    let cap_names = eng.cpp_query.capture_names();

    let mut findings = Vec::new();

    while let Some(m) = matches.next() {
        for cap in m.captures.iter() {
            let description = match cap_names[cap.index as usize] {
                "raw_new" => {
                    "Raw `new`: prefer std::make_unique<T>() or std::make_shared<T>() \
                              for exception-safe RAII ownership"
                }
                "raw_delete" => {
                    "Raw `delete`: manual memory management is error-prone — \
                                 let unique_ptr/shared_ptr handle deallocation"
                }
                _ => continue,
            };
            findings.push(SlopFinding {
                start_byte: cap.node.start_byte(),
                end_byte: cap.node.end_byte(),
                description: description.to_string(),
                domain: DOMAIN_FIRST_PARTY,
            });
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Bash: unquoted variable expansions
// ---------------------------------------------------------------------------

fn find_bash_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.bash_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(&eng.bash_query, tree.root_node(), source);
    let cap_names = eng.bash_query.capture_names();

    let mut findings = Vec::new();

    while let Some(m) = matches.next() {
        let Some(cap) = m
            .captures
            .iter()
            .find(|c| cap_names[c.index as usize] == "unquoted_var")
        else {
            continue;
        };

        let var_text = cap
            .node
            .utf8_text(source)
            .unwrap_or("$VAR")
            .trim_start_matches('$')
            .trim_start_matches('{')
            .trim_end_matches('}');

        findings.push(SlopFinding {
            start_byte: cap.node.start_byte(),
            end_byte: cap.node.end_byte(),
            description: format!(
                "Unquoted variable `${var_text}`: subject to word splitting and glob expansion — \
                 quote it: \"${var_text}\""
            ),
            domain: DOMAIN_FIRST_PARTY,
        });
    }

    findings
}

// ---------------------------------------------------------------------------
// JavaScript / TypeScript: eval() call detection
// ---------------------------------------------------------------------------

/// Detect `eval()` calls in JavaScript/JSX source.
fn find_javascript_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: skip files that don't contain "eval".
    if !source.windows(4).any(|w| w == b"eval") {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.js_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    find_eval_calls(tree.root_node(), source, &mut findings);
    findings
}

/// Detect `eval()` calls in TypeScript/TSX source.
///
/// `tsx` selects the TSX grammar variant (required for `.tsx` files that
/// contain JSX syntax).
fn find_typescript_slop(eng: &QueryEngine, source: &[u8], tsx: bool) -> Vec<SlopFinding> {
    if !source.windows(4).any(|w| w == b"eval") {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    let lang = if tsx { &eng.tsx_lang } else { &eng.ts_lang };
    if parser.set_language(lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    find_eval_calls(tree.root_node(), source, &mut findings);
    findings
}

/// Walk the AST and report every `call_expression` whose function is the
/// bare identifier `eval`.
fn find_eval_calls(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" && func.utf8_text(source).ok() == Some("eval") {
                findings.push(SlopFinding {
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                    description: "eval() call: executes arbitrary code from a string — \
                                  code injection risk; use JSON.parse() or a safe alternative"
                        .to_string(),
                    domain: DOMAIN_FIRST_PARTY,
                });
                return; // don't recurse into the eval call itself
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_eval_calls(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// C: banned libc functions
// ---------------------------------------------------------------------------

/// Detect calls to dangerous libc functions (`gets`) in C/C-header source.
fn find_c_slop(eng: &QueryEngine, source: &[u8]) -> Vec<SlopFinding> {
    // Fast pre-filter: must contain "gets".
    if !source.windows(4).any(|w| w == b"gets") {
        return Vec::new();
    }
    let mut parser = tree_sitter::Parser::new();
    if parser.set_language(&eng.c_lang).is_err() {
        return Vec::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return Vec::new();
    };
    let mut findings = Vec::new();
    find_banned_c_calls(tree.root_node(), source, &mut findings);
    findings
}

/// Walk the C AST reporting calls to functions banned by C11 / CERT-C.
fn find_banned_c_calls(node: Node<'_>, source: &[u8], findings: &mut Vec<SlopFinding>) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                if let Ok(name) = func.utf8_text(source) {
                    let desc = match name {
                        "gets" => Some(
                            "gets(): removed in C11 — performs unbounded buffer read; \
                             use fgets(buf, sizeof(buf), stdin) instead",
                        ),
                        _ => None,
                    };
                    if let Some(d) = desc {
                        findings.push(SlopFinding {
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                            description: d.to_string(),
                            domain: DOMAIN_FIRST_PARTY,
                        });
                        return;
                    }
                }
            }
        }
    }
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        find_banned_c_calls(child, source, findings);
    }
}

// ---------------------------------------------------------------------------
// HCL / Terraform: open-world CIDR detection (byte-scan, no grammar needed)
// ---------------------------------------------------------------------------

/// Detect wildcard CIDR `0.0.0.0/0` inside a security-group context in HCL.
///
/// Uses a byte-level scan rather than tree-sitter parsing to avoid a grammar
/// dependency in forge — the signal is unambiguous enough to not require AST
/// structure.  A finding is only emitted when the file also contains an
/// ingress/security-group marker, reducing false positives on non-IaC TOML.
fn find_hcl_slop(source: &[u8]) -> Vec<SlopFinding> {
    const WILDCARD: &[u8] = b"0.0.0.0/0";
    if !source.windows(WILDCARD.len()).any(|w| w == WILDCARD) {
        return Vec::new();
    }

    // Require a security-group context — reduces false positives on health-check IPs.
    const SECURITY_MARKERS: &[&[u8]] = &[
        b"ingress",
        b"security_group",
        b"aws_security_group",
        b"cidr_blocks",
    ];
    let has_context = SECURITY_MARKERS
        .iter()
        .any(|m| source.windows(m.len()).any(|w| w == *m));
    if !has_context {
        return Vec::new();
    }

    // Report each occurrence.
    source
        .windows(WILDCARD.len())
        .enumerate()
        .filter(|(_, w)| *w == WILDCARD)
        .map(|(i, _)| SlopFinding {
            start_byte: i,
            end_byte: i + WILDCARD.len(),
            description: "Open CIDR `0.0.0.0/0` in security group rule: \
                          exposes resource to the entire internet — \
                          restrict to specific IP ranges"
                .to_string(),
            domain: DOMAIN_ALL,
        })
        .collect()
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
            "used import should not be flagged, got: {findings:?}"
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

    #[test]
    fn test_yaml_virtualservice_wildcard_host_detected() {
        let src = b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - \"*\"
  gateways:
  - bookinfo-gateway
";
        let findings = find_slop("yaml", src);
        assert!(
            !findings.is_empty(),
            "VirtualService with wildcard host must be detected"
        );
        assert!(findings[0].description.contains("VirtualService"));
    }

    #[test]
    fn test_yaml_explicit_host_not_flagged() {
        let src = b"\
apiVersion: networking.istio.io/v1alpha3
kind: VirtualService
metadata:
  name: bookinfo
spec:
  hosts:
  - bookinfo.example.com
";
        let findings = find_slop("yaml", src);
        assert!(
            findings.is_empty(),
            "VirtualService with explicit host must not be flagged"
        );
    }

    // -----------------------------------------------------------------------
    // Java tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_java_empty_catch_detected() {
        let src = b"\
class Foo {
    void bar() {
        try {
            riskyOp();
        } catch (Exception e) {}
    }
}
";
        let findings = find_slop("java", src);
        assert!(
            !findings.is_empty(),
            "empty catch block must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("catch"));
    }

    #[test]
    fn test_java_non_empty_catch_not_flagged() {
        let src = b"\
class Foo {
    void bar() {
        try {
            riskyOp();
        } catch (Exception e) {
            logger.error(\"oops\", e);
        }
    }
}
";
        let findings = find_slop("java", src);
        // No empty-catch finding; may still get sysout — filter for catch type.
        let catch_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.description.contains("catch"))
            .collect();
        assert!(
            catch_findings.is_empty(),
            "non-empty catch must not be flagged, got: {catch_findings:?}"
        );
    }

    #[test]
    fn test_java_sysout_detected() {
        let src = b"\
class Foo {
    void bar() {
        System.out.println(\"debug info\");
    }
}
";
        let findings = find_slop("java", src);
        assert!(
            !findings.is_empty(),
            "System.out.println must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("System.out"));
    }

    // -----------------------------------------------------------------------
    // C# tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_csharp_async_void_detected() {
        let src = b"\
public class Handler {
    public async void ProcessMessage(string msg) {
        await Task.Delay(100);
    }
}
";
        let findings = find_slop("cs", src);
        assert!(
            !findings.is_empty(),
            "async void method must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("async void"));
    }

    #[test]
    fn test_csharp_async_task_not_flagged() {
        let src = b"\
public class Handler {
    public async Task ProcessMessage(string msg) {
        await Task.Delay(100);
    }
}
";
        let findings = find_slop("cs", src);
        assert!(
            findings.is_empty(),
            "async Task method must not be flagged: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // C++ tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_cpp_raw_new_detected() {
        let src = b"\
#include <string>
void foo() {
    std::string* s = new std::string(\"hello\");
    delete s;
}
";
        let findings = find_slop("cpp", src);
        let new_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.description.contains("new"))
            .collect();
        assert!(
            !new_findings.is_empty(),
            "raw new must be detected: {findings:?}"
        );
    }

    #[test]
    fn test_cpp_raw_delete_detected() {
        let src = b"\
void foo(int* p) {
    delete p;
}
";
        let findings = find_slop("cpp", src);
        let del_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.description.contains("delete"))
            .collect();
        assert!(
            !del_findings.is_empty(),
            "raw delete must be detected: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Bash tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_bash_unquoted_var_detected() {
        let src = b"rm -rf $TARGET_DIR\n";
        let findings = find_slop("sh", src);
        assert!(
            !findings.is_empty(),
            "unquoted $TARGET_DIR must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("TARGET_DIR"));
    }

    #[test]
    fn test_bash_quoted_var_not_flagged() {
        let src = b"rm -rf \"$TARGET_DIR\"\n";
        let findings = find_slop("sh", src);
        assert!(
            findings.is_empty(),
            "quoted variable must not be flagged: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // JavaScript / TypeScript tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_js_eval_detected() {
        let src = b"const result = eval(userInput);\n";
        let findings = find_slop("js", src);
        assert!(
            !findings.is_empty(),
            "eval() call in JS must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("eval()"));
    }

    #[test]
    fn test_js_no_eval_not_flagged() {
        let src = b"const x = JSON.parse(userInput);\n";
        let findings = find_slop("js", src);
        assert!(
            findings.is_empty(),
            "JSON.parse is safe — must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_jsx_eval_detected() {
        let src = b"function App() { return <div>{eval(code)}</div>; }\n";
        let findings = find_slop("jsx", src);
        assert!(
            !findings.is_empty(),
            "eval() in JSX must be detected: {findings:?}"
        );
    }

    #[test]
    fn test_ts_eval_detected() {
        let src = b"const r: string = eval(s);\n";
        let findings = find_slop("ts", src);
        assert!(
            !findings.is_empty(),
            "eval() in TypeScript must be detected: {findings:?}"
        );
    }

    #[test]
    fn test_ts_no_eval_not_flagged() {
        let src = b"const x: number = parseInt(s, 10);\n";
        let findings = find_slop("ts", src);
        assert!(
            findings.is_empty(),
            "clean TS must not be flagged: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // C tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_c_gets_detected() {
        let src = b"#include <stdio.h>\nint main() { char buf[64]; gets(buf); return 0; }\n";
        let findings = find_slop("c", src);
        assert!(
            !findings.is_empty(),
            "gets() call in C must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("gets()"));
    }

    #[test]
    fn test_c_fgets_not_flagged() {
        let src =
            b"#include <stdio.h>\nint main() { char buf[64]; fgets(buf, sizeof(buf), stdin); return 0; }\n";
        let findings = find_slop("c", src);
        assert!(
            findings.is_empty(),
            "fgets() is safe — must not be flagged: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // HCL / Terraform tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_hcl_open_cidr_in_security_group_detected() {
        let src = b"\
resource \"aws_security_group_rule\" \"allow_all\" {
  type        = \"ingress\"
  cidr_blocks = [\"0.0.0.0/0\"]
  from_port   = 0
  to_port     = 65535
  protocol    = \"-1\"
}
";
        let findings = find_slop("tf", src);
        assert!(
            !findings.is_empty(),
            "wildcard CIDR in security group must be detected: {findings:?}"
        );
        assert!(findings[0].description.contains("0.0.0.0/0"));
    }

    #[test]
    fn test_hcl_restricted_cidr_not_flagged() {
        let src = b"\
resource \"aws_security_group_rule\" \"office_only\" {
  type        = \"ingress\"
  cidr_blocks = [\"10.0.0.0/8\"]
  from_port   = 443
  to_port     = 443
  protocol    = \"tcp\"
}
";
        let findings = find_slop("tf", src);
        assert!(
            findings.is_empty(),
            "restricted CIDR must not be flagged: {findings:?}"
        );
    }

    #[test]
    fn test_hcl_wildcard_cidr_without_security_context_not_flagged() {
        // 0.0.0.0/0 alone (e.g., in a route table default route) is not flagged
        // without an ingress/security_group context marker.
        let src = b"destination_cidr_block = \"0.0.0.0/0\"\n";
        let findings = find_slop("tf", src);
        assert!(
            findings.is_empty(),
            "wildcard CIDR without security context must not be flagged: {findings:?}"
        );
    }
}
