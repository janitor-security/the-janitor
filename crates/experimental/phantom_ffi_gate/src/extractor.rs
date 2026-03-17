//! Tree-sitter extraction of FFI symbol boundaries.
//!
//! ## C++ export patterns detected
//! 1. `extern "C" TYPE func(...);` — single-line linkage declaration.
//! 2. `extern "C" { TYPE func(...); }` — block-form linkage declarations.
//! 3. `m.def("symbol", &cpp_fn)` — pybind11 Python-visible registrations.
//!
//! ## Python call-site patterns detected
//! - `lib.symbol_name(...)` — ctypes/cffi attribute-style invocations.
//!   The caller is responsible for pre-filtering `lib` identifiers to only
//!   those obtained via `ctypes.CDLL`, `cffi.FFI.dlopen`, etc.

use anyhow::{bail, Result};
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator};

// ---------------------------------------------------------------------------
// Grammar accessors
// ---------------------------------------------------------------------------

fn cpp_language() -> Language {
    tree_sitter_cpp::LANGUAGE.into()
}

fn python_language() -> Language {
    tree_sitter_python::LANGUAGE.into()
}

// ---------------------------------------------------------------------------
// C++ extern "C" query
// ---------------------------------------------------------------------------

/// Captures function names inside `linkage_specification` nodes.
///
/// Two patterns handle the single-line and block forms respectively:
/// - `extern "C" void func(...);`  → `linkage_specification → declaration`
/// - `extern "C" { void func(); }` → `linkage_specification → declaration_list → declaration`
///
/// Only the simple `identifier` declarator is matched.  Pointer-typed
/// return values (`void* alloc(...)`) and qualified names are out-of-scope
/// for this prototype.
const EXTERN_C_QUERY: &str = r#"
(linkage_specification
  (declaration
    (function_declarator
      declarator: (identifier) @ffi.name)))

(linkage_specification
  (declaration_list
    (declaration
      (function_declarator
        declarator: (identifier) @ffi.name))))

(linkage_specification
  (function_definition
    declarator: (function_declarator
      declarator: (identifier) @ffi.name)))

(linkage_specification
  (declaration_list
    (function_definition
      declarator: (function_declarator
        declarator: (identifier) @ffi.name))))
"#;

/// Extract all C++ symbols exported via `extern "C"` linkage.
///
/// Parses `source` with the C++ grammar and captures every function
/// identifier declared inside a `linkage_specification` node.
///
/// Parser Error Neutrality: returns `Err` if the grammar fails; returns
/// an empty `Vec` if the AST contains parse errors (grammar version lag).
///
/// # Errors
/// Returns `Err` if the C++ grammar cannot be loaded or the query is
/// malformed.
pub fn extract_extern_c_symbols(source: &[u8]) -> Result<Vec<String>> {
    let mut parser = Parser::new();
    parser
        .set_language(&cpp_language())
        .map_err(|e| anyhow::anyhow!("C++ grammar load failed: {e}"))?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("C++ parser returned None"))?;

    if tree.root_node().has_error() {
        // Neutral: broken AST → caller gets empty list, not a false positive.
        return Ok(Vec::new());
    }

    let query = Query::new(&cpp_language(), EXTERN_C_QUERY)
        .map_err(|e| anyhow::anyhow!("extern C query compile failed: {e}"))?;
    let cap_names = query.capture_names();

    let mut cursor = QueryCursor::new();
    let mut qm = cursor.matches(&query, tree.root_node(), source);

    let mut symbols: Vec<String> = Vec::new();
    while let Some(m) = qm.next() {
        for cap in m.captures {
            if cap_names[cap.index as usize] == "ffi.name" {
                if let Ok(name) = cap.node.utf8_text(source) {
                    if !symbols.contains(&name.to_string()) {
                        symbols.push(name.to_string());
                    }
                }
            }
        }
    }
    Ok(symbols)
}

// ---------------------------------------------------------------------------
// pybind11 m.def query
// ---------------------------------------------------------------------------

/// Captures the first string argument of `m.def("name", ...)` call expressions.
///
/// The Python-visible symbol name is the first positional string argument —
/// subsequent arguments (the C++ function pointer, return-value policies,
/// docstring) are ignored.
const PYBIND11_DEF_QUERY: &str = r#"
(call_expression
  function: (field_expression
    field: (field_identifier) @_method)
  arguments: (argument_list
    (string_literal
      (string_content) @ffi.name)))
"#;

/// Extract Python-visible names registered via `pybind11`'s `m.def(...)`.
///
/// Parses the C++ source and captures every string literal that is the
/// first argument of a `.def(...)` call expression.  Parse errors are
/// tolerated (PYBIND11_MODULE macro expansion confuses some grammar versions)
/// — the function returns whatever matches were found before the error node.
///
/// # Errors
/// Returns `Err` if the C++ grammar cannot be loaded or the query is
/// malformed.
pub fn extract_pybind11_symbols(source: &[u8]) -> Result<Vec<String>> {
    let mut parser = Parser::new();
    parser
        .set_language(&cpp_language())
        .map_err(|e| anyhow::anyhow!("C++ grammar load failed: {e}"))?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("C++ parser returned None"))?;

    // Tolerate parse errors — macro expansion routinely confuses grammars.
    let query = Query::new(&cpp_language(), PYBIND11_DEF_QUERY)
        .map_err(|e| anyhow::anyhow!("pybind11 query compile failed: {e}"))?;
    let cap_names = query.capture_names();

    let mut cursor = QueryCursor::new();
    let mut qm = cursor.matches(&query, tree.root_node(), source);

    let mut symbols: Vec<String> = Vec::new();
    while let Some(m) = qm.next() {
        // Only process matches where the method field is literally "def".
        let method_is_def = m.captures.iter().any(|c| {
            cap_names[c.index as usize] == "_method" && c.node.utf8_text(source).ok() == Some("def")
        });
        if !method_is_def {
            continue;
        }
        // Take the first ffi.name capture (= first string argument).
        if let Some(cap) = m
            .captures
            .iter()
            .find(|c| cap_names[c.index as usize] == "ffi.name")
        {
            if let Ok(name) = cap.node.utf8_text(source) {
                if !symbols.contains(&name.to_string()) {
                    symbols.push(name.to_string());
                }
            }
        }
    }
    Ok(symbols)
}

// ---------------------------------------------------------------------------
// Python call-site extraction
// ---------------------------------------------------------------------------

/// Captures the attribute identifier from `obj.METHOD(...)` call expressions.
///
/// Returns every `METHOD` name from attribute-style calls.  The caller
/// filters this list against known ctypes/cffi library-handle variables.
/// Dunder methods (`__init__`, `__enter__`, etc.) are excluded — they are
/// never FFI symbols.
const PYTHON_ATTR_CALL_QUERY: &str = r#"
(call
  function: (attribute
    attribute: (identifier) @call.name))
"#;

/// Extract Python attribute-based function call names from `source`.
///
/// Returns every `name` from `obj.name(...)` expressions found in `source`.
/// Dunder methods are filtered out.  The caller is responsible for
/// correlating the returned names against known library-handle identifiers
/// to isolate genuine ctypes/cffi FFI call sites.
///
/// # Errors
/// Returns `Err` if the Python grammar cannot be loaded, the query is
/// malformed, or the source contains parse errors.
pub fn extract_python_ffi_calls(source: &[u8]) -> Result<Vec<String>> {
    let mut parser = Parser::new();
    parser
        .set_language(&python_language())
        .map_err(|e| anyhow::anyhow!("Python grammar load failed: {e}"))?;

    let tree = parser
        .parse(source, None)
        .ok_or_else(|| anyhow::anyhow!("Python parser returned None"))?;

    if tree.root_node().has_error() {
        bail!("Python source contains parse errors — aborting extraction");
    }

    let query = Query::new(&python_language(), PYTHON_ATTR_CALL_QUERY)
        .map_err(|e| anyhow::anyhow!("Python attr-call query compile failed: {e}"))?;
    let cap_names = query.capture_names();

    let mut cursor = QueryCursor::new();
    let mut qm = cursor.matches(&query, tree.root_node(), source);

    let mut calls: Vec<String> = Vec::new();
    while let Some(m) = qm.next() {
        for cap in m.captures {
            if cap_names[cap.index as usize] == "call.name" {
                if let Ok(name) = cap.node.utf8_text(source) {
                    // Dunder + lifecycle methods are never FFI call sites.
                    if !name.starts_with("__") && !calls.contains(&name.to_string()) {
                        calls.push(name.to_string());
                    }
                }
            }
        }
    }
    Ok(calls)
}
