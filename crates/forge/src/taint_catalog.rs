//! Zero-copy taint catalog I/O (P0-1 Cross-File Spine, Phase 3).
//!
//! Persists [`TaintExportRecord`] entries to `.janitor/taint_catalog.rkyv`
//! using rkyv zero-copy serialization + memmap2 for O(1)-memory reads.
//!
//! ## Budget constraint
//! The catalog must remain under 10 MB on disk.  [`write_catalog`] enforces
//! this by truncating the oldest entries when the budget would be exceeded.
//!
//! ## 8 GB Law compliance
//! The READ path ([`CatalogView`]) never copies the catalog to the heap —
//! the memory-mapped file is the sole backing store.  All lookups operate
//! directly on the archived bytes.  The WRITE path allocates only the new
//! serialized payload; no gratuitous in-memory duplication occurs.
//!
//! ## Cross-file detection
//! [`scan_cross_file_sinks`] walks the tree-sitter AST of an added source
//! fragment and flags any call site whose callee appears in the catalog with
//! non-empty `sink_kinds`.  Supported languages: Python, JavaScript/JSX, Java.
//! Returns an empty vec for unsupported languages or when no catalog is loaded.

use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use anyhow::Result;
use memmap2::Mmap;
use tree_sitter::Node;

use common::taint::TaintExportRecord;

/// Maximum on-disk size of the taint catalog (10 MiB).
const CATALOG_BUDGET_BYTES: usize = 10 * 1024 * 1024;

/// Archived form of the catalog: a `Vec<TaintExportRecord>`.
type ArchivedCatalog = rkyv::Archived<Vec<TaintExportRecord>>;

// ─────────────────────────────────────────────────────────────────────────────
// CatalogView — zero-copy read-only handle
// ─────────────────────────────────────────────────────────────────────────────

/// Zero-copy read-only view of the persisted taint catalog.
///
/// The memory-mapped file is kept alive for the lifetime of this struct.
/// All lookups scan the archived bytes linearly — O(N) but heap-allocation-free.
pub struct CatalogView {
    _mmap: Mmap,
}

impl CatalogView {
    /// Memory-map the catalog file at `path`.
    ///
    /// Returns `None` when the file does not exist, is empty, or contains
    /// invalid rkyv data.  Callers must treat `None` as "catalog unavailable"
    /// and proceed without cross-file taint analysis.
    pub fn open(path: &Path) -> Option<Self> {
        if !path.exists() {
            return None;
        }
        let file = File::open(path).ok()?;
        let mmap = unsafe { Mmap::map(&file).ok()? };
        if mmap.is_empty() {
            return None;
        }
        // Structural validation — rejects corrupt or truncated archives.
        rkyv::access::<ArchivedCatalog, rkyv::rancor::Error>(&mmap[..]).ok()?;
        Some(Self { _mmap: mmap })
    }

    /// Returns a zero-copy reference to the archived record vec.
    ///
    /// # Safety
    /// The mmap is valid and the rkyv structure was validated in [`open`].
    /// `access_unchecked` is safe here because open ran a full structural
    /// validation before constructing `Self`.
    fn archived(&self) -> &ArchivedCatalog {
        unsafe { rkyv::access_unchecked::<ArchivedCatalog>(&self._mmap[..]) }
    }

    /// Returns `true` if any catalog record for `symbol_name` has non-empty
    /// `sink_kinds` — indicating the function reaches a dangerous sink.
    ///
    /// O(N) linear scan — allocation-free.
    pub fn has_sink(&self, symbol_name: &str) -> bool {
        self.archived()
            .iter()
            .any(|r| r.symbol_name == symbol_name && !r.sink_kinds.is_empty())
    }

    /// Returns `true` if any catalog record for `symbol_name` propagates taint
    /// through its return value.
    ///
    /// O(N) linear scan — allocation-free.
    pub fn propagates_taint(&self, symbol_name: &str) -> bool {
        self.archived()
            .iter()
            .any(|r| r.symbol_name == symbol_name && r.propagates_to_return)
    }

    /// Returns `true` if the catalog contains at least one record.
    pub fn is_empty(&self) -> bool {
        self.archived().is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Write path — serialise and persist
// ─────────────────────────────────────────────────────────────────────────────

/// Atomically write `records` to `catalog_path` in rkyv format.
///
/// Enforces the 10 MiB budget by dropping the oldest entries until the
/// serialized payload fits.  Uses a `.tmp` → rename atomic write so a
/// concurrent reader never sees a partial file.
pub fn write_catalog(catalog_path: &Path, records: &[TaintExportRecord]) -> Result<()> {
    if let Some(parent) = catalog_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Trim oldest entries if the serialized size would exceed the budget.
    // rkyv::to_bytes requires a Sized concrete type; clone to a Vec for serialization.
    let mut trimmed: Vec<TaintExportRecord> = records.to_vec();
    loop {
        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&trimmed)
            .map_err(|e| anyhow::anyhow!("rkyv serialize catalog: {e}"))?;
        if bytes.len() <= CATALOG_BUDGET_BYTES || trimmed.is_empty() {
            let tmp = catalog_path.with_extension("rkyv.tmp");
            {
                let mut f = File::create(&tmp)?;
                f.write_all(&bytes)?;
                f.flush()?;
            }
            fs::rename(&tmp, catalog_path).inspect_err(|_| {
                let _ = fs::remove_file(&tmp);
            })?;
            return Ok(());
        }
        // Drop the first (oldest) entry.
        trimmed.remove(0);
    }
}

/// Append a single record to the catalog, maintaining the 10 MiB budget.
///
/// Reads any existing records, appends `record`, then writes the result back.
/// This is an O(N) operation on the existing catalog size; callers should
/// batch writes where possible.
pub fn append_record(catalog_path: &Path, record: TaintExportRecord) -> Result<()> {
    let mut records: Vec<TaintExportRecord> = if catalog_path.exists() {
        File::open(catalog_path)
            .ok()
            .and_then(|f| {
                let mmap = unsafe { Mmap::map(&f).ok()? };
                if mmap.is_empty() {
                    return Some(vec![]);
                }
                rkyv::access::<ArchivedCatalog, rkyv::rancor::Error>(&mmap[..])
                    .ok()
                    .map(|archived| {
                        rkyv::deserialize::<Vec<TaintExportRecord>, rkyv::rancor::Error>(archived)
                            .unwrap_or_default()
                    })
            })
            .unwrap_or_default()
    } else {
        vec![]
    };
    records.push(record);
    write_catalog(catalog_path, &records)
}

// ─────────────────────────────────────────────────────────────────────────────
// Cross-file sink finding
// ─────────────────────────────────────────────────────────────────────────────

/// A confirmed cross-file taint sink found in the added source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrossFileSinkFinding {
    /// Name of the callee function whose catalog entry confirms a sink.
    pub callee_name: String,
    /// Start byte of the call expression in the added source.
    pub start_byte: usize,
    /// End byte of the call expression in the added source.
    pub end_byte: usize,
}

/// Scan `source` (already parsed into `tree`) for calls to cataloged sink functions.
///
/// Returns a [`CrossFileSinkFinding`] for each call site where:
/// 1. The callee name matches a [`CatalogView`] entry with non-empty `sink_kinds`.
/// 2. At least one argument is potentially tainted (non-literal expression).
///
/// Supported languages: `"py"`, `"js"`, `"jsx"`, `"ts"`, `"tsx"`, `"java"`, `"go"`.
/// Returns an empty vec for unsupported languages (fail-open).
///
/// ## 3-hop budget
/// Catalog entries are themselves the product of up to 3-hop analysis: a
/// record present in the catalog confirms that the callee transitively reaches
/// a sink within the 3-hop propagation window.  This function enforces the
/// hop budget by checking only one level of call depth against the catalog —
/// the catalog records handle the remaining hops.
pub fn scan_cross_file_sinks(
    lang: &str,
    source: &[u8],
    tree: &tree_sitter::Tree,
    catalog: &CatalogView,
) -> Vec<CrossFileSinkFinding> {
    if catalog.is_empty() {
        return vec![];
    }
    match lang {
        "py" => scan_python(source, tree.root_node(), catalog),
        "js" | "jsx" => scan_js(source, tree.root_node(), catalog),
        // TypeScript uses identical call_expression / arguments node structure to JS.
        "ts" | "tsx" => scan_ts(source, tree.root_node(), catalog),
        "java" => scan_java(source, tree.root_node(), catalog),
        "go" => scan_go(source, tree.root_node(), catalog),
        _ => vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Python — `call` nodes with `identifier` function
// ─────────────────────────────────────────────────────────────────────────────

fn scan_python(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_python_calls(root, source, catalog, &mut out);
    out
}

fn walk_python_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
) {
    if node.kind() == "call" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let callee = func.utf8_text(source).unwrap_or("");
                if catalog.has_sink(callee) {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if has_nontrivial_arg_python(args, source) {
                            out.push(CrossFileSinkFinding {
                                callee_name: callee.to_string(),
                                start_byte: node.start_byte(),
                                end_byte: node.end_byte(),
                            });
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_python_calls(child, source, catalog, out);
    }
}

/// Returns `true` when the argument list contains at least one non-literal child.
///
/// Python literal node kinds: `"string"`, `"integer"`, `"float"`, `"true"`,
/// `"false"`, `"none"`.  Everything else — identifiers, subscripts, attribute
/// accesses, nested calls — is treated as potentially tainted.
fn has_nontrivial_arg_python(args_node: Node<'_>, source: &[u8]) -> bool {
    const PY_LITERAL_KINDS: &[&str] = &[
        "string",
        "integer",
        "float",
        "true",
        "false",
        "none",
        "concatenated_string",
    ];
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        if !PY_LITERAL_KINDS.contains(&child.kind()) {
            // Named arguments (keyword=value) carry a `value` field — check that.
            if child.kind() == "keyword_argument" {
                if let Some(val) = child.child_by_field_name("value") {
                    if !PY_LITERAL_KINDS.contains(&val.kind()) {
                        let _ = source; // suppress unused warning
                        return true;
                    }
                }
            } else {
                return true;
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// JavaScript / JSX — `call_expression` nodes with `identifier` function
// ─────────────────────────────────────────────────────────────────────────────

fn scan_js(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_js_calls(root, source, catalog, &mut out);
    out
}

fn walk_js_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let callee = func.utf8_text(source).unwrap_or("");
                if catalog.has_sink(callee) {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if has_nontrivial_arg_js(args, source) {
                            out.push(CrossFileSinkFinding {
                                callee_name: callee.to_string(),
                                start_byte: node.start_byte(),
                                end_byte: node.end_byte(),
                            });
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_js_calls(child, source, catalog, out);
    }
}

/// Returns `true` when the JS `arguments` node contains at least one non-literal arg.
///
/// JS literal kinds: `"string"`, `"number"`, `"true"`, `"false"`, `"null"`,
/// `"undefined"`, `"template_string"` (without substitution).
fn has_nontrivial_arg_js(args_node: Node<'_>, source: &[u8]) -> bool {
    const JS_LITERAL_KINDS: &[&str] = &["string", "number", "true", "false", "null", "undefined"];
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        let kind = child.kind();
        if kind == "template_string" {
            // template strings without substitutions are safe literals.
            let text = child.utf8_text(source).unwrap_or("");
            if !text.contains("${") {
                continue;
            }
            return true;
        }
        if !JS_LITERAL_KINDS.contains(&kind) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Java — `method_invocation` nodes
// ─────────────────────────────────────────────────────────────────────────────

fn scan_java(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_java_calls(root, source, catalog, &mut out);
    out
}

fn walk_java_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
) {
    if node.kind() == "method_invocation" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let callee = name_node.utf8_text(source).unwrap_or("");
            if catalog.has_sink(callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_java(args, source) {
                        out.push(CrossFileSinkFinding {
                            callee_name: callee.to_string(),
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                        });
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_java_calls(child, source, catalog, out);
    }
}

/// Returns `true` when the Java argument list contains at least one non-literal.
///
/// Java literal kinds: `"string_literal"`, `"decimal_integer_literal"`,
/// `"hex_integer_literal"`, `"null_literal"`, `"true"`, `"false"`.
fn has_nontrivial_arg_java(args_node: Node<'_>, source: &[u8]) -> bool {
    const JAVA_LITERAL_KINDS: &[&str] = &[
        "string_literal",
        "decimal_integer_literal",
        "hex_integer_literal",
        "null_literal",
        "true",
        "false",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        if !JAVA_LITERAL_KINDS.contains(&child.kind()) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// TypeScript / TSX — same call_expression structure as JavaScript
// ─────────────────────────────────────────────────────────────────────────────

/// TypeScript cross-file sink scanner.
///
/// Tree-sitter-typescript uses the same `call_expression` / `identifier` /
/// `arguments` node structure as tree-sitter-javascript, so the scan logic is
/// identical.  Both `"ts"` and `"tsx"` dispatch here.
fn scan_ts(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_ts_calls(root, source, catalog, &mut out);
    out
}

fn walk_ts_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "identifier" {
                let callee = func.utf8_text(source).unwrap_or("");
                if catalog.has_sink(callee) {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if has_nontrivial_arg_js(args, source) {
                            out.push(CrossFileSinkFinding {
                                callee_name: callee.to_string(),
                                start_byte: node.start_byte(),
                                end_byte: node.end_byte(),
                            });
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_ts_calls(child, source, catalog, out);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Go — call_expression with identifier or selector_expression.field function
// ─────────────────────────────────────────────────────────────────────────────

/// Go cross-file sink scanner.
///
/// Detects two call forms:
/// - Bare identifier: `buildSQL(userInput)` — `call_expression` where `function`
///   is an `identifier`.
/// - Selector: `helper.buildSQL(userInput)` — `call_expression` where `function`
///   is a `selector_expression`; the callee name is the `field` child.
///
/// Argument taint check uses Go literal kinds: `"interpreted_string_literal"`,
/// `"raw_string_literal"`, `"int_literal"`, `"float_literal"`, `"true"`,
/// `"false"`, `"nil"`.
fn scan_go(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_go_calls(root, source, catalog, &mut out);
    out
}

fn walk_go_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
) {
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let callee = match func.kind() {
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "selector_expression" => func
                    .child_by_field_name("field")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_go(args, source) {
                        out.push(CrossFileSinkFinding {
                            callee_name: callee,
                            start_byte: node.start_byte(),
                            end_byte: node.end_byte(),
                        });
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_go_calls(child, source, catalog, out);
    }
}

/// Returns `true` when the Go `argument_list` node contains at least one non-literal arg.
///
/// Go literal node kinds: `"interpreted_string_literal"`, `"raw_string_literal"`,
/// `"int_literal"`, `"float_literal"`, `"rune_literal"`, `"true"`, `"false"`, `"nil"`.
fn has_nontrivial_arg_go(args_node: Node<'_>, source: &[u8]) -> bool {
    const GO_LITERAL_KINDS: &[&str] = &[
        "interpreted_string_literal",
        "raw_string_literal",
        "int_literal",
        "float_literal",
        "rune_literal",
        "true",
        "false",
        "nil",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        if !GO_LITERAL_KINDS.contains(&child.kind()) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use common::taint::{TaintKind, TaintedParam};

    fn make_record(symbol_name: &str, sink: bool) -> TaintExportRecord {
        TaintExportRecord {
            symbol_name: symbol_name.to_string(),
            file_path: "helpers.py".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "user_input".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: if sink {
                vec![TaintKind::DatabaseResult]
            } else {
                vec![]
            },
            propagates_to_return: true,
        }
    }

    fn tmp_catalog_path() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("taint_catalog.rkyv");
        (dir, path)
    }

    #[test]
    fn write_and_open_catalog_roundtrip() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("build_query", true)];
        write_catalog(&path, &records).expect("write");
        let view = CatalogView::open(&path).expect("open");
        assert!(!view.is_empty());
        assert!(view.has_sink("build_query"));
        assert!(!view.has_sink("unknown_fn"));
    }

    #[test]
    fn no_sink_record_does_not_fire() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("safe_helper", false)];
        write_catalog(&path, &records).expect("write");
        let view = CatalogView::open(&path).expect("open");
        assert!(!view.has_sink("safe_helper"));
    }

    #[test]
    fn catalog_open_returns_none_for_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("nonexistent.rkyv");
        assert!(CatalogView::open(&path).is_none());
    }

    #[test]
    fn append_record_accumulates() {
        let (_dir, path) = tmp_catalog_path();
        append_record(&path, make_record("fn_a", true)).expect("append a");
        append_record(&path, make_record("fn_b", true)).expect("append b");
        let view = CatalogView::open(&path).expect("open");
        assert!(view.has_sink("fn_a"));
        assert!(view.has_sink("fn_b"));
    }

    fn parse_python(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    fn parse_typescript(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    fn parse_go(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    #[test]
    fn python_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("build_query", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "result = db.execute(build_query(user_id))\n";
        let tree = parse_python(src);
        let findings = scan_cross_file_sinks("py", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "build_query");
    }

    #[test]
    fn python_cross_file_sink_silent_for_literal_arg() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("build_query", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "result = db.execute(build_query(\"static-value\"))\n";
        let tree = parse_python(src);
        let findings = scan_cross_file_sinks("py", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "literal arg must not emit cross-file taint finding"
        );
    }

    #[test]
    fn python_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("other_fn", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "result = uncataloged_func(user_id)\n";
        let tree = parse_python(src);
        let findings = scan_cross_file_sinks("py", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged function must not produce cross-file finding"
        );
    }

    // ── TypeScript cross-file taint ─────────────────────────────────────────

    /// True positive: TS diff calls a cataloged sink helper with a non-literal arg.
    #[test]
    fn typescript_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("buildQuery", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "const result = db.execute(buildQuery(userId));\n";
        let tree = parse_typescript(src);
        let findings = scan_cross_file_sinks("ts", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "TypeScript cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "buildQuery");
    }

    /// True negative: TS diff calls a function not in the catalog — must be silent.
    #[test]
    fn typescript_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousHelper", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "const result = safeTransform(data);\n";
        let tree = parse_typescript(src);
        let findings = scan_cross_file_sinks("ts", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged TypeScript function must not produce cross-file finding"
        );
    }

    /// True negative: TS diff calls cataloged sink with a literal arg — must be silent.
    #[test]
    fn typescript_cross_file_sink_silent_for_literal_arg() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("buildQuery", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "const result = buildQuery(\"static-value\");\n";
        let tree = parse_typescript(src);
        let findings = scan_cross_file_sinks("ts", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "TypeScript literal arg must not emit cross-file taint finding"
        );
    }

    // ── Go cross-file taint ─────────────────────────────────────────────────

    /// True positive (bare identifier): Go diff calls a cataloged sink with a non-literal.
    #[test]
    fn go_cross_file_sink_fires_on_bare_identifier_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("buildQuery", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "package main\nfunc h(userID string) {\n    db.Exec(buildQuery(userID))\n}\n";
        let tree = parse_go(src);
        let findings = scan_cross_file_sinks("go", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Go cross-file taint must fire on cataloged bare-identifier callee"
        );
        assert_eq!(findings[0].callee_name, "buildQuery");
    }

    /// True positive (selector): Go diff calls `helper.BuildSQL(userID)` — must fire.
    #[test]
    fn go_cross_file_sink_fires_on_selector_expression_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("BuildSQL", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src =
            "package main\nfunc h(userID string) {\n    db.Query(helper.BuildSQL(userID))\n}\n";
        let tree = parse_go(src);
        let findings = scan_cross_file_sinks("go", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Go cross-file taint must fire on cataloged selector-expression callee"
        );
        assert_eq!(findings[0].callee_name, "BuildSQL");
    }

    /// True negative: Go diff calls uncataloged function — must be silent.
    #[test]
    fn go_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousHelper", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "package main\nfunc h(x string) {\n    safeTransform(x)\n}\n";
        let tree = parse_go(src);
        let findings = scan_cross_file_sinks("go", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged Go function must not produce cross-file finding"
        );
    }

    /// True negative: Go diff calls cataloged sink with a literal arg — must be silent.
    #[test]
    fn go_cross_file_sink_silent_for_literal_arg() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("buildQuery", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "package main\nfunc h() {\n    db.Exec(buildQuery(\"static\"))\n}\n";
        let tree = parse_go(src);
        let findings = scan_cross_file_sinks("go", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "Go literal arg must not emit cross-file taint finding"
        );
    }
}
