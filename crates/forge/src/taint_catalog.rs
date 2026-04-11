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
///
/// A BLAKE3 hash of the raw catalog bytes is computed at open time and stored
/// so that callers can bind it into a [`common::receipt::DecisionCapsule`] for
/// cryptographic provenance — proving exactly which taint catalog state was
/// active when a bounce decision was sealed (CT-013).
pub struct CatalogView {
    _mmap: Mmap,
    /// BLAKE3 hex digest of the raw catalog bytes, computed at [`open`] time.
    catalog_hash: String,
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
        // CT-013: hash the raw catalog bytes so the decision capsule can seal this state.
        let catalog_hash = blake3::hash(&mmap[..]).to_hex().to_string();
        Some(Self {
            _mmap: mmap,
            catalog_hash,
        })
    }

    /// BLAKE3 hex digest of the raw catalog bytes, computed at open time.
    ///
    /// Bind this into [`common::receipt::DecisionCapsule::taint_catalog_hash`]
    /// to prove exactly which taint catalog state drove the bounce decision.
    pub fn catalog_hash(&self) -> &str {
        &self.catalog_hash
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
/// Supported languages: `"py"`, `"js"`, `"jsx"`, `"ts"`, `"tsx"`, `"java"`, `"go"`,
/// `"rb"`, `"php"`, `"cs"`, `"kt"`, `"kts"`, `"cpp"`, `"cxx"`, `"cc"`, `"h"`,
/// `"hpp"`, `"c"`, `"rs"`, `"swift"`, `"scala"`.
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
        "rb" => scan_ruby(source, tree.root_node(), catalog),
        "php" => scan_php(source, tree.root_node(), catalog),
        "cs" => scan_csharp(source, tree.root_node(), catalog),
        "kt" | "kts" => scan_kotlin(source, tree.root_node(), catalog),
        "cpp" | "cxx" | "cc" | "h" | "hpp" | "c" => scan_cpp(source, tree.root_node(), catalog),
        "rs" => scan_rust(source, tree.root_node(), catalog),
        "swift" => scan_swift(source, tree.root_node(), catalog),
        "scala" => scan_scala(source, tree.root_node(), catalog),
        _ => vec![],
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Python — `call` nodes with `identifier` function
// ─────────────────────────────────────────────────────────────────────────────

fn scan_python(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_python_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_python_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call" {
        if let Some(func) = node.child_by_field_name("function") {
            // CT-014: match both bare identifiers (`helper(arg)`) and attribute
            // calls (`self.helper(arg)`, `obj.db_helper(user_input)`).
            let callee: String = match func.kind() {
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "attribute" => func
                    .child_by_field_name("attribute")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_python(args, source) {
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
        walk_python_calls(child, source, catalog, out, depth + 1);
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
    walk_js_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_js_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            // CT-014: match bare identifiers (`sink(arg)`) and member-expression
            // call chains (`obj.sink(arg)`, `this.dangerousHelper(userInput)`).
            let callee: String = match func.kind() {
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "member_expression" => func
                    .child_by_field_name("property")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_js(args, source) {
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
        walk_js_calls(child, source, catalog, out, depth + 1);
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
    walk_java_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_java_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
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
        walk_java_calls(child, source, catalog, out, depth + 1);
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
    walk_ts_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_ts_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            // CT-014: match bare identifiers and member-expression call chains
            // (`this.queryRunner.execute(payload)`, `service.dangerousSink(arg)`).
            let callee: String = match func.kind() {
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "member_expression" => func
                    .child_by_field_name("property")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_js(args, source) {
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
        walk_ts_calls(child, source, catalog, out, depth + 1);
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
    walk_go_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_go_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
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
        walk_go_calls(child, source, catalog, out, depth + 1);
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
// Ruby — `call` nodes with `method` field
// ─────────────────────────────────────────────────────────────────────────────

/// Ruby cross-file sink scanner.
///
/// Detects `call` nodes (both `receiver.method(args)` and bare `method(args)`
/// forms).  The `method` field holds the callee identifier.  The `arguments`
/// field holds the `argument_list` node.
fn scan_ruby(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_ruby_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_ruby_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call" {
        if let Some(method_node) = node.child_by_field_name("method") {
            let callee = method_node.utf8_text(source).unwrap_or("").to_string();
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_ruby(args, source) {
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
        walk_ruby_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the Ruby `argument_list` contains at least one non-literal arg.
///
/// Ruby literal kinds: `"string"`, `"integer"`, `"float"`, `"true"`,
/// `"false"`, `"nil"`, `"symbol"`.
fn has_nontrivial_arg_ruby(args_node: Node<'_>, source: &[u8]) -> bool {
    const RUBY_LITERAL_KINDS: &[&str] = &[
        "string", "integer", "float", "true", "false", "nil", "symbol",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        if !RUBY_LITERAL_KINDS.contains(&child.kind()) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// PHP — `function_call_expression` (bare) and `member_call_expression` (chained)
// ─────────────────────────────────────────────────────────────────────────────

/// PHP cross-file sink scanner.
///
/// Detects two call forms:
/// - Bare: `dangerousSink($arg)` — `function_call_expression` with `function` field.
/// - Chained: `$obj->dangerousSink($arg)` — `member_call_expression` with `name` field.
///
/// PHP wraps each argument in an `argument` node.  The actual expression is
/// accessed via the `value` field of that wrapper (or its first named child).
/// String literals: `"string"`, `"encapsed_string"`.
fn scan_php(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_php_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_php_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    let callee: String = match node.kind() {
        "function_call_expression" => node
            .child_by_field_name("function")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("")
            .to_string(),
        "member_call_expression" | "static_method_call_expression" => node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    };
    if !callee.is_empty() && catalog.has_sink(&callee) {
        if let Some(args) = node.child_by_field_name("arguments") {
            if has_nontrivial_arg_php(args, source) {
                out.push(CrossFileSinkFinding {
                    callee_name: callee,
                    start_byte: node.start_byte(),
                    end_byte: node.end_byte(),
                });
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_php_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the PHP `argument_list` contains at least one non-literal arg.
///
/// PHP `argument_list` children are `argument` wrapper nodes; the expression
/// lives under the `value` field (or first named child).
/// PHP literal kinds: `"string"`, `"integer"`, `"float"`, `"true"`, `"false"`,
/// `"null"`, `"encapsed_string"`.
fn has_nontrivial_arg_php(args_node: Node<'_>, source: &[u8]) -> bool {
    const PHP_LITERAL_KINDS: &[&str] = &[
        "string",
        "integer",
        "float",
        "true",
        "false",
        "null",
        "encapsed_string",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        let expr_kind = if child.kind() == "argument" {
            // Unwrap one level: `value` field or first named child.
            child
                .child_by_field_name("value")
                .map(|v| v.kind())
                .or_else(|| child.named_child(0).map(|n| n.kind()))
                .unwrap_or(child.kind())
        } else {
            child.kind()
        };
        if !PHP_LITERAL_KINDS.contains(&expr_kind) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// C# — `invocation_expression` nodes
// ─────────────────────────────────────────────────────────────────────────────

/// C# cross-file sink scanner.
///
/// Detects `invocation_expression` nodes where the `function` field is:
/// - `identifier_name` — bare call: `DangerousSink(arg)`
/// - `member_access_expression` — chain: `obj.DangerousSink(arg)`, name from `name` field.
///
/// Argument list literal kinds: `"string_literal"`, `"verbatim_string_literal"`,
/// `"integer_literal"`, `"real_literal"`, `"character_literal"`, `"true"`,
/// `"false"`, `"null_literal"`.
fn scan_csharp(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_csharp_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_csharp_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "invocation_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let callee: String = match func.kind() {
                // tree-sitter-c-sharp 0.23.x uses `identifier` for bare identifiers.
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "member_access_expression" => func
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_csharp(args, source) {
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
        walk_csharp_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the C# `argument_list` contains at least one non-literal arg.
///
/// C# wraps arguments in `argument` nodes; the expression is the first named child.
fn has_nontrivial_arg_csharp(args_node: Node<'_>, source: &[u8]) -> bool {
    const CSHARP_LITERAL_KINDS: &[&str] = &[
        "string_literal",
        "verbatim_string_literal",
        "integer_literal",
        "real_literal",
        "character_literal",
        "true",
        "false",
        "null_literal",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        let expr_kind = if child.kind() == "argument" {
            child
                .named_child(0)
                .map(|n| n.kind())
                .unwrap_or(child.kind())
        } else {
            child.kind()
        };
        if !CSHARP_LITERAL_KINDS.contains(&expr_kind) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Kotlin — `call_expression` nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Kotlin cross-file sink scanner.
///
/// Detects `call_expression` nodes.  The callable is the first named child:
/// - `identifier` — bare call: `dangerousSink(arg)` (tree-sitter-kotlin-ng uses `identifier`)
/// - `navigation_expression` — chain: `obj.dangerousSink(arg)`, last `identifier` is callee.
///
/// Arguments are in a `value_arguments` child node.
fn scan_kotlin(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_kotlin_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_kotlin_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call_expression" {
        // Callable is first named child (`identifier` or `navigation_expression`).
        if let Some(func) = node.named_child(0) {
            let callee: String = match func.kind() {
                // tree-sitter-kotlin-ng uses `identifier` (not `simple_identifier`).
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "navigation_expression" => {
                    let count = func.named_child_count();
                    func.named_child(count.saturating_sub(1) as u32)
                        .filter(|n| n.kind() == "identifier")
                        .and_then(|n| n.utf8_text(source).ok())
                        .unwrap_or("")
                        .to_string()
                }
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                // value_arguments is the argument list; walk children to find it.
                let mut args_opt: Option<Node<'_>> = None;
                let mut c = node.walk();
                for child in node.children(&mut c) {
                    if child.kind() == "value_arguments" {
                        args_opt = Some(child);
                        break;
                    }
                }
                if let Some(args) = args_opt {
                    if has_nontrivial_arg_kotlin(args, source) {
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
        walk_kotlin_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the Kotlin `value_arguments` contains at least one non-literal.
///
/// `value_arguments` wraps each argument in a `value_argument` node.
/// Kotlin literal kinds: `"string_literal"`, `"integer_literal"`, `"real_literal"`,
/// `"long_literal"`, `"boolean_literal"`, `"character_literal"`, `"null"`.
fn has_nontrivial_arg_kotlin(args_node: Node<'_>, source: &[u8]) -> bool {
    const KOTLIN_LITERAL_KINDS: &[&str] = &[
        "string_literal",
        "integer_literal",
        "real_literal",
        "long_literal",
        "boolean_literal",
        "character_literal",
        "null",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        let expr_kind = if child.kind() == "value_argument" {
            child
                .named_child(0)
                .map(|n| n.kind())
                .unwrap_or(child.kind())
        } else {
            child.kind()
        };
        if !KOTLIN_LITERAL_KINDS.contains(&expr_kind) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// C/C++ — `call_expression` nodes
// ─────────────────────────────────────────────────────────────────────────────

/// C/C++ cross-file sink scanner.
///
/// Detects `call_expression` nodes.  The `function` field can be:
/// - `identifier` — bare call: `dangerous_sink(arg)`
/// - `field_expression` — `obj.dangerous_sink(arg)`, `field` child is callee.
/// - `scoped_identifier` — `ns::dangerous_sink(arg)`, `name` child is callee.
///
/// Argument literal kinds: `"number_literal"`, `"string_literal"`,
/// `"char_literal"`, `"true"`, `"false"`, `"null"`, `"nullptr"`.
fn scan_cpp(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_cpp_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_cpp_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let callee: String = match func.kind() {
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "field_expression" => func
                    .child_by_field_name("field")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                "scoped_identifier" => func
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_cpp(args, source) {
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
        walk_cpp_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the C/C++ `argument_list` contains at least one non-literal arg.
///
/// C/C++ literal kinds: `"number_literal"`, `"string_literal"`, `"char_literal"`,
/// `"system_lib_string"`, `"true"`, `"false"`, `"null"`, `"nullptr"`.
fn has_nontrivial_arg_cpp(args_node: Node<'_>, source: &[u8]) -> bool {
    const CPP_LITERAL_KINDS: &[&str] = &[
        "number_literal",
        "string_literal",
        "char_literal",
        "system_lib_string",
        "true",
        "false",
        "null",
        "nullptr",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        if !CPP_LITERAL_KINDS.contains(&child.kind()) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Rust — `call_expression` and `method_call_expression` nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Rust cross-file sink scanner.
///
/// In tree-sitter-rust 0.24.x, `call_expression` is the sole call node type.
/// The `function` field is:
/// - `identifier` — bare call: `dangerous_sink(arg)`
/// - `scoped_identifier` — path call: `module::dangerous_sink(arg)`, `name` child is callee.
/// - `field_expression` — method call: `obj.dangerous_sink(arg)`, `field` child is callee.
///
/// Argument literal kinds: `"string_literal"`, `"raw_string_literal"`,
/// `"integer_literal"`, `"float_literal"`, `"boolean_literal"`,
/// `"char_literal"`, `"true"`, `"false"`.
fn scan_rust(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_rust_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_rust_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // tree-sitter-rust 0.24.x: only call_expression (no separate method_call_expression).
    // obj.method(args) → call_expression where function is field_expression.
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            let callee: String = match func.kind() {
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "scoped_identifier" => func
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                // `obj.dangerous_sink(arg)` — function is a field_expression.
                "field_expression" => func
                    .child_by_field_name("field")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if has_nontrivial_arg_rust(args, source) {
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
        walk_rust_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the Rust `arguments` node contains at least one non-literal arg.
///
/// Rust literal kinds: `"string_literal"`, `"raw_string_literal"`,
/// `"integer_literal"`, `"float_literal"`, `"boolean_literal"`,
/// `"char_literal"`, `"true"`, `"false"`.
fn has_nontrivial_arg_rust(args_node: Node<'_>, source: &[u8]) -> bool {
    const RUST_LITERAL_KINDS: &[&str] = &[
        "string_literal",
        "raw_string_literal",
        "integer_literal",
        "float_literal",
        "boolean_literal",
        "char_literal",
        "true",
        "false",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        if !RUST_LITERAL_KINDS.contains(&child.kind()) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Swift — `call_expression` nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Swift cross-file sink scanner.
///
/// Detects `call_expression` nodes.  The first named child is the callable:
/// - `simple_identifier` — bare call: `dangerousSink(arg)`
/// - `navigation_expression` — chain: `obj.dangerousSink(arg)`, last suffix is callee.
///
/// The argument clause is found by scanning for a `call_suffix` or
/// `value_arguments` child.  Literal kinds: `"line_string_literal"`,
/// `"multiline_string_literal"`, `"integer_literal"`, `"float_literal"`,
/// `"boolean_literal"`, `"nil"`, `"true"`, `"false"`.
fn scan_swift(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_swift_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_swift_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call_expression" {
        // First named child is the callable expression.
        if let Some(func) = node.named_child(0) {
            let callee: String = match func.kind() {
                "simple_identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "navigation_expression" => {
                    // `navigation_expression` ends with a `simple_identifier` suffix.
                    let count = func.named_child_count();
                    func.named_child(count.saturating_sub(1) as u32)
                        .and_then(|n| n.utf8_text(source).ok())
                        .unwrap_or("")
                        .to_string()
                }
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                // Argument clause: look for `call_suffix` or `value_arguments` child.
                let mut args_opt: Option<Node<'_>> = None;
                let mut c = node.walk();
                for child in node.children(&mut c) {
                    if matches!(
                        child.kind(),
                        "call_suffix" | "value_arguments" | "argument_clause"
                    ) {
                        args_opt = Some(child);
                        break;
                    }
                }
                if let Some(args) = args_opt {
                    if has_nontrivial_arg_swift(args, source) {
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
        walk_swift_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the Swift argument clause contains at least one non-literal arg.
///
/// Swift literal kinds: `"line_string_literal"`, `"multiline_string_literal"`,
/// `"integer_literal"`, `"float_literal"`, `"boolean_literal"`, `"nil"`.
fn has_nontrivial_arg_swift(args_node: Node<'_>, source: &[u8]) -> bool {
    const SWIFT_LITERAL_KINDS: &[&str] = &[
        "line_string_literal",
        "multiline_string_literal",
        "integer_literal",
        "float_literal",
        "boolean_literal",
        "nil",
        "true",
        "false",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        // `value_argument` wrapper — check inside.
        let expr_kind = if child.kind() == "value_argument" {
            child
                .named_child(0)
                .map(|n| n.kind())
                .unwrap_or(child.kind())
        } else {
            child.kind()
        };
        if !SWIFT_LITERAL_KINDS.contains(&expr_kind) {
            return true;
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Scala — `call_expression` nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Scala cross-file sink scanner.
///
/// Detects `call_expression` nodes.  The first named child is the callable:
/// - `identifier` — bare call: `dangerousSink(arg)`
/// - `field_expression` — chain: `obj.dangerousSink(arg)`, `name` child is callee.
///
/// Arguments are in an `arguments` child node.
/// Literal kinds: `"string"`, `"integer_literal"`, `"floating_point_literal"`,
/// `"boolean_literal"`, `"null_literal"`, `"symbol_literal"`.
fn scan_scala(source: &[u8], root: Node<'_>, catalog: &CatalogView) -> Vec<CrossFileSinkFinding> {
    let mut out = Vec::new();
    walk_scala_calls(root, source, catalog, &mut out, 0);
    out
}

fn walk_scala_calls(
    node: Node<'_>,
    source: &[u8],
    catalog: &CatalogView,
    out: &mut Vec<CrossFileSinkFinding>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call_expression" {
        // First named child is the callable expression.
        if let Some(func) = node.named_child(0) {
            let callee: String = match func.kind() {
                "identifier" => func.utf8_text(source).unwrap_or("").to_string(),
                "field_expression" | "selection_expression" => func
                    .child_by_field_name("name")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("")
                    .to_string(),
                _ => String::new(),
            };
            if !callee.is_empty() && catalog.has_sink(&callee) {
                // Arguments node: try field name first, then scan children.
                let mut args_opt = node.child_by_field_name("arguments");
                if args_opt.is_none() {
                    let mut c = node.walk();
                    for child in node.children(&mut c) {
                        if child.kind() == "arguments" {
                            args_opt = Some(child);
                            break;
                        }
                    }
                }
                if let Some(args) = args_opt {
                    if has_nontrivial_arg_scala(args, source) {
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
        walk_scala_calls(child, source, catalog, out, depth + 1);
    }
}

/// Returns `true` when the Scala `arguments` node contains at least one non-literal arg.
///
/// Scala literal kinds: `"string"`, `"integer_literal"`, `"floating_point_literal"`,
/// `"boolean_literal"`, `"null_literal"`, `"symbol_literal"`.
fn has_nontrivial_arg_scala(args_node: Node<'_>, source: &[u8]) -> bool {
    const SCALA_LITERAL_KINDS: &[&str] = &[
        "string",
        "integer_literal",
        "floating_point_literal",
        "boolean_literal",
        "null_literal",
        "symbol_literal",
    ];
    let _ = source;
    let mut cur = args_node.walk();
    for child in args_node.named_children(&mut cur) {
        if !SCALA_LITERAL_KINDS.contains(&child.kind()) {
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

    /// CT-013: catalog_hash() must return a deterministic BLAKE3 hex digest that
    /// reflects the on-disk content.  Two opens of the same file yield the same
    /// hash; a different catalog yields a different hash.
    #[test]
    fn catalog_hash_is_deterministic_and_content_sensitive() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("build_query", true)];
        write_catalog(&path, &records).expect("write");

        let view_a = CatalogView::open(&path).expect("open a");
        let view_b = CatalogView::open(&path).expect("open b");
        let hash_a = view_a.catalog_hash().to_owned();
        let hash_b = view_b.catalog_hash().to_owned();

        // Same file → same hash (deterministic).
        assert_eq!(
            hash_a, hash_b,
            "same catalog file must yield identical hash"
        );
        // Hash is a 64-char hex BLAKE3 digest.
        assert_eq!(hash_a.len(), 64, "BLAKE3 hex digest must be 64 characters");

        // Different content → different hash.
        let (_dir2, path2) = tmp_catalog_path();
        let records2 = vec![make_record("other_sink", true)];
        write_catalog(&path2, &records2).expect("write 2");
        let view_c = CatalogView::open(&path2).expect("open c");
        assert_ne!(
            hash_a,
            view_c.catalog_hash(),
            "different catalog content must yield different hash"
        );
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

    // ── CT-014: member-expression / attribute call chain tests ─────────────

    fn parse_js(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_javascript::LANGUAGE.into())
            .expect("JavaScript grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// CT-014 true positive (JS): `obj.dangerousSink(tainted)` — member_expression callee.
    #[test]
    fn js_member_expression_cross_file_sink_fires() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "obj.dangerousSink(userInput);\n";
        let tree = parse_js(src);
        let findings = scan_cross_file_sinks("js", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "JS member_expression callee must be intercepted as cross-file taint sink"
        );
        assert_eq!(findings[0].callee_name, "dangerousSink");
    }

    /// CT-014 true negative (JS): `obj.safeMethod("literal")` — literal arg must be silent.
    #[test]
    fn js_member_expression_literal_arg_silent() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "obj.dangerousSink(\"static-value\");\n";
        let tree = parse_js(src);
        let findings = scan_cross_file_sinks("js", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "JS member_expression callee with literal arg must not fire"
        );
    }

    /// CT-014 true positive (TS): `this.queryRunner(payload)` — member_expression callee.
    #[test]
    fn ts_member_expression_cross_file_sink_fires() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("queryRunner", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "this.queryRunner(payload);\n";
        let tree = parse_typescript(src);
        let findings = scan_cross_file_sinks("ts", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "TS member_expression callee must be intercepted as cross-file taint sink"
        );
        assert_eq!(findings[0].callee_name, "queryRunner");
    }

    /// CT-014 true positive (Python): `self.db_helper(user_input)` — attribute callee.
    #[test]
    fn python_attribute_callee_cross_file_sink_fires() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("db_helper", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "self.db_helper(user_input)\n";
        let tree = parse_python(src);
        let findings = scan_cross_file_sinks("py", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Python attribute callee must be intercepted as cross-file taint sink"
        );
        assert_eq!(findings[0].callee_name, "db_helper");
    }

    /// CT-014 true negative (Python): `self.safe_method("literal")` — literal arg, must be silent.
    #[test]
    fn python_attribute_callee_literal_arg_silent() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("db_helper", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "self.db_helper(\"static-query\")\n";
        let tree = parse_python(src);
        let findings = scan_cross_file_sinks("py", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "Python attribute callee with literal arg must not fire"
        );
    }

    // ── Ruby cross-file taint ───────────────────────────────────────────────

    fn parse_ruby(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .expect("Ruby grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive: Ruby diff calls `obj.dangerousSink(user_input)` — must fire.
    #[test]
    fn ruby_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "obj.dangerousSink(user_input)\n";
        let tree = parse_ruby(src);
        let findings = scan_cross_file_sinks("rb", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Ruby cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerousSink");
    }

    /// True negative: Ruby diff calls uncataloged function — must be silent.
    #[test]
    fn ruby_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "obj.safeMethod(user_input)\n";
        let tree = parse_ruby(src);
        let findings = scan_cross_file_sinks("rb", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged Ruby function must not produce cross-file finding"
        );
    }

    // ── PHP cross-file taint ────────────────────────────────────────────────

    fn parse_php(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive: PHP bare function call `dangerous_sink($user_input)` — must fire.
    #[test]
    fn php_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerous_sink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "<?php\ndangerous_sink($user_input);\n";
        let tree = parse_php(src);
        let findings = scan_cross_file_sinks("php", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "PHP cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerous_sink");
    }

    /// True negative: PHP call to uncataloged function — must be silent.
    #[test]
    fn php_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerous_sink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "<?php\nsafe_transform($user_input);\n";
        let tree = parse_php(src);
        let findings = scan_cross_file_sinks("php", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged PHP function must not produce cross-file finding"
        );
    }

    // ── C# cross-file taint ─────────────────────────────────────────────────

    fn parse_csharp(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive: C# `dangerousSink(userInput)` in a method — must fire.
    #[test]
    fn csharp_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "class C { void M(object x) { dangerousSink(x); } }\n";
        let tree = parse_csharp(src);
        let findings = scan_cross_file_sinks("cs", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "C# cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerousSink");
    }

    /// True negative: C# call to uncataloged function — must be silent.
    #[test]
    fn csharp_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "class C { void M(object x) { SafeMethod(x); } }\n";
        let tree = parse_csharp(src);
        let findings = scan_cross_file_sinks("cs", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged C# function must not produce cross-file finding"
        );
    }

    // ── Kotlin cross-file taint ─────────────────────────────────────────────

    fn parse_kotlin(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_kotlin_ng::LANGUAGE.into())
            .expect("Kotlin grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive: Kotlin `dangerousSink(userInput)` — must fire.
    #[test]
    fn kotlin_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "fun h(userInput: String) { dangerousSink(userInput) }\n";
        let tree = parse_kotlin(src);
        let findings = scan_cross_file_sinks("kt", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Kotlin cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerousSink");
    }

    /// True negative: Kotlin call to uncataloged function — must be silent.
    #[test]
    fn kotlin_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "fun h(x: String) { safeTransform(x) }\n";
        let tree = parse_kotlin(src);
        let findings = scan_cross_file_sinks("kt", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged Kotlin function must not produce cross-file finding"
        );
    }

    // ── C/C++ cross-file taint ──────────────────────────────────────────────

    fn parse_cpp(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive: C++ `dangerous_sink(user_input)` — must fire.
    #[test]
    fn cpp_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerous_sink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "void h(char* user_input) { dangerous_sink(user_input); }\n";
        let tree = parse_cpp(src);
        let findings = scan_cross_file_sinks("cpp", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "C++ cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerous_sink");
    }

    /// True negative: C++ call to uncataloged function — must be silent.
    #[test]
    fn cpp_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerous_sink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "void h(char* x) { safe_transform(x); }\n";
        let tree = parse_cpp(src);
        let findings = scan_cross_file_sinks("cpp", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged C++ function must not produce cross-file finding"
        );
    }

    // ── Rust cross-file taint ───────────────────────────────────────────────

    fn parse_rust(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive (call_expression): Rust `dangerous_sink(user_input)` — must fire.
    #[test]
    fn rust_cross_file_sink_fires_on_call_expression() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerous_sink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "fn h(user_input: &str) { dangerous_sink(user_input); }\n";
        let tree = parse_rust(src);
        let findings = scan_cross_file_sinks("rs", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Rust cross-file taint must fire on cataloged call_expression with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerous_sink");
    }

    /// True positive (field_expression / dot-call): Rust `obj.dangerous_sink(x)` — must fire.
    ///
    /// In tree-sitter-rust 0.24.x, `obj.method(args)` is a `call_expression`
    /// where `function` is a `field_expression` (not a separate `method_call_expression`).
    #[test]
    fn rust_cross_file_sink_fires_on_field_expression_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerous_sink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "fn h(obj: DB, x: &str) { obj.dangerous_sink(x); }\n";
        let tree = parse_rust(src);
        let findings = scan_cross_file_sinks("rs", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Rust cross-file taint must fire on cataloged field_expression call with non-literal"
        );
        assert_eq!(findings[0].callee_name, "dangerous_sink");
    }

    /// True negative: Rust call to uncataloged function — must be silent.
    #[test]
    fn rust_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerous_sink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "fn h(x: &str) { safe_transform(x); }\n";
        let tree = parse_rust(src);
        let findings = scan_cross_file_sinks("rs", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged Rust function must not produce cross-file finding"
        );
    }

    // ── Swift cross-file taint ──────────────────────────────────────────────

    fn parse_swift(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_swift::LANGUAGE.into())
            .expect("Swift grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive: Swift `dangerousSink(userInput)` — must fire.
    #[test]
    fn swift_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "func h(userInput: String) { dangerousSink(userInput) }\n";
        let tree = parse_swift(src);
        let findings = scan_cross_file_sinks("swift", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Swift cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerousSink");
    }

    /// True negative: Swift call to uncataloged function — must be silent.
    #[test]
    fn swift_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "func h(x: String) { safeTransform(x) }\n";
        let tree = parse_swift(src);
        let findings = scan_cross_file_sinks("swift", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged Swift function must not produce cross-file finding"
        );
    }

    // ── Scala cross-file taint ──────────────────────────────────────────────

    fn parse_scala(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_scala::LANGUAGE.into())
            .expect("Scala grammar");
        parser.parse(source.as_bytes(), None).expect("parse")
    }

    /// True positive: Scala `dangerousSink(userInput)` — must fire.
    #[test]
    fn scala_cross_file_sink_fires_on_tainted_call() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "def h(userInput: String): Unit = { dangerousSink(userInput) }\n";
        let tree = parse_scala(src);
        let findings = scan_cross_file_sinks("scala", src.as_bytes(), &tree, &catalog);
        assert!(
            !findings.is_empty(),
            "Scala cross-file taint must fire on cataloged callee with non-literal arg"
        );
        assert_eq!(findings[0].callee_name, "dangerousSink");
    }

    /// True negative: Scala call to uncataloged function — must be silent.
    #[test]
    fn scala_cross_file_sink_silent_for_uncataloged_fn() {
        let (_dir, path) = tmp_catalog_path();
        let records = vec![make_record("dangerousSink", true)];
        write_catalog(&path, &records).expect("write");
        let catalog = CatalogView::open(&path).expect("open");

        let src = "def h(x: String): Unit = { safeTransform(x) }\n";
        let tree = parse_scala(src);
        let findings = scan_cross_file_sinks("scala", src.as_bytes(), &tree, &catalog);
        assert!(
            findings.is_empty(),
            "uncataloged Scala function must not produce cross-file finding"
        );
    }
}
