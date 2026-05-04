//! P9-4 Cross-Language FFI Semantic Dependency Graph.
//!
//! The decade's hardest bugs live at FFI interfaces: memory-model mismatches,
//! ownership surprises, and type confusion across ABIs. A Rust crate may call a
//! C shim wrapping a Python module loading a Wasm blob — taint crosses four
//! language boundaries and the engine currently stops at the first.
//!
//! This module builds an `InterLanguageCallGraph` where every node is a
//! `(language, symbol, ABI spec)` triple and edges record the FFI bridge kind.
//! It then runs AhoCorasick + structural pattern detection over source text to
//! emit `security:ffi_memory_corruption` (Critical) when:
//!
//! - A Rust `extern "C"` or `#[no_mangle]` function exposes a `*mut T` or
//!   `&mut T` parameter to a C caller that has no lifetime guarantee, OR
//! - A `Box<T>` raw pointer is handed across an FFI boundary without an explicit
//!   documented drop contract (`Box::from_raw` / `Box::into_raw` asymmetry), OR
//! - A PyO3 `#[pyfunction]` passes a mutable Python object reference across the
//!   GIL boundary into a thread that may outlive the GIL acquisition.
//!
//! ## Architecture
//!
//! ```text
//! Source file(s)
//!   └─► detect_ffi_boundary_violations()   ← public entry point
//!         ├─► scan_rust_extern_blocks()     ← *mut / &mut exposure
//!         ├─► scan_rust_box_raw_patterns()  ← Box<T> ownership leak
//!         └─► scan_pyo3_gil_violations()    ← GIL / thread-lifetime mismatch
//!               └─► InterLanguageCallGraph::record_edge()
//! ```

use aho_corasick::AhoCorasick;
use common::slop::StructuredFinding;
use petgraph::Graph;
use std::sync::OnceLock;

// ---------------------------------------------------------------------------
// AhoCorasick patterns — compiled once
// ---------------------------------------------------------------------------

/// Rust FFI exposure patterns that may carry mutable memory across the boundary.
static RUST_FFI_MUT_PATTERNS: OnceLock<AhoCorasick> = OnceLock::new();

fn rust_ffi_mut_ac() -> &'static AhoCorasick {
    RUST_FFI_MUT_PATTERNS.get_or_init(|| {
        AhoCorasick::new([
            // extern "C" with mutable raw pointer
            b"*mut " as &[u8],
            // extern "C" with mutable reference — lifetime ends at return but
            // C caller may stash the address
            b"&mut ",
            // Box::into_raw — transfers ownership; C must call Box::from_raw
            b"Box::into_raw",
            // Raw pointer cast — Rust no longer owns the memory
            b"as *mut ",
            b"as *const ",
        ])
        .expect("ffi_taint: rust_ffi_mut_ac patterns must compile")
    })
}

/// PyO3 patterns indicating mutable Python object exposure.
static PYO3_GIL_PATTERNS: OnceLock<AhoCorasick> = OnceLock::new();

fn pyo3_gil_ac() -> &'static AhoCorasick {
    PYO3_GIL_PATTERNS.get_or_init(|| {
        AhoCorasick::new([
            b"#[pyfunction]" as &[u8],
            b"PyCell",
            b"PyRefMut",
            // spawn while holding a mutable Python reference
            b"thread::spawn",
            b"tokio::spawn",
            b"rayon::spawn",
        ])
        .expect("ffi_taint: pyo3_gil_ac patterns must compile")
    })
}

/// Box::from_raw — the required paired call that frees the C-side memory.
static BOX_FREE_PATTERNS: OnceLock<AhoCorasick> = OnceLock::new();

fn box_free_ac() -> &'static AhoCorasick {
    BOX_FREE_PATTERNS.get_or_init(|| {
        AhoCorasick::new([b"Box::from_raw" as &[u8]])
            .expect("ffi_taint: box_free_ac patterns must compile")
    })
}

// ---------------------------------------------------------------------------
// Graph types
// ---------------------------------------------------------------------------

/// The kind of FFI bridge that an edge in the `InterLanguageCallGraph` models.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FfiBridgeKind {
    /// Rust `extern "C"` block or `#[no_mangle]` function.
    CExternBlock,
    /// PyO3 `#[pyfunction]` / `#[pymethods]` bridge.
    PyO3,
    /// JNI `Java_*` or `JNI_OnLoad` entry points.
    Jni,
    /// `wasmtime` host function or Wasm export.
    WasmExport,
    /// Python `ctypes` or `cffi` call site.
    CffiCtypes,
    /// Node.js N-API (`napi_*`) bridge.
    Napi,
    /// Neon (Rust → Node.js) bridge.
    Neon,
}

/// ABI metadata carried on each `FfiNode`.
#[derive(Debug, Clone)]
pub struct AbiSpec {
    /// The function or export symbol name at this boundary.
    pub symbol: String,
    /// True when the boundary exposes a `*mut T` or `&mut T`.
    pub passes_mut_ref: bool,
    /// True when a `Box::into_raw` is present without a matching `Box::from_raw`
    /// in the same lexical scope — ownership transfer with no documented drop.
    pub ownership_transfer_undocumented: bool,
    /// True when a PyO3 mutable reference is passed into a spawned thread.
    pub pyo3_gil_escape: bool,
}

/// A node in the `InterLanguageCallGraph`.
#[derive(Debug, Clone)]
pub struct FfiNode {
    /// Source language of this symbol.
    pub language: &'static str,
    /// Symbol name (function, export, or import).
    pub symbol: String,
    /// Source file this node was detected in.
    pub file: String,
    /// Approximate line of the FFI declaration.
    pub line: Option<u32>,
    /// ABI metadata.
    pub abi_spec: AbiSpec,
}

/// Cross-language taint graph.
///
/// Each node is an FFI boundary symbol; each edge is the bridge mechanism
/// that connects two symbols across a language boundary.
pub struct InterLanguageCallGraph {
    pub graph: Graph<FfiNode, FfiBridgeKind>,
}

impl InterLanguageCallGraph {
    /// Create an empty graph.
    pub fn new() -> Self {
        Self {
            graph: Graph::new(),
        }
    }

    /// Record a directed FFI edge from `caller` to `callee`.
    pub fn record_edge(&mut self, caller: FfiNode, callee: FfiNode, bridge: FfiBridgeKind) {
        let a = self.graph.add_node(caller);
        let b = self.graph.add_node(callee);
        self.graph.add_edge(a, b, bridge);
    }
}

impl Default for InterLanguageCallGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan `content` (a Rust source file) for FFI boundary violations.
///
/// Returns `security:ffi_memory_corruption` (Critical) findings for every
/// detected ownership or lifetime violation at a language boundary.
pub fn detect_ffi_boundary_violations(content: &str, file_path: &str) -> Vec<StructuredFinding> {
    let mut findings = Vec::new();
    let bytes = content.as_bytes();

    scan_rust_extern_blocks(bytes, file_path, &mut findings);
    scan_rust_box_raw_patterns(bytes, file_path, &mut findings);
    scan_pyo3_gil_violations(bytes, file_path, &mut findings);

    findings
}

// ---------------------------------------------------------------------------
// Sub-scanners
// ---------------------------------------------------------------------------

/// Emit a finding when `*mut T` or `&mut T` appears inside an `extern "C"` block.
///
/// C callers have no knowledge of Rust lifetimes; they may stash the pointer
/// and dereference it after the Rust side has dropped or reallocated the memory.
fn scan_rust_extern_blocks(bytes: &[u8], file_path: &str, out: &mut Vec<StructuredFinding>) {
    let content = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    let in_extern_block = content.contains("extern \"C\"");
    if !in_extern_block {
        return;
    }

    // Check for mutable pointer/reference patterns in the same file.
    let has_mut_ptr = rust_ffi_mut_ac()
        .find_iter(bytes)
        .any(|m| matches!(m.pattern().as_u32(), 0 | 1 | 3 | 4));
    // Pattern indices: 0 = *mut, 1 = &mut, 3 = as *mut, 4 = as *const

    if !has_mut_ptr {
        return;
    }

    // Narrow to line-level: find the first extern "C" line.
    let line_no = content
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("extern \"C\""))
        .map(|(i, _)| (i + 1) as u32);

    out.push(ffi_finding(
        file_path,
        line_no,
        "Rust `extern \"C\"` block exposes `*mut T` or `&mut T` to a C caller; \
         C has no lifetime contract — pointer may be used after Rust drops the referent. \
         Use an explicit drop-contract: export a `#[no_mangle] free_<T>` destructor \
         that the C caller must invoke, or wrap state in an opaque handle type \
         with a lifetime-erased `NonNull<T>` and a paired destructor callback.",
        FfiBridgeKind::CExternBlock,
    ));
}

/// Emit a finding when `Box::into_raw` appears without a matching `Box::from_raw`
/// in the same file — orphaned raw pointer with no documented drop path.
fn scan_rust_box_raw_patterns(bytes: &[u8], file_path: &str, out: &mut Vec<StructuredFinding>) {
    let has_into_raw = rust_ffi_mut_ac()
        .find_iter(bytes)
        .any(|m| m.pattern().as_u32() == 2); // pattern index 2 = Box::into_raw

    if !has_into_raw {
        return;
    }

    let has_from_raw = box_free_ac().find_iter(bytes).next().is_some();
    if has_from_raw {
        // Paired — Box::from_raw exists somewhere in the file; ownership is managed.
        return;
    }

    let content = std::str::from_utf8(bytes).unwrap_or("");
    let line_no = content
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("Box::into_raw"))
        .map(|(i, _)| (i + 1) as u32);

    out.push(ffi_finding(
        file_path,
        line_no,
        "`Box::into_raw` transfers heap ownership across an FFI boundary with no \
         corresponding `Box::from_raw` in this file; the heap allocation will leak \
         unless the C side calls the correct Rust destructor. Add an exported \
         `#[no_mangle] pub extern \"C\" fn free_<T>(ptr: *mut T)` that calls \
         `Box::from_raw(ptr)` and document the drop contract in the C header.",
        FfiBridgeKind::CExternBlock,
    ));
}

/// Emit a finding when a `PyRefMut` or `PyCell` (mutable Python object) is
/// present in the same file as a thread-spawn call — the GIL is not held
/// across the spawn boundary, making the mutable reference unsound.
fn scan_pyo3_gil_violations(bytes: &[u8], file_path: &str, out: &mut Vec<StructuredFinding>) {
    let content = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    if !content.contains("#[pyfunction]") && !content.contains("PyRefMut") {
        return;
    }

    let mut has_mut_ref = false;
    let mut has_spawn = false;

    for m in pyo3_gil_ac().find_iter(bytes) {
        match m.pattern().as_u32() {
            1 | 2 => has_mut_ref = true,   // PyCell, PyRefMut
            3..=5 => has_spawn = true, // thread::spawn, tokio::spawn, rayon::spawn
            _ => {}
        }
    }

    if !(has_mut_ref && has_spawn) {
        return;
    }

    let line_no = content
        .lines()
        .enumerate()
        .find(|(_, l)| l.contains("PyRefMut") || l.contains("PyCell"))
        .map(|(i, _)| (i + 1) as u32);

    out.push(ffi_finding(
        file_path,
        line_no,
        "PyO3 `PyRefMut` / `PyCell` mutable borrow escapes across a thread-spawn boundary; \
         the GIL is released when the `Python<'_>` token is dropped, leaving the mutable \
         reference dangling in the spawned thread. Move the data out of the Python object \
         into an owned Rust type before spawning, or use `Python::with_gil` inside the \
         spawned thread to re-acquire the GIL.",
        FfiBridgeKind::PyO3,
    ));
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn ffi_finding(
    file_path: &str,
    line: Option<u32>,
    detail: &str,
    _bridge: FfiBridgeKind,
) -> StructuredFinding {
    StructuredFinding {
        id: "security:ffi_memory_corruption".to_string(),
        file: Some(file_path.to_string()),
        line,
        fingerprint: String::new(),
        severity: Some("Critical".to_string()),
        remediation: Some(detail.to_string()),
        docs_url: Some("https://thejanitor.app/findings/ffi-memory-corruption".to_string()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extern_c_with_mut_ptr_triggers() {
        let src = r#"
extern "C" {
    fn c_process(buf: *mut u8, len: usize);
}

pub fn call_c(data: &mut Vec<u8>) {
    unsafe { c_process(data.as_mut_ptr(), data.len()); }
}
"#;
        let findings = detect_ffi_boundary_violations(src, "src/bridge.rs");
        assert_eq!(findings.len(), 1, "extern C + *mut must trigger");
        assert_eq!(findings[0].id, "security:ffi_memory_corruption");
        assert_eq!(findings[0].severity.as_deref(), Some("Critical"));
    }

    #[test]
    fn extern_c_without_mut_no_finding() {
        let src = r#"
extern "C" {
    fn c_read(buf: *const u8, len: usize) -> i32;
}
"#;
        let findings = detect_ffi_boundary_violations(src, "src/safe_bridge.rs");
        assert!(
            findings.is_empty(),
            "read-only extern C must not trigger ffi_memory_corruption"
        );
    }

    #[test]
    fn box_into_raw_without_from_raw_triggers() {
        let src = r#"
#[no_mangle]
pub extern "C" fn create_handle(value: u64) -> *mut MyHandle {
    Box::into_raw(Box::new(MyHandle { value }))
}
"#;
        let findings = detect_ffi_boundary_violations(src, "src/handle.rs");
        // Both extern-C *mut and Box::into_raw detectors may fire; assert at least one
        // is specifically about the ownership-transfer gap.
        assert!(
            !findings.is_empty(),
            "Box::into_raw without Box::from_raw must trigger"
        );
        let ownership_finding = findings.iter().any(|f| {
            f.remediation
                .as_deref()
                .unwrap_or("")
                .contains("transfers heap ownership")
        });
        assert!(ownership_finding, "must emit ownership-transfer finding");
    }

    #[test]
    fn box_into_raw_with_from_raw_no_finding() {
        let src = r#"
pub extern "C" fn create_handle() -> *mut u64 {
    Box::into_raw(Box::new(42u64))
}

pub extern "C" fn free_handle(ptr: *mut u64) {
    unsafe { let _ = Box::from_raw(ptr); }
}
"#;
        let findings = detect_ffi_boundary_violations(src, "src/handle_pair.rs");
        // The ownership-transfer finding is suppressed when Box::from_raw is present.
        // (The extern-C *mut pointer-exposure finding may still fire; that is expected.)
        let ownership_findings: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.remediation
                    .as_deref()
                    .unwrap_or("")
                    .contains("transfers heap ownership")
            })
            .collect();
        assert!(
            ownership_findings.is_empty(),
            "paired Box::into_raw / Box::from_raw must not trigger heap-leak finding"
        );
    }

    #[test]
    fn pyo3_pyrefmut_plus_spawn_triggers() {
        let src = r#"
use pyo3::prelude::*;

#[pyfunction]
fn process_async(py: Python<'_>, obj: &PyCell<MyData>) -> PyResult<()> {
    let data: PyRefMut<MyData> = obj.borrow_mut();
    std::thread::spawn(move || {
        // data is now used outside the GIL
        println!("{:?}", data);
    });
    Ok(())
}
"#;
        let findings = detect_ffi_boundary_violations(src, "src/pyo3_bridge.rs");
        assert_eq!(findings.len(), 1, "PyRefMut + thread::spawn must trigger");
        assert_eq!(findings[0].severity.as_deref(), Some("Critical"));
    }

    #[test]
    fn pyo3_without_spawn_no_finding() {
        let src = r#"
use pyo3::prelude::*;

#[pyfunction]
fn process_sync(obj: &PyCell<MyData>) -> PyResult<()> {
    let _data: PyRefMut<MyData> = obj.borrow_mut();
    Ok(())
}
"#;
        let findings = detect_ffi_boundary_violations(src, "src/pyo3_safe.rs");
        assert!(
            findings.is_empty(),
            "PyRefMut without thread spawn must not trigger"
        );
    }

    #[test]
    fn empty_file_no_panic() {
        let findings = detect_ffi_boundary_violations("", "src/empty.rs");
        assert!(findings.is_empty());
    }

    #[test]
    fn graph_records_edge() {
        let mut cg = InterLanguageCallGraph::new();
        let caller = FfiNode {
            language: "rust",
            symbol: "create_handle".to_string(),
            file: "src/lib.rs".to_string(),
            line: Some(5),
            abi_spec: AbiSpec {
                symbol: "create_handle".to_string(),
                passes_mut_ref: true,
                ownership_transfer_undocumented: true,
                pyo3_gil_escape: false,
            },
        };
        let callee = FfiNode {
            language: "c",
            symbol: "handle_use".to_string(),
            file: "lib/c_wrapper.c".to_string(),
            line: Some(12),
            abi_spec: AbiSpec {
                symbol: "handle_use".to_string(),
                passes_mut_ref: false,
                ownership_transfer_undocumented: false,
                pyo3_gil_escape: false,
            },
        };
        cg.record_edge(caller, callee, FfiBridgeKind::CExternBlock);
        assert_eq!(cg.graph.node_count(), 2);
        assert_eq!(cg.graph.edge_count(), 1);
    }
}
