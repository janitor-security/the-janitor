//! Isolation test suite for the Phantom FFI Gate.
//!
//! All tests are self-contained and leave no persistent state.  Temporary
//! rkyv registry files are written to `std::env::temp_dir()` and removed at
//! the end of each test.
//!
//! ## Test inventory
//! 1. `extern_c_single_line`      — single-line `extern "C"` declaration
//! 2. `extern_c_block_form`       — block `extern "C" { ... }` declarations
//! 3. `pybind11_def_extraction`   — `m.def("name", &fn)` registrations
//! 4. `python_call_extraction`    — ctypes-style `lib.symbol(...)` call sites
//! 5. `registry_build_lookup`     — in-memory registry membership test
//! 6. `registry_round_trip_mmap`  — serialize → mmap → O(log N) lookup
//! 7. `evaluator_detects_phantom` — end-to-end hallucination detection
//! 8. `veto_bond_signing`         — ML-DSA-65 VetoBond shape verification
//! 9. `end_to_end_pipeline`       — C++ source → Python hallucination → VetoBond

use phantom_ffi_gate::evaluator::evaluate;
use phantom_ffi_gate::extractor::{
    extract_extern_c_symbols, extract_pybind11_symbols, extract_python_ffi_calls,
};
use phantom_ffi_gate::registry::{save_registry, FfiSymbolRegistry, RegistryMmap};
use phantom_ffi_gate::veto::sign_veto;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Write a registry to a uniquely-named temp file and return the path.
/// Caller must remove the file when done.
fn write_temp_registry(registry: &FfiSymbolRegistry, tag: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("phantom_ffi_{tag}.rkyv"));
    save_registry(registry, &path, None).expect("save_registry failed");
    path
}

// ---------------------------------------------------------------------------
// Phase 2 — Extraction tests
// ---------------------------------------------------------------------------

#[test]
fn extern_c_single_line() {
    let cpp = br#"
extern "C" void add_vectors(const float* a, const float* b, float* out, int n);
extern "C" int compute_score(const char* data, int len);
extern "C" void release_buffer(void* ptr);
"#;
    let symbols = extract_extern_c_symbols(cpp).expect("extern C extraction failed");
    assert!(
        symbols.contains(&"add_vectors".to_string()),
        "expected add_vectors, got: {symbols:?}"
    );
    assert!(symbols.contains(&"compute_score".to_string()));
    assert!(symbols.contains(&"release_buffer".to_string()));
}

#[test]
fn extern_c_block_form() {
    let cpp = br#"
extern "C" {
    void matrix_multiply(const float* a, const float* b, float* c, int m, int n, int k);
    float dot_product(const float* a, const float* b, int n);
}
"#;
    let symbols = extract_extern_c_symbols(cpp).expect("extern C block extraction failed");
    assert!(
        symbols.contains(&"matrix_multiply".to_string()),
        "expected matrix_multiply in {symbols:?}"
    );
    assert!(symbols.contains(&"dot_product".to_string()));
}

#[test]
fn pybind11_def_extraction() {
    // Simulates the body of a PYBIND11_MODULE block.
    // The macro wrapper is intentionally omitted — it is preprocessed away
    // before the tree-sitter grammar sees the source.
    let cpp = br#"
    m.def("add", &cpp_add, "Add two arrays element-wise");
    m.def("multiply", &cpp_multiply);
    m.def("normalise", &cpp_normalise, py::arg("inplace") = false);
"#;
    let symbols = extract_pybind11_symbols(cpp).expect("pybind11 extraction failed");
    assert!(
        symbols.contains(&"add".to_string()),
        "expected add in {symbols:?}"
    );
    assert!(symbols.contains(&"multiply".to_string()));
    assert!(symbols.contains(&"normalise".to_string()));
}

#[test]
fn python_call_extraction() {
    let python = br#"
import ctypes
lib = ctypes.CDLL("./libcompute.so")

result = lib.add_vectors(a_ptr, b_ptr, out_ptr, n)
score  = lib.compute_score(data_ptr, length)
lib.release_buffer(out_ptr)
bad    = lib.hallucinated_function(x)
"#;
    let calls = extract_python_ffi_calls(python).expect("Python call extraction failed");
    assert!(
        calls.contains(&"add_vectors".to_string()),
        "expected add_vectors in {calls:?}"
    );
    assert!(calls.contains(&"compute_score".to_string()));
    assert!(calls.contains(&"release_buffer".to_string()));
    assert!(calls.contains(&"hallucinated_function".to_string()));
    // Dunders must be excluded.
    assert!(!calls.iter().any(|n| n.starts_with("__")));
}

// ---------------------------------------------------------------------------
// Phase 2 — Registry tests
// ---------------------------------------------------------------------------

#[test]
fn registry_build_lookup() {
    let symbols = vec![
        "add_vectors".to_string(),
        "compute_score".to_string(),
        "release_buffer".to_string(),
    ];
    let reg = FfiSymbolRegistry::build(&symbols);
    assert!(reg.contains("add_vectors"));
    assert!(reg.contains("compute_score"));
    assert!(reg.contains("release_buffer"));
    assert!(!reg.contains("hallucinated_function"));
    assert!(!reg.contains(""));
    // Dedup: building from a list with duplicates should not double-count.
    let dup = vec!["foo".to_string(), "foo".to_string()];
    let dup_reg = FfiSymbolRegistry::build(&dup);
    assert_eq!(dup_reg.hashes.len(), 1);
}

#[test]
fn registry_round_trip_mmap() {
    let symbols = vec![
        "add_vectors".to_string(),
        "dot_product".to_string(),
        "matrix_multiply".to_string(),
    ];
    let reg = FfiSymbolRegistry::build(&symbols);

    let path = write_temp_registry(&reg, "round_trip");

    let mmap = RegistryMmap::open(&path).expect("RegistryMmap::open failed");
    assert!(mmap.lookup("add_vectors"), "add_vectors should be present");
    assert!(mmap.lookup("dot_product"));
    assert!(mmap.lookup("matrix_multiply"));
    assert!(
        !mmap.lookup("ghost_symbol"),
        "ghost_symbol should be absent"
    );
    assert!(!mmap.lookup(""));

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Phase 3 — Evaluator tests
// ---------------------------------------------------------------------------

#[test]
fn evaluator_detects_phantom() {
    let known = vec![
        "add_vectors".to_string(),
        "dot_product".to_string(),
        "release_buffer".to_string(),
    ];
    let python_calls = vec![
        "add_vectors".to_string(),           // known — should pass
        "hallucinated_function".to_string(), // unknown — should be flagged
        "dot_product".to_string(),           // known — should pass
        "ghost_matmul".to_string(),          // unknown — should be flagged
    ];

    let reg = FfiSymbolRegistry::build(&known);
    let path = write_temp_registry(&reg, "evaluator");

    let mmap = RegistryMmap::open(&path).expect("RegistryMmap::open failed");
    let phantoms = evaluate(&python_calls, &mmap);

    assert_eq!(phantoms.len(), 2, "expected 2 phantoms, got: {phantoms:?}");
    assert!(phantoms.contains(&"hallucinated_function".to_string()));
    assert!(phantoms.contains(&"ghost_matmul".to_string()));
    // Known symbols must NOT appear in the phantom list.
    assert!(!phantoms.contains(&"add_vectors".to_string()));
    assert!(!phantoms.contains(&"dot_product".to_string()));

    let _ = std::fs::remove_file(&path);
}

// ---------------------------------------------------------------------------
// Phase 4 — VetoBond tests
// ---------------------------------------------------------------------------

#[test]
fn veto_bond_signing() {
    let bond = sign_veto("hallucinated_function").expect("sign_veto failed");

    assert_eq!(bond.hallucinated_symbol, "hallucinated_function");

    // ML-DSA-65 verifying key: 1952 bytes.
    assert_eq!(
        bond.vk_bytes.len(),
        fips204::ml_dsa_65::PK_LEN,
        "unexpected vk_bytes length"
    );
    // ML-DSA-65 signature: 3309 bytes.
    assert_eq!(
        bond.sig_bytes.len(),
        fips204::ml_dsa_65::SIG_LEN,
        "unexpected sig_bytes length"
    );
    // Signature must not be all-zero (sanity check that signing ran).
    assert!(
        bond.sig_bytes.iter().any(|&b| b != 0),
        "signature is all-zero — signing likely did not execute"
    );
}

#[test]
fn veto_bonds_are_distinct_per_invocation() {
    // Two separate sign_veto calls for the same symbol must produce different
    // signatures (ephemeral keypair → fresh randomness each time).
    let bond_a = sign_veto("ghost_symbol").expect("first sign_veto failed");
    let bond_b = sign_veto("ghost_symbol").expect("second sign_veto failed");

    // Different verifying keys (different ephemeral keypairs).
    assert_ne!(
        bond_a.vk_bytes, bond_b.vk_bytes,
        "two calls produced the same verifying key — RNG may be broken"
    );
}

// ---------------------------------------------------------------------------
// End-to-end pipeline test
// ---------------------------------------------------------------------------

#[test]
fn end_to_end_pipeline() {
    // ── Step 1: extract C++ exported symbols ─────────────────────────────
    let cpp_source = br#"
extern "C" void add_vectors(const float* a, const float* b, float* out, int n);
extern "C" int  compute_score(const char* data, int len);
extern "C" void release_buffer(void* ptr);
"#;
    let cpp_symbols = extract_extern_c_symbols(cpp_source).expect("C++ extraction failed");
    assert!(!cpp_symbols.is_empty(), "no C++ symbols extracted");

    // ── Step 2: build and persist the registry ────────────────────────────
    let reg = FfiSymbolRegistry::build(&cpp_symbols);
    let path = write_temp_registry(&reg, "e2e");

    // ── Step 3: extract Python call sites ────────────────────────────────
    let python_source = br#"
import ctypes
lib = ctypes.CDLL("./libcompute.so")
lib.add_vectors(a, b, out, n)
lib.compute_score(data, length)
lib.release_buffer(out)
lib.hallucinated_matmul(a, b)
lib.phantom_normalise(vec)
"#;
    let py_calls = extract_python_ffi_calls(python_source).expect("Python extraction failed");

    // ── Step 4: evaluate against the mmap registry ────────────────────────
    let mmap = RegistryMmap::open(&path).expect("RegistryMmap::open failed");
    let phantoms = evaluate(&py_calls, &mmap);

    // Known symbols pass; hallucinated ones are flagged.
    assert!(
        phantoms.contains(&"hallucinated_matmul".to_string()),
        "expected hallucinated_matmul in phantoms: {phantoms:?}"
    );
    assert!(phantoms.contains(&"phantom_normalise".to_string()));
    assert!(
        !phantoms.contains(&"add_vectors".to_string()),
        "add_vectors is real — must not appear in phantoms"
    );

    // ── Step 5: sign VetoBonds for each phantom ────────────────────────────
    let bonds: Vec<_> = phantoms
        .iter()
        .map(|sym| sign_veto(sym).expect("sign_veto failed"))
        .collect();

    assert_eq!(bonds.len(), phantoms.len());
    for bond in &bonds {
        assert_eq!(bond.sig_bytes.len(), fips204::ml_dsa_65::SIG_LEN);
        assert_eq!(bond.vk_bytes.len(), fips204::ml_dsa_65::PK_LEN);
    }

    let _ = std::fs::remove_file(&path);
}
