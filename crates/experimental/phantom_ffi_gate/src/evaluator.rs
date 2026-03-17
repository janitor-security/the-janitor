//! Cross-boundary evaluation pass.
//!
//! Resolves Python FFI call sites against the mmap-backed C++ symbol registry.
//! Any call whose name has no entry in the registry is classified as a
//! *hallucinated symbol* — a candidate for a [`crate::veto::VetoBond`].
//!
//! ## Limitations (prototype scope)
//! The evaluator operates on a flat list of attribute-call names extracted by
//! [`crate::extractor::extract_python_ffi_calls`].  It does not track which
//! Python variable holds the ctypes/cffi library handle — all attribute calls
//! in the source are tested against the registry.  A production pass would
//! first resolve library handles via a dataflow analysis and filter call sites
//! to only those on confirmed FFI handles.

use crate::registry::RegistryMmap;

/// Evaluate `python_calls` against the mmap-backed C++ symbol registry.
///
/// Returns the subset of `python_calls` whose names are **absent** from the
/// registry — these are the hallucinated symbols that have no C++ backing.
///
/// # Performance
/// Each lookup is O(log N) via binary search on the archived hash slice.
/// No heap allocation occurs on the lookup hot path.
pub fn evaluate(python_calls: &[String], registry: &RegistryMmap) -> Vec<String> {
    python_calls
        .iter()
        .filter(|name| !registry.lookup(name))
        .cloned()
        .collect()
}
