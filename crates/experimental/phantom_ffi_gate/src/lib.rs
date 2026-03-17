//! **Phantom FFI Gate** — experimental cross-boundary AST validation engine.
//!
//! Detects hallucinated Foreign Function Interface (FFI) symbols between C++
//! and Python, targeting Agentic Swarm artefacts that fabricate call sites
//! for symbols that do not exist in the backing C++ shared library.
//!
//! ## Architecture
//!
//! ```text
//! C++ source ──► extractor::extract_extern_c_symbols()  ──┐
//!                extractor::extract_pybind11_symbols()  ───► registry::FfiSymbolRegistry
//!                                                            │  (BLAKE3-hashed, rkyv-serialized)
//!                                                            │  save_registry() → symbols.rkyv
//!                                                            │
//! Python source ─► extractor::extract_python_ffi_calls() ──► evaluator::evaluate()
//!                                                            │  mmap lookup via RegistryMmap
//!                                                            ▼
//!                                                   hallucinated symbols
//!                                                            │
//!                                                            ▼
//!                                               veto::sign_veto()
//!                                               → VetoBond { sig (ML-DSA-65) }
//! ```
//!
//! ## Memory gate
//! If the serialised registry exceeds 20 MiB, [`registry::save_registry`]
//! degrades to a sorted plaintext trie and commits an architectural failure
//! notice to `.janitor/experiments.log`.
//!
//! ## PHF note
//! True O(1) compile-time PHF (via `phf_codegen` in a `build.rs`) requires
//! the symbol corpus at build time.  Since symbols are extracted at runtime
//! from arbitrary C++ sources, this prototype uses a sorted `Vec<[u8; 32]>`
//! of BLAKE3 hashes plus `binary_search` for O(log N) membership tests.
//!
//! ## Isolation guarantee
//! This crate is **not wired into the production pipeline**.
//! It lives exclusively under `crates/experimental/` as an R&D prototype.

pub mod evaluator;
pub mod extractor;
pub mod registry;
pub mod veto;
