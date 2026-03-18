//! # Advanced Threat Matrix — Experimental Crate
//!
//! Isolated prototypes for four non-ML defensive paradigms:
//!
//! - [`blast_radius`]: Topological Blast-Radius Matrix. Uses `petgraph` CSR graphs
//!   and `bumpalo` arena allocation to detect unbridged monolithic changes
//!   (Agentic Hallucination) via BFS without touching the global allocator.
//!
//! - [`yggdrasil`]: The Yggdrasil Protocol — Lite. Uses `aho-corasick` + `tree-sitter`
//!   to detect CI injection indicators (`${{`, `github.token`, `secrets.`, …) within
//!   application code nodes, then signs confirmed threats with an ephemeral ML-DSA-65
//!   keypair (`fips204`).
//!
//! - [`unicode_gate`]: Zero-Allocation Invisible-Character Scanner. O(N) single-pass
//!   via AhoCorasick automaton (OnceLock). Detects BiDi controls (CVE-2021-42574),
//!   zero-width spaces, and Cyrillic homoglyphs used in ASCII identifier spoofing.
//!
//! - [`lotl_hunter`]: Living-off-the-Land Execution Anomaly Detector. Two-layer:
// janitor:ignore security:lotl_execution_anomaly
//!   AhoCorasick fast path for PowerShell -EncodedCommand / base64-decode-exec chains,
//!   plus `tree-sitter-bash` structural AST analysis for `/tmp/` / `/dev/shm/`
//!   staging-area binary execution.
//!
//! **ISOLATION GUARANTEE**: No module is wired into `PatchBouncer::bounce`,
//! `slop_hunter.rs`, or any production CLI pipeline. These are standalone prototypes.

pub mod blast_radius;
pub mod lotl_hunter;
pub mod unicode_gate;
pub mod yggdrasil;
