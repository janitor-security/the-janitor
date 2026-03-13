//! # Advanced Threat Matrix — Experimental Crate
//!
//! Isolated prototypes for two non-ML defensive paradigms:
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
//! **ISOLATION GUARANTEE**: Neither module is wired into `PatchBouncer::bounce`,
//! `slop_hunter.rs`, or any production CLI pipeline. These are standalone prototypes.

pub mod blast_radius;
pub mod yggdrasil;
