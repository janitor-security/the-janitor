//! # Include Deflator — C/C++ Transitive Header Dependency Analyser
//!
//! Experimental crate. **Not wired into the production pipeline.**
//!
//! ## Architecture
//!
//! ```text
//! Source files ──→ graph::IncludeGraphBuilder ──→ petgraph CSR DAG
//!                                                      │
//!                                           deflator::DeltaEngine
//!                                                      │
//!                                     ┌────────────────┴────────────────┐
//!                               DeflationBonus                    ThreatReport
//!                          (edges severed, reach Δ)        (compile_time_bloat)
//! ```
//!
//! ## What it measures
//!
//! **Transitive Reach** of a node N = the number of files that eventually pull in N
//! (i.e., the count of ancestors in the include DAG). Removing an edge from a heavily
//! included header reduces the reach of everything downstream from that header —
//! exactly the saving Godot PR #117516 achieved by detaching `error_macros.h` from
//! the core include spine.
//!
//! **Compile-time bloat** fires when a PR *adds* an include edge from a high-reach
//! header H into file F where `reach(H) > BLOAT_REACH_THRESHOLD`. Every translation
//! unit that transitively includes F now also pulls in H's entire closure.
//!
//! **ISOLATION GUARANTEE**: No symbol in this crate is imported by `PatchBouncer`,
//! `slop_hunter`, or any production CLI path. This is a standalone R&D prototype.

pub mod deflator;
pub mod graph;

// ─── Public re-exports ────────────────────────────────────────────────────────

pub use deflator::{
    DeflationBonus, DeltaEngine, EntanglementReport, ThreatReport, ENTANGLEMENT_LABEL,
    ENTANGLEMENT_THRESHOLD,
};
pub use graph::{IncludeGraph, IncludeGraphBuilder};
