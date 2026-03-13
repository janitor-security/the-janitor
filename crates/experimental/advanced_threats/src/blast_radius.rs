//! Topological Blast-Radius Matrix.
//!
//! Detects unbridged monolithic changes (Agentic Hallucination) by measuring the
//! maximum shortest-path distance between every pair of PR-modified nodes in a
//! directed dependency graph.
//!
//! ## Arena Allocation
//! BFS state (distance array + queue) is allocated entirely from a `bumpalo::Bump`
//! arena, which is reset between per-source BFS runs.  No individual allocation is
//! ever returned to the OS mid-loop — the arena reuses its pages across all BFS
//! traversals for a single call to [`compute_blast_radius`].
//!
//! ## Directed-graph pairwise semantics
//! For each ordered pair `(src, dst)` of modified nodes we record the forward BFS
//! distance `d(src→dst)`.  The canonical distance for an unordered pair `{a,b}` is
//! `min(d(a→b), d(b→a))` — i.e. whichever directed path is shorter.  Only when
//! **both** directions are unreachable is the pair flagged as disconnected (the
//! strongest hallucination signal).
//!
//! ## Node Index Type
//! `petgraph::csr::NodeIndex<Ix>` is a **type alias** for `Ix` (default `u32`), not
//! a newtype wrapper.  The public API here therefore uses plain `u32` node indices
//! consistent with `Csr::add_node()`.
//!
//! ## Hallucination Threshold
//! When the maximum pairwise distance exceeds [`HALLUCINATION_THRESHOLD`], the change
//! is flagged as an Agentic Hallucination: a monolithic diff spanning components with
//! no short dependency path, implying changes were generated without coherent
//! cross-module reasoning.

use bumpalo::collections::Vec as BumpVec;
use bumpalo::Bump;
use petgraph::csr::Csr;

/// Node index type used by `petgraph::csr::Csr<_, _, _, u32>`.
/// In petgraph CSR, `NodeIndex<Ix>` is a type alias for `Ix` — just `u32`.
pub type NodeIndex = u32;

/// Shortest-path hop distance above which a PR is classified as an Agentic
/// Hallucination (unbridged monolithic change).
pub const HALLUCINATION_THRESHOLD: u32 = 4;

/// Result of a blast-radius computation over a set of PR-modified nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlastRadiusReport {
    /// Maximum `min(d(a→b), d(b→a))` across all pairs of modified nodes.
    ///
    /// `u32::MAX` when at least one modified-node pair has no directed path
    /// in either direction.
    pub max_hop_distance: u32,
    /// `true` when `max_hop_distance > HALLUCINATION_THRESHOLD`.
    ///
    /// Flags an unbridged monolithic change consistent with Agentic Hallucination.
    pub is_agentic_hallucination: bool,
}

/// Compute the blast-radius matrix for a set of PR-modified nodes.
///
/// Performs a BFS from each modified node using arena-allocated state, records
/// all pairwise forward distances, then derives the canonical distance for each
/// unordered pair as `min(forward, reverse)`.
///
/// # Arguments
/// * `graph`    — directed CSR dependency graph.
/// * `modified` — `u32` node indices corresponding to changed files or symbols.
///
/// # Returns
/// A [`BlastRadiusReport`] with the max hop distance and hallucination flag.
/// Returns `max_hop_distance = 0, is_agentic_hallucination = false` when
/// `modified` contains fewer than two distinct nodes.
pub fn compute_blast_radius(graph: &Csr<(), ()>, modified: &[NodeIndex]) -> BlastRadiusReport {
    let m = modified.len();
    if m < 2 {
        return BlastRadiusReport {
            max_hop_distance: 0,
            is_agentic_hallucination: false,
        };
    }

    let n = graph.node_count();
    // pair_dist[i * m + j] = forward BFS distance from modified[i] to modified[j].
    // Allocated from the global heap (O(m²) in modified count, not graph size).
    let mut pair_dist = vec![u32::MAX; m * m];

    // Single arena reused across all BFS runs — reset() reclaims pages without
    // syscall overhead.
    let mut arena = Bump::new();

    for (i, &src) in modified.iter().enumerate() {
        let src_idx = src as usize;
        if src_idx >= n {
            continue; // guard: skip OOB node indices
        }

        // ── Inner scope: arena borrows live only here, dropped before reset() ──
        {
            // Arena-allocated distance array — u32::MAX = "unreachable".
            let dist: &mut [u32] = arena.alloc_slice_fill_with(n, |_| u32::MAX);
            // Arena-allocated BFS queue; head pointer simulates dequeue in O(1).
            let mut queue: BumpVec<'_, NodeIndex> = BumpVec::new_in(&arena);

            dist[src_idx] = 0;
            queue.push(src);

            let mut head: usize = 0;
            while head < queue.len() {
                let node = queue[head];
                head += 1;
                let d = dist[node as usize];
                for &neighbor in graph.neighbors_slice(node) {
                    let ni = neighbor as usize;
                    if dist[ni] == u32::MAX {
                        dist[ni] = d + 1;
                        queue.push(neighbor);
                    }
                }
            }

            // Record forward distances from src to every other modified node.
            for (j, &dst) in modified.iter().enumerate() {
                if i == j {
                    continue;
                }
                let dst_idx = dst as usize;
                if dst_idx < n {
                    pair_dist[i * m + j] = dist[dst_idx];
                }
            }
        } // dist + queue dropped; arena borrows released.

        // Reclaim all pages for the next BFS run — zero OS syscalls.
        arena.reset();
    }

    // ── Derive canonical pairwise distances ────────────────────────────────
    // For unordered pair {a, b}: distance = min(d(a→b), d(b→a)).
    // This handles directed graphs where only one direction has a path.
    let mut max_dist: u32 = 0;
    let mut any_disconnected = false;

    for i in 0..m {
        for j in i + 1..m {
            let d_fwd = pair_dist[i * m + j]; // d(modified[i] → modified[j])
            let d_rev = pair_dist[j * m + i]; // d(modified[j] → modified[i])
            let canonical = d_fwd.min(d_rev);
            if canonical == u32::MAX {
                // No path in either direction — strongest hallucination signal.
                any_disconnected = true;
            } else if canonical > max_dist {
                max_dist = canonical;
            }
        }
    }

    let effective = if any_disconnected { u32::MAX } else { max_dist };
    BlastRadiusReport {
        max_hop_distance: effective,
        is_agentic_hallucination: effective > HALLUCINATION_THRESHOLD,
    }
}
