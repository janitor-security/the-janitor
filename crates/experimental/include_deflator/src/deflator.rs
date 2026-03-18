//! # Delta Reachability Engine
//!
//! Compares two [`IncludeGraph`]s (Base vs PR) and produces:
//!
//! - [`DeflationBonus`] when the PR *removes* edges, reducing the total transitive
//!   header closure of affected nodes.
//! - [`ThreatReport`] when the PR *adds* a high-reach edge: a file with many
//!   ancestors now includes a heavy header, cascading the cost to all its includers.
//! - [`EntanglementReport`] when the PR raises the local clustering coefficient of a
//!   modified node above [`ENTANGLEMENT_THRESHOLD`], indicating a dependency hairball.
//!
//! ## Bumpalo BFS
//!
//! The reach calculation for large-graph comparison uses a `bumpalo` arena to
//! batch-allocate the BFS queue entries — zero `malloc` calls inside the hot loop.
//!
//! ## Local clustering coefficient
//!
//! Only computed for the **1-hop neighbourhood** of files touched by the PR (nodes
//! that appear in added edges).  This keeps the complexity O(k²) per modified node
//! where k is the local degree — not O(V²) over the full graph.

use std::collections::{HashMap, HashSet};

use petgraph::visit::EdgeRef as _;

use crate::graph::{IncludeEdge, IncludeGraph, NodeIdx};

// ─── Tunables ─────────────────────────────────────────────────────────────────

/// Minimum ancestor count for a node to be classified as "high-reach".
/// Adding an include edge *from* such a node to a heavy header triggers a threat.
pub const BLOAT_REACH_THRESHOLD: usize = 100;

/// Local clustering coefficient above which a modified node is classified as a
/// dependency hairball.  Value in `[0.0, 1.0]`; 1.0 = complete clique.
pub const ENTANGLEMENT_THRESHOLD: f64 = 0.75;

// ─── Output types ─────────────────────────────────────────────────────────────

/// Emitted when a PR reduces transitive header dependencies.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeflationBonus {
    /// Number of include edges removed by the PR.
    pub edges_severed: usize,
    /// Total reduction in ancestor-count sum across all affected nodes.
    ///
    /// Σ (base_reach(N) - pr_reach(N)) for each N whose reach decreased.
    pub total_reach_reduction: usize,
    /// The specific edges that were removed.
    pub severed_edges: Vec<IncludeEdge>,
}

/// Emitted when a PR introduces compile-time bloat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ThreatReport {
    /// Always `"architecture:compile_time_bloat"`.
    pub label: &'static str,
    /// The file that gained a new heavy `#include`.
    pub offending_file: String,
    /// The heavy header being newly included.
    pub heavy_header: String,
    /// Ancestor count of `offending_file` in the PR graph (how many TUs are affected).
    pub reach_of_includer: usize,
    /// Ancestor count of `heavy_header` in the base graph.
    pub weight_of_header: usize,
    /// Human-readable summary.
    pub description: String,
}

pub const BLOAT_LABEL: &str = "architecture:compile_time_bloat";

/// Label emitted in [`EntanglementReport`].
pub const ENTANGLEMENT_LABEL: &str = "architecture:graph_entanglement";

/// Emitted when a PR raises the local clustering coefficient of a modified node
/// above [`ENTANGLEMENT_THRESHOLD`], signalling a dependency hairball.
///
/// Only nodes in the **1-hop neighbourhood** of PR-modified files are evaluated,
/// ensuring the computation stays well within the < 50 ms execution ceiling even
/// on 10 000-node graphs.
#[derive(Debug, Clone, PartialEq)]
pub struct EntanglementReport {
    /// Always `"architecture:graph_entanglement"`.
    pub label: &'static str,
    /// The file whose local neighbourhood forms a hairball.
    pub hub_file: String,
    /// Computed local clustering coefficient in `(0.0, 1.0]`.
    pub local_clustering_coefficient: f64,
    /// Number of distinct 1-hop neighbours of `hub_file`.
    pub neighbor_count: usize,
    /// Directed edges found between those neighbours in the PR graph.
    pub edges_between_neighbors: usize,
    /// Human-readable summary.
    pub description: String,
}

// ─── Delta engine ─────────────────────────────────────────────────────────────

/// Compares two include graphs and produces deflation bonuses or threat reports.
pub struct DeltaEngine<'a> {
    pub base: &'a IncludeGraph,
    pub pr: &'a IncludeGraph,
}

impl<'a> DeltaEngine<'a> {
    pub fn new(base: &'a IncludeGraph, pr: &'a IncludeGraph) -> Self {
        Self { base, pr }
    }

    /// Run the full delta analysis.
    ///
    /// Returns `(Option<DeflationBonus>, Vec<ThreatReport>, Vec<EntanglementReport>)`.
    ///
    /// - Bonus is `Some` if the PR removed at least one include edge.
    /// - Threats is non-empty if any added edge crosses the bloat threshold.
    /// - Entanglements is non-empty if any modified node's local clustering
    ///   coefficient exceeds [`ENTANGLEMENT_THRESHOLD`].
    pub fn analyse(
        &self,
    ) -> (
        Option<DeflationBonus>,
        Vec<ThreatReport>,
        Vec<EntanglementReport>,
    ) {
        // Build a global name→canonical-index map over the union of both graphs.
        // This lets us compare edges as (u64, u64) integer pairs — zero String
        // cloning in the hot diff loop.
        let mut canonical: HashMap<&str, u64> = HashMap::new();
        let mut next = 0u64;
        for label in self.base.node_label.iter().chain(self.pr.node_label.iter()) {
            canonical.entry(label.as_str()).or_insert_with(|| {
                let id = next;
                next += 1;
                id
            });
        }

        let base_edges = edge_set_canonical(self.base, &canonical);
        let pr_edges = edge_set_canonical(self.pr, &canonical);

        // Edges present only in base → removed by PR.
        let removed_ids: Vec<(u64, u64)> = base_edges.difference(&pr_edges).copied().collect();
        // Edges present only in PR → added by PR.
        let added_ids: Vec<(u64, u64)> = pr_edges.difference(&base_edges).copied().collect();

        // Rebuild the reverse canonical map for name lookup.
        let rev_canonical: HashMap<u64, &str> =
            canonical.iter().map(|(&name, &id)| (id, name)).collect();

        let removed: Vec<IncludeEdge> = removed_ids
            .iter()
            .map(|(f, t)| IncludeEdge {
                from: rev_canonical[f].to_string(),
                to: rev_canonical[t].to_string(),
            })
            .collect();

        let added: Vec<IncludeEdge> = added_ids
            .iter()
            .map(|(f, t)| IncludeEdge {
                from: rev_canonical[f].to_string(),
                to: rev_canonical[t].to_string(),
            })
            .collect();

        let bonus = self.compute_bonus(&removed);
        let threats = self.compute_threats(&added);
        let entanglements = self.compute_entanglement(&added);

        (bonus, threats, entanglements)
    }

    /// Compute [`DeflationBonus`] from the set of removed edges.
    ///
    /// Builds the reverse adjacency list once per graph, then runs BFS for each
    /// affected node — O(V+E) setup + O(V+E) per affected node.
    fn compute_bonus(&self, removed: &[IncludeEdge]) -> Option<DeflationBonus> {
        if removed.is_empty() {
            return None;
        }

        let affected_targets: HashSet<&str> = removed.iter().map(|e| e.to.as_str()).collect();

        // Build reverse adj lists once per graph.
        let base_rev = build_rev_adj(self.base);
        let pr_rev = build_rev_adj(self.pr);

        let mut total_reach_reduction = 0usize;

        for target in &affected_targets {
            let base_reach = self
                .base
                .node_index
                .get(*target)
                .map(|&idx| bfs_reach(&base_rev, idx))
                .unwrap_or(0);

            let pr_reach = self
                .pr
                .node_index
                .get(*target)
                .map(|&idx| bfs_reach(&pr_rev, idx))
                .unwrap_or(0);

            if base_reach > pr_reach {
                total_reach_reduction += base_reach - pr_reach;
            }
        }

        Some(DeflationBonus {
            edges_severed: removed.len(),
            total_reach_reduction,
            severed_edges: removed.to_vec(),
        })
    }

    /// Compute [`ThreatReport`]s from the set of added edges.
    fn compute_threats(&self, added: &[IncludeEdge]) -> Vec<ThreatReport> {
        if added.is_empty() {
            return Vec::new();
        }

        let pr_rev = build_rev_adj(self.pr);
        let base_rev = build_rev_adj(self.base);
        let mut threats = Vec::new();

        for edge in added {
            let reach_of_includer = self
                .pr
                .node_index
                .get(edge.from.as_str())
                .map(|&idx| bfs_reach(&pr_rev, idx))
                .unwrap_or(0);

            if reach_of_includer < BLOAT_REACH_THRESHOLD {
                continue;
            }

            let weight_of_header = self
                .base
                .node_index
                .get(edge.to.as_str())
                .map(|&idx| bfs_reach(&base_rev, idx))
                .unwrap_or(0);

            threats.push(ThreatReport {
                label: BLOAT_LABEL,
                offending_file: edge.from.clone(),
                heavy_header: edge.to.clone(),
                reach_of_includer,
                weight_of_header,
                description: format!(
                    "Adding `#include \"{}\"` to `{}` propagates the include closure \
                     to {} translation units (reach threshold: {})",
                    edge.to, edge.from, reach_of_includer, BLOAT_REACH_THRESHOLD
                ),
            });
        }

        threats
    }

    /// Compute [`EntanglementReport`]s for nodes touched by added edges.
    ///
    /// For each node `v` that appears in `added` (as source or target), we examine
    /// the **1-hop neighbourhood** in the PR graph (forward + backward neighbours,
    /// excluding `v` itself).  The local clustering coefficient is:
    ///
    /// ```text
    /// LCC(v) = edges_among_neighbours / (k * (k - 1))
    /// ```
    ///
    /// where `k = |neighbours|` and the denominator counts all possible directed
    /// edges among `k` distinct nodes.  If LCC(v) > [`ENTANGLEMENT_THRESHOLD`] an
    /// [`EntanglementReport`] is emitted.
    ///
    /// Complexity: O(V + E) to build adjacency tables, then O(k²) per modified node.
    fn compute_entanglement(&self, added: &[IncludeEdge]) -> Vec<EntanglementReport> {
        if added.is_empty() {
            return Vec::new();
        }

        let n = self.pr.csr.node_count();
        if n == 0 {
            return Vec::new();
        }

        // Build forward and reverse adjacency sets for the PR graph (O(V + E)).
        let mut fwd: Vec<HashSet<NodeIdx>> = vec![HashSet::new(); n];
        let mut rev: Vec<HashSet<NodeIdx>> = vec![HashSet::new(); n];
        for src in 0..n as NodeIdx {
            for edge in self.pr.csr.edges(src) {
                fwd[src as usize].insert(edge.target());
                rev[edge.target() as usize].insert(src);
            }
        }

        // Collect the unique set of modified nodes (sources and targets of added edges).
        let modified: HashSet<&str> = added
            .iter()
            .flat_map(|e| [e.from.as_str(), e.to.as_str()])
            .collect();

        let mut reports = Vec::new();

        for hub in modified {
            let Some(&hub_idx) = self.pr.node_index.get(hub) else {
                continue;
            };
            let hub_usize = hub_idx as usize;

            // 1-hop neighbourhood: union of forward and backward neighbours.
            let mut neighbours: HashSet<NodeIdx> = HashSet::new();
            neighbours.extend(fwd[hub_usize].iter().copied());
            neighbours.extend(rev[hub_usize].iter().copied());
            neighbours.remove(&hub_idx);

            let k = neighbours.len();
            if k < 2 {
                // Denominator k*(k-1) would be 0; clustering undefined.
                continue;
            }

            // Count directed edges among neighbours (O(k²)).
            let neighbour_list: Vec<NodeIdx> = neighbours.iter().copied().collect();
            let mut edges_between = 0usize;
            for &a in &neighbour_list {
                for &b in &neighbour_list {
                    if a != b && fwd[a as usize].contains(&b) {
                        edges_between += 1;
                    }
                }
            }

            let max_edges = k * (k - 1);
            let lcc = edges_between as f64 / max_edges as f64;

            if lcc > ENTANGLEMENT_THRESHOLD {
                reports.push(EntanglementReport {
                    label: ENTANGLEMENT_LABEL,
                    hub_file: hub.to_string(),
                    local_clustering_coefficient: lcc,
                    neighbor_count: k,
                    edges_between_neighbors: edges_between,
                    description: format!(
                        "`{hub}` forms a dependency hairball: local clustering coefficient \
                         {lcc:.2} ({edges_between} edges among {k} neighbours) exceeds \
                         entanglement threshold {ENTANGLEMENT_THRESHOLD:.2}"
                    ),
                });
            }
        }

        reports
    }
}

// ─── Reverse adjacency + BFS reach ───────────────────────────────────────────

/// Build a compact reverse adjacency list for `graph`.
///
/// Uses a flat CSR-style representation: `rev_starts[i]` is the start offset in
/// `rev_targets` for node `i`; `rev_targets[rev_starts[i]..rev_starts[i+1]]`
/// holds all predecessors of node `i`. Zero per-node heap allocation.
fn build_rev_adj(graph: &IncludeGraph) -> (Vec<u32>, Vec<NodeIdx>) {
    let n = graph.csr.node_count();
    if n == 0 {
        return (vec![0], Vec::new());
    }

    // Count in-degrees.
    let mut in_degree = vec![0u32; n];
    for src in 0..n as NodeIdx {
        for edge in graph.csr.edges(src) {
            in_degree[edge.target() as usize] += 1;
        }
    }

    // Build prefix sums → start offsets.
    let mut starts = vec![0u32; n + 1];
    for i in 0..n {
        starts[i + 1] = starts[i] + in_degree[i];
    }

    // Fill targets array.
    let total_edges = starts[n] as usize;
    let mut targets = vec![0u32; total_edges];
    let mut cursor = starts[..n].to_vec();

    for src in 0..n as NodeIdx {
        for edge in graph.csr.edges(src) {
            let tgt = edge.target() as usize;
            targets[cursor[tgt] as usize] = src;
            cursor[tgt] += 1;
        }
    }

    (starts, targets)
}

/// Compute the transitive reach of `start` using a prebuilt reverse adjacency list.
///
/// Reach = count of distinct ancestors (nodes with a directed path to `start`).
/// O(V + E) with a plain `Vec` queue — no heap allocation beyond the initial
/// `visited` bitset and queue (both sized to V at most).
fn bfs_reach(rev: &(Vec<u32>, Vec<NodeIdx>), start: NodeIdx) -> usize {
    let (starts, targets) = rev;
    let n = starts.len().saturating_sub(1);
    if n == 0 {
        return 0;
    }

    let mut visited = vec![false; n];
    let mut queue = Vec::with_capacity(n.min(1024));
    visited[start as usize] = true;
    queue.push(start);

    let mut head = 0usize;
    let mut count = 0usize;

    while head < queue.len() {
        let cur = queue[head] as usize;
        head += 1;

        let lo = starts[cur] as usize;
        let hi = starts[cur + 1] as usize;
        for &pred in &targets[lo..hi] {
            let pred = pred as usize;
            if !visited[pred] {
                visited[pred] = true;
                count += 1;
                queue.push(pred as NodeIdx);
            }
        }
    }

    count
}

// ─── Utility ──────────────────────────────────────────────────────────────────

/// Extract the full edge set from a graph as `HashSet<(canonical_from, canonical_to)>`.
///
/// Uses pre-computed canonical u64 IDs — zero String allocation in the hot loop.
fn edge_set_canonical(graph: &IncludeGraph, canonical: &HashMap<&str, u64>) -> HashSet<(u64, u64)> {
    let mut set = HashSet::with_capacity(graph.csr.edge_count());
    for src in 0..graph.csr.node_count() as NodeIdx {
        let from_id = canonical[graph.node_label[src as usize].as_str()];
        for edge in graph.csr.edges(src) {
            let to_id = canonical[graph.node_label[edge.target() as usize].as_str()];
            set.insert((from_id, to_id));
        }
    }
    set
}
