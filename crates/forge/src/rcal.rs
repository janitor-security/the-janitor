//! Root Cause Abstraction Lattice (RCAL) — domination lattice + causality scoring.
//!
//! Two independent layers:
//!
//! **Layer 1 — Domination tree** (`DominationTree`, `RootCause`, `find_root_causes`):
//! Maps a set of `StructuredFinding` leaf nodes back to their dominating caller in a
//! `CallGraph`, collapsing N findings that originate from one unsanitised helper into a
//! single `RootCause` capsule.  Uses `petgraph::algo::dominators::simple_fast` (Cooper
//! et al O(V²) with fast practical performance on call graphs < 30 000 nodes).
//!
//! **Layer 2 — Causality vectors** (`CausalityVector`, `ProvenInvariant`,
//! `evaluate_proven_invariants`):
//! Propensity-score evidence pairing sanitizer paths with vulnerability classes over a
//! repository cohort.  A sanitizer becomes a proven invariant when the clean-rate over
//! the cohort exceeds the configured threshold.

use crate::callgraph::CallGraph;
use common::slop::StructuredFinding;
use petgraph::algo::dominators::simple_fast;
use petgraph::graph::NodeIndex;
use std::collections::{BTreeMap, HashMap, HashSet};

// ============================================================================
// Layer 1 — Domination Tree
// ============================================================================

/// A root cause capsule grouping dominated findings under one repair task.
///
/// Emitted by [`find_root_causes`] when multiple findings share the same
/// dominator in the call graph — meaning a single fix at `node` closes every
/// finding in `dominated_findings`.
#[derive(Debug, Clone)]
pub struct RootCause {
    /// Index of the dominating call-graph node (the repair point).
    pub node: NodeIndex,
    /// Finding IDs dominated by this node.
    pub dominated_findings: Vec<String>,
    /// Human-readable minimum fix specification.
    pub fix_spec: String,
}

/// Compute the least-common-ancestor of `nodes` in the dominator tree.
///
/// The LCA is the deepest node in the dominator tree that dominates every
/// element of `nodes`.  Runs `simple_fast` once per call; cache the result
/// externally when calling repeatedly over the same graph.
///
/// Returns `None` when `nodes` is empty, when `graph` has no nodes, or when
/// any node is unreachable from `root`.
pub fn lca_in_domtree(
    graph: &CallGraph,
    root: NodeIndex,
    nodes: &[NodeIndex],
) -> Option<NodeIndex> {
    if nodes.is_empty() || graph.node_count() == 0 {
        return None;
    }
    if nodes.len() == 1 {
        return Some(nodes[0]);
    }
    let doms = simple_fast(graph, root);
    // For each node, collect the dominator chain from the node up to root.
    let chains: Vec<Vec<NodeIndex>> = nodes
        .iter()
        .map(|&n| {
            doms.dominators(n)
                .map(|it| it.collect::<Vec<_>>())
                .unwrap_or_default()
        })
        .collect();
    if chains.iter().any(|c| c.is_empty()) {
        return None;
    }
    // Build HashSets for chain[1..] for O(1) membership tests.
    let tail_sets: Vec<HashSet<NodeIndex>> = chains[1..]
        .iter()
        .map(|c| c.iter().copied().collect())
        .collect();
    // Walk chain[0] from leaf toward root; the first node present in every
    // tail set is the deepest common dominator (the LCA).
    chains[0]
        .iter()
        .copied()
        .find(|n| tail_sets.iter().all(|s| s.contains(n)))
}

/// Collapse `findings` under their dominator root causes in `graph`.
///
/// Each entry is `(function_name, finding_id)`.  Findings whose function
/// name is not a node in `graph` are silently skipped.  All findings that
/// share the same least-common-ancestor are collapsed into one [`RootCause`]
/// capsule; if they share no common dominator an empty vec is returned.
pub fn find_root_causes(
    graph: &CallGraph,
    root: NodeIndex,
    findings: &[(&str, &str)],
) -> Vec<RootCause> {
    if findings.is_empty() || graph.node_count() == 0 {
        return Vec::new();
    }
    let name_to_node: HashMap<&str, NodeIndex> = graph
        .node_indices()
        .filter_map(|n| graph.node_weight(n).map(|s| (s.as_str(), n)))
        .collect();
    let located: Vec<(NodeIndex, String)> = findings
        .iter()
        .filter_map(|(fn_name, finding_id)| {
            name_to_node
                .get(fn_name)
                .map(|&n| (n, finding_id.to_string()))
        })
        .collect();
    if located.is_empty() {
        return Vec::new();
    }
    let nodes: Vec<NodeIndex> = located.iter().map(|(n, _)| *n).collect();
    let lca = match lca_in_domtree(graph, root, &nodes) {
        Some(n) => n,
        None => return Vec::new(),
    };
    let fn_name = graph
        .node_weight(lca)
        .map(String::as_str)
        .unwrap_or("unknown");
    let dominated_findings: Vec<String> = located.iter().map(|(_, id)| id.clone()).collect();
    vec![RootCause {
        node: lca,
        dominated_findings: dominated_findings.clone(),
        fix_spec: format!(
            "Add input sanitization in `{fn_name}` to remediate {} dominated findings.",
            dominated_findings.len()
        ),
    }]
}

// ============================================================================
// Layer 2 — Causality Vectors
// ============================================================================

/// Propensity-score style evidence for one sanitizer and vulnerability class.
#[derive(Debug, Clone, PartialEq)]
pub struct CausalityVector {
    /// Sanitizer or validator path being evaluated.
    pub sanitizer_path: String,
    /// Vulnerability family or concrete finding class.
    pub finding_class: String,
    /// Number of comparable repositories using this sanitizer path.
    pub repos_observed: u32,
    /// Number of comparable repositories with zero findings in `finding_class`.
    pub clean_repos: u32,
}

impl CausalityVector {
    /// Return the clean percentage for this vector.
    pub fn clean_rate_pct(&self) -> f64 {
        if self.repos_observed == 0 {
            return 0.0;
        }
        self.clean_repos as f64 / self.repos_observed as f64 * 100.0
    }
}

/// Sanitizer/class pair that cleared the PSM clean-rate threshold.
#[derive(Debug, Clone, PartialEq)]
pub struct ProvenInvariant {
    /// Sanitizer path that behaved as an invariant.
    pub sanitizer_path: String,
    /// Finding class suppressed by the invariant.
    pub finding_class: String,
    /// Repositories in the matched cohort.
    pub repos_observed: u32,
    /// Clean repositories in the matched cohort.
    pub clean_repos: u32,
    /// Clean percentage over the cohort.
    pub clean_rate_pct: f64,
}

/// Evaluate sanitizer causality vectors and return proven invariants.
pub fn evaluate_proven_invariants(
    vectors: &[CausalityVector],
    threshold_pct: f64,
) -> Vec<ProvenInvariant> {
    let mut grouped: BTreeMap<(&str, &str), (u32, u32)> = BTreeMap::new();
    for vector in vectors {
        if vector.repos_observed == 0 {
            continue;
        }
        let entry = grouped
            .entry((&vector.sanitizer_path, &vector.finding_class))
            .or_default();
        entry.0 = entry.0.saturating_add(vector.repos_observed);
        entry.1 = entry.1.saturating_add(vector.clean_repos);
    }

    grouped
        .into_iter()
        .filter_map(
            |((sanitizer_path, finding_class), (repos_observed, clean_repos))| {
                if repos_observed == 0 {
                    return None;
                }
                let clean_rate_pct = clean_repos as f64 / repos_observed as f64 * 100.0;
                (clean_rate_pct >= threshold_pct).then(|| ProvenInvariant {
                    sanitizer_path: sanitizer_path.to_string(),
                    finding_class: finding_class.to_string(),
                    repos_observed,
                    clean_repos,
                    clean_rate_pct,
                })
            },
        )
        .collect()
}

/// Build defensive evidence text for Bugcrowd-style reports.
pub fn defensive_evidence_for_findings(findings: &[&StructuredFinding]) -> Option<String> {
    let mut vectors = Vec::new();
    for finding in findings {
        let Some(witness) = finding.exploit_witness.as_ref() else {
            continue;
        };
        let Some(audit) = witness.sanitizer_audit.as_deref() else {
            continue;
        };
        vectors.extend(parse_causality_vectors(&finding.id, audit));
    }

    let invariants = evaluate_proven_invariants(&vectors, 90.0);
    if invariants.is_empty() {
        return None;
    }

    let lines = invariants
        .iter()
        .map(|invariant| {
            format!(
                "- Proven Invariant: `{}` kept `{}` clean in {}/{} matched repos ({:.1}%).",
                invariant.sanitizer_path,
                invariant.finding_class,
                invariant.clean_repos,
                invariant.repos_observed,
                invariant.clean_rate_pct
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    Some(lines)
}

fn parse_causality_vectors(finding_class: &str, audit: &str) -> Vec<CausalityVector> {
    let mut vectors = Vec::new();
    for sanitizer in bracketed_sanitizers(audit) {
        if let Some((clean_repos, repos_observed)) = parse_repo_ratio_after(audit, &sanitizer) {
            vectors.push(CausalityVector {
                sanitizer_path: sanitizer,
                finding_class: finding_class.to_string(),
                repos_observed,
                clean_repos,
            });
        }
    }
    vectors
}

fn bracketed_sanitizers(audit: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = audit;
    while let Some(start) = rest.find('[') {
        let after = &rest[start + 1..];
        let Some(end) = after.find(']') else {
            break;
        };
        for part in after[..end].split(',') {
            let sanitizer = part.trim();
            if !sanitizer.is_empty() {
                out.push(sanitizer.to_string());
            }
        }
        rest = &after[end + 1..];
    }
    out.sort();
    out.dedup();
    out
}

fn parse_repo_ratio_after(audit: &str, sanitizer: &str) -> Option<(u32, u32)> {
    let index = audit.find(sanitizer)?;
    let tail = &audit[index..];
    parse_ratio(tail).or_else(|| parse_percent(tail).map(|pct| (pct as u32, 100)))
}

fn parse_ratio(text: &str) -> Option<(u32, u32)> {
    for token in text.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '/');
        let Some((left, right)) = trimmed.split_once('/') else {
            continue;
        };
        let clean = left.parse::<u32>().ok()?;
        let total = right.parse::<u32>().ok()?;
        if total > 0 && clean <= total {
            return Some((clean, total));
        }
    }
    None
}

fn parse_percent(text: &str) -> Option<f64> {
    for token in text.split_whitespace() {
        let trimmed = token.trim_matches(|ch: char| !ch.is_ascii_digit() && ch != '.');
        if token.contains('%') {
            let pct = trimmed.parse::<f64>().ok()?;
            if (0.0..=100.0).contains(&pct) {
                return Some(pct);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causality_vector_promotes_sanitizer_to_proven_invariant() {
        let vectors = vec![
            CausalityVector {
                sanitizer_path: "escapeHtml".to_string(),
                finding_class: "security:dom_xss_innerHTML".to_string(),
                repos_observed: 10,
                clean_repos: 9,
            },
            CausalityVector {
                sanitizer_path: "escapeHtml".to_string(),
                finding_class: "security:dom_xss_innerHTML".to_string(),
                repos_observed: 10,
                clean_repos: 10,
            },
        ];

        let invariants = evaluate_proven_invariants(&vectors, 90.0);

        assert_eq!(invariants.len(), 1);
        assert_eq!(invariants[0].sanitizer_path, "escapeHtml");
        assert_eq!(invariants[0].repos_observed, 20);
        assert_eq!(invariants[0].clean_repos, 19);
        assert!(invariants[0].clean_rate_pct >= 95.0);
    }

    #[test]
    fn causality_vector_rejects_low_clean_rate() {
        let vectors = vec![CausalityVector {
            sanitizer_path: "escapeHtml".to_string(),
            finding_class: "security:ssrf".to_string(),
            repos_observed: 10,
            clean_repos: 6,
        }];

        assert!(evaluate_proven_invariants(&vectors, 90.0).is_empty());
    }

    #[test]
    fn defensive_evidence_extracts_repo_ratio_from_sanitizer_audit() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            exploit_witness: Some(common::slop::ExploitWitness {
                sanitizer_audit: Some(
                    "Path sanitizers [escapeHtml] matched PSM cohort 19/20 clean repos."
                        .to_string(),
                ),
                ..Default::default()
            }),
            ..Default::default()
        };

        let evidence = defensive_evidence_for_findings(&[&finding])
            .expect("PSM ratio must produce defensive evidence");

        assert!(evidence.contains("Proven Invariant"));
        assert!(evidence.contains("escapeHtml"));
        assert!(evidence.contains("19/20"));
    }

    // -----------------------------------------------------------------------
    // Layer 1 — Domination tree tests
    // -----------------------------------------------------------------------

    #[test]
    fn three_findings_with_shared_caller_collapse_under_one_root_cause() {
        use crate::callgraph::build_call_graph;
        // Call graph: root_entry → shared_helper → {leaf_a, leaf_b, leaf_c}
        // Findings are in leaf_a, leaf_b, leaf_c.
        // Expected: shared_helper dominates all three leaves → one RootCause.
        let source = b"\
def root_entry():
    shared_helper()

def shared_helper():
    leaf_a()
    leaf_b()
    leaf_c()

def leaf_a():
    pass

def leaf_b():
    pass

def leaf_c():
    pass
";
        let graph = build_call_graph("py", source);
        let root_node = graph
            .node_indices()
            .find(|&n| {
                graph
                    .node_weight(n)
                    .map(|s| s == "root_entry")
                    .unwrap_or(false)
            })
            .expect("root_entry must be in the call graph");

        let findings = [
            ("leaf_a", "security:sqli"),
            ("leaf_b", "security:sqli"),
            ("leaf_c", "security:sqli"),
        ];
        let root_causes = find_root_causes(&graph, root_node, &findings);

        assert_eq!(
            root_causes.len(),
            1,
            "three dominated findings must collapse to one RootCause capsule"
        );
        assert_eq!(
            root_causes[0].dominated_findings.len(),
            3,
            "all three finding IDs must appear in the capsule"
        );
        let rc_fn = graph.node_weight(root_causes[0].node).unwrap();
        assert_eq!(
            rc_fn, "shared_helper",
            "root cause node must be the shared upstream caller"
        );
    }

    #[test]
    fn single_finding_produces_singleton_root_cause() {
        use crate::callgraph::build_call_graph;
        // `only_fn` must be a callee so the graph includes it as a node.
        let source = b"\
def root():
    only_fn()

def only_fn():
    pass
";
        let graph = build_call_graph("py", source);
        let root = graph
            .node_indices()
            .find(|&n| graph.node_weight(n).map(|s| s == "root").unwrap_or(false))
            .expect("root must be in the call graph");
        let findings = [("only_fn", "security:xss")];
        let root_causes = find_root_causes(&graph, root, &findings);
        assert_eq!(root_causes.len(), 1);
        assert_eq!(root_causes[0].dominated_findings.len(), 1);
    }

    #[test]
    fn empty_findings_returns_empty_root_causes() {
        use petgraph::graph::DiGraph;
        // find_root_causes returns empty immediately when findings is empty,
        // regardless of graph structure.
        let graph: CallGraph = DiGraph::new();
        let root_causes = find_root_causes(&graph, NodeIndex::new(0), &[]);
        assert!(root_causes.is_empty());
    }
}
