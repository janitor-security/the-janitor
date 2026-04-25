//! Autonomous cross-service campaign planner (P3-2).
//!
//! Models an environment as a directed [`AttackGraph`] where nodes represent
//! privilege states or discrete vulnerabilities and edges represent exploit
//! steps with an associated cost (complexity, prerequisites, detectability).
//! [`find_shortest_kill_chain`] uses Dijkstra's algorithm to find the
//! minimum-cost path from a public internet entry-point to a crown-jewel node,
//! making multi-hop chain synthesis deterministic and reproducible.

use common::slop::StructuredFinding;
use petgraph::algo::dijkstra;
use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;
use petgraph::Direction;

/// A node in the [`AttackGraph`].
///
/// Nodes are either named privilege states (e.g. `"UnauthenticatedInternet"`,
/// `"AdminDatabase"`) or discrete vulnerabilities wrapping a
/// [`StructuredFinding`] produced by the Janitor detector suite.
#[derive(Debug, Clone)]
pub enum AttackNode {
    /// A named privilege or trust-boundary state.
    PrivilegeState(String),
    /// A concrete finding whose exploitation transitions the attacker to a
    /// higher-privilege state.
    Vulnerability(Box<StructuredFinding>),
}

impl AttackNode {
    /// Returns a human-readable label for graph output.
    pub fn label(&self) -> &str {
        match self {
            AttackNode::PrivilegeState(name) => name.as_str(),
            AttackNode::Vulnerability(f) => f.id.as_str(),
        }
    }

    /// Wrap a finding into a `Vulnerability` node, boxing it to keep enum size small.
    pub fn vulnerability(finding: StructuredFinding) -> Self {
        AttackNode::Vulnerability(Box::new(finding))
    }
}

/// An edge in the [`AttackGraph`] representing one exploit step.
///
/// `cost` encodes the complexity of the step: lower values mean the transition
/// is easier for an attacker.  Dijkstra minimises total cost, so the shortest
/// kill chain is the path that minimises aggregate exploit complexity.
#[derive(Debug, Clone, Copy)]
pub struct ExploitEdge {
    /// Exploit complexity cost (lower = easier for attacker).
    pub cost: u32,
}

/// Directed attack graph used by the campaign planner.
///
/// Wrap a [`petgraph::DiGraph`] so callers interact with the domain-specific
/// API and are shielded from petgraph internals.
#[derive(Debug, Default)]
pub struct AttackGraph(DiGraph<AttackNode, ExploitEdge>);

impl AttackGraph {
    /// Construct an empty graph.
    pub fn new() -> Self {
        Self(DiGraph::new())
    }

    /// Add a node and return its index.
    pub fn add_node(&mut self, node: AttackNode) -> NodeIndex {
        self.0.add_node(node)
    }

    /// Add a directed edge from `from` to `to` with the given exploit `cost`.
    pub fn add_edge(&mut self, from: NodeIndex, to: NodeIndex, cost: u32) {
        self.0.add_edge(from, to, ExploitEdge { cost });
    }

    /// Return an immutable reference to the underlying petgraph.
    pub fn inner(&self) -> &DiGraph<AttackNode, ExploitEdge> {
        &self.0
    }

    /// Find the minimum-cost kill chain from `start` to `crown_jewel`.
    ///
    /// Uses Dijkstra's algorithm over the graph, treating each edge's `cost`
    /// as the distance weight.  Returns the ordered sequence of [`NodeIndex`]
    /// values from `start` to `crown_jewel` (inclusive), or `None` when no
    /// path exists.
    ///
    /// The result is deterministic: given the same graph state and node
    /// indices, this function always produces the same output.
    pub fn find_shortest_kill_chain(
        &self,
        start: NodeIndex,
        crown_jewel: NodeIndex,
    ) -> Option<Vec<NodeIndex>> {
        // Dijkstra returns the minimum-cost map from `start` to all reachable nodes.
        let distances = dijkstra(&self.0, start, Some(crown_jewel), |e| e.weight().cost);

        if !distances.contains_key(&crown_jewel) {
            return None;
        }

        // Reconstruct path by walking backwards from crown_jewel to start.
        // At each step, select the incoming neighbor whose distance plus the
        // connecting edge cost equals the current node's distance (integer
        // arithmetic is exact, so no floating-point ambiguity).
        let mut path = vec![crown_jewel];
        let mut current = crown_jewel;

        while current != start {
            let current_dist = *distances.get(&current)?;
            let predecessor = self
                .0
                .edges_directed(current, Direction::Incoming)
                .find_map(|e| {
                    let src = e.source();
                    let src_dist = *distances.get(&src)?;
                    if src_dist.saturating_add(e.weight().cost) == current_dist {
                        Some(src)
                    } else {
                        None
                    }
                })?;
            path.push(predecessor);
            current = predecessor;
        }

        path.reverse();
        Some(path)
    }

    /// Return the labels of all nodes in a kill chain for human-readable output.
    pub fn chain_labels(&self, chain: &[NodeIndex]) -> Vec<&str> {
        chain.iter().map(|idx| self.0[*idx].label()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn privilege(name: &str) -> AttackNode {
        AttackNode::PrivilegeState(name.to_string())
    }

    fn vuln(id: &str) -> AttackNode {
        AttackNode::Vulnerability(Box::new(StructuredFinding {
            id: id.to_string(),
            ..StructuredFinding::default()
        }))
    }

    #[test]
    fn find_shortest_kill_chain_finds_direct_path() {
        let mut graph = AttackGraph::new();
        let internet = graph.add_node(privilege("UnauthenticatedInternet"));
        let crown = graph.add_node(privilege("AdminDatabase"));
        graph.add_edge(internet, crown, 10);

        let chain = graph
            .find_shortest_kill_chain(internet, crown)
            .expect("direct path must be found");
        assert_eq!(chain, vec![internet, crown]);
    }

    #[test]
    fn find_shortest_kill_chain_selects_minimum_cost_path() {
        // Two paths: direct (cost 100) vs indirect via vuln (cost 5+5=10).
        let mut graph = AttackGraph::new();
        let start = graph.add_node(privilege("UnauthenticatedInternet"));
        let mid = graph.add_node(vuln("security:ssrf_bypass"));
        let crown = graph.add_node(privilege("SecretStore"));

        graph.add_edge(start, crown, 100); // expensive direct route
        graph.add_edge(start, mid, 5); // cheap hop through vuln
        graph.add_edge(mid, crown, 5); // cheap second hop

        let chain = graph
            .find_shortest_kill_chain(start, crown)
            .expect("path must exist");
        assert_eq!(
            chain,
            vec![start, mid, crown],
            "planner must select the cheaper indirect path"
        );
    }

    #[test]
    fn find_shortest_kill_chain_returns_none_when_unreachable() {
        let mut graph = AttackGraph::new();
        let a = graph.add_node(privilege("NodeA"));
        let b = graph.add_node(privilege("NodeB"));
        // No edge added — unreachable.
        assert!(
            graph.find_shortest_kill_chain(a, b).is_none(),
            "must return None when no path exists"
        );
    }

    #[test]
    fn chain_labels_returns_human_readable_sequence() {
        let mut graph = AttackGraph::new();
        let internet = graph.add_node(privilege("UnauthenticatedInternet"));
        let vuln_node = graph.add_node(vuln("security:sqli_concatenation"));
        let db = graph.add_node(privilege("AdminDatabase"));
        graph.add_edge(internet, vuln_node, 3);
        graph.add_edge(vuln_node, db, 2);

        let chain = graph
            .find_shortest_kill_chain(internet, db)
            .expect("path must exist");
        let labels = graph.chain_labels(&chain);
        assert_eq!(
            labels,
            vec![
                "UnauthenticatedInternet",
                "security:sqli_concatenation",
                "AdminDatabase"
            ]
        );
    }
}
