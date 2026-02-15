use petgraph::graph::DiGraph;
use petgraph::visit::EdgeRef;
use petgraph::Direction;
use std::collections::{HashSet, VecDeque};

pub struct SymbolOracle;

impl SymbolOracle {
    /// Computes the list of "dead" symbol IDs.
    ///
    /// # Algorithm
    /// 1. **The Universe**: Start with a list of ALL node IDs in the graph.
    /// 2. **The Living**: Identify all nodes reachable from `entry_points`.
    /// 3. **The Evidence**: Union the "Reachable" set with `live_ids` (from Lazarus) and `wisdom_protected` (from Heuristics).
    /// 4. **The Verdict**: Any node NOT in the "Living/Evidence" set is **DEAD**.
    ///
    /// # Arguments
    /// * `graph` - The dependency graph where nodes are Symbol IDs (u64).
    /// * `entry_points` - List of symbol IDs that are considered roots (e.g., main functions, API endpoints).
    /// * `live_ids` - Set of symbol IDs found in runtime logs (Lazarus).
    /// * `wisdom_protected` - Set of symbol IDs protected by static analysis heuristics.
    pub fn compute_kill_list(
        graph: &DiGraph<u64, ()>,
        entry_points: &[u64],
        live_ids: &HashSet<u64>,
        wisdom_protected: &HashSet<u64>,
    ) -> Vec<u64> {
        let node_count = graph.node_count();
        if node_count == 0 {
            return Vec::new();
        }

        // 1. Map u64 IDs to NodeIndices and identify BFS starts
        // Optimization: We iterate the graph once to build the queue and the entry set.
        let entry_point_set: HashSet<u64> = entry_points.iter().cloned().collect();
        let mut visited_indices: HashSet<usize> = HashSet::with_capacity(node_count);
        let mut queue = VecDeque::new();

        for idx in graph.node_indices() {
            let id = graph[idx];
            if entry_point_set.contains(&id) {
                visited_indices.insert(idx.index());
                queue.push_back(idx);
            }
        }

        // 2. BFS for Reachability ("The Living")
        while let Some(node_idx) = queue.pop_front() {
            for edge in graph.edges_directed(node_idx, Direction::Outgoing) {
                let target_idx = edge.target();
                if !visited_indices.contains(&target_idx.index()) {
                    visited_indices.insert(target_idx.index());
                    queue.push_back(target_idx);
                }
            }
        }

        // 3. & 4. The Verdict
        let mut kill_list = Vec::new();

        for idx in graph.node_indices() {
            let id = graph[idx];
            let is_reachable = visited_indices.contains(&idx.index());
            let is_live = live_ids.contains(&id);
            let is_protected = wisdom_protected.contains(&id);

            // Any node NOT in the "Living/Evidence" set is DEAD.
            if !is_reachable && !is_live && !is_protected {
                kill_list.push(id);
            }
        }

        kill_list
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_compute_kill_list() {
        let mut graph = DiGraph::<u64, ()>::new();

        // Nodes
        // 1: Entry Point (Main)
        // 2: Called by 1 (Reachable)
        // 3: Dead (Isolated)
        // 4: Logged (Live in logs)
        // 5: Protected (Heuristic)
        // 6: Called by 4 (Dependency of Live - SHOULD BE DEAD per strict algo?)
        //    Wait, the prompt says "Reachable from entry_points".
        //    It does NOT say "Reachable from live_ids".
        //    "The Verdict: Any node NOT in 'Living/Evidence' set is DEAD."
        //    So 6 is NOT in Living (reachable from 1), NOT in Live (4 is live, 6 is not), NOT in Protected.
        //    So 6 is DEAD. This confirms strict adherence to the prompt.

        let n1 = graph.add_node(1);
        let n2 = graph.add_node(2);
        let _n3 = graph.add_node(3);
        let n4 = graph.add_node(4);
        let _n5 = graph.add_node(5);
        let n6 = graph.add_node(6);

        // Edges
        graph.add_edge(n1, n2, ());
        graph.add_edge(n4, n6, ()); // 4 -> 6

        let entry_points = vec![1];
        let mut live_ids = HashSet::new();
        live_ids.insert(4);
        let mut wisdom_protected = HashSet::new();
        wisdom_protected.insert(5);

        let kill_list =
            SymbolOracle::compute_kill_list(&graph, &entry_points, &live_ids, &wisdom_protected);

        // Analysis:
        // 1: Entry -> Alive
        // 2: Reachable from 1 -> Alive
        // 3: Isolated -> Dead
        // 4: In live_ids -> Alive
        // 5: In wisdom_protected -> Alive
        // 6: Reachable from 4, but 4 is not entry point. Not in live_ids. Not protected. -> Dead.

        // Expected Dead: [3, 6]
        let mut sorted_kill = kill_list.clone();
        sorted_kill.sort();
        assert_eq!(sorted_kill, vec![3, 6]);
    }
}
