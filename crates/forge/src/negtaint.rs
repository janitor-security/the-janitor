//! Negative taint tracking over interprocedural call graphs.
//!
//! Standard taint analysis proves the *presence* of a source-to-sink flow.
//! This module inverts the lattice to prove the *absence* of upstream
//! validation: values begin `UNVALIDATED`, and only registered sanitizer or
//! validator nodes can transition a path to `VALIDATED`.

use std::collections::{HashMap, HashSet};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::ifds::FunctionModel;
use crate::sanitizer::SanitizerRegistry;

/// Negative-taint label at a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegTaintLabel {
    /// At least one reachable path bypasses all registered validation.
    Unvalidated,
    /// Every reachable path intersects at least one registered validation node.
    Validated,
}

/// Deterministic negative-taint audit verdict for one source-to-sink pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegTaintReport {
    /// Final sink label under the meet-over-all-paths lattice.
    pub label: NegTaintLabel,
    /// Number of reachable paths observed during backward traversal.
    pub reachable_paths: usize,
    /// Registered validation nodes observed on any traversed path.
    pub observed_validation_nodes: Vec<String>,
    /// Human-readable falsification string used in bug-bounty reports.
    pub sanitizer_audit: Option<String>,
}

#[derive(Debug, Default)]
struct PathFold {
    reachable_paths: usize,
    all_paths_validated: bool,
    any_path_unvalidated: bool,
    observed_validation_nodes: HashSet<String>,
}

impl PathFold {
    fn observe_path(&mut self, validations: HashSet<String>) {
        self.reachable_paths += 1;
        let path_validated = !validations.is_empty();
        if self.reachable_paths == 1 {
            self.all_paths_validated = path_validated;
        } else {
            self.all_paths_validated &= path_validated;
        }
        self.any_path_unvalidated |= !path_validated;
        self.observed_validation_nodes.extend(validations);
    }
}

/// Meet-over-all-paths negative-taint solver.
pub struct NegTaintSolver<'a> {
    graph: &'a DiGraph<String, ()>,
    node_by_name: &'a HashMap<String, NodeIndex>,
    models: &'a HashMap<String, FunctionModel>,
    registry: &'a SanitizerRegistry,
}

impl<'a> NegTaintSolver<'a> {
    /// Construct a solver over an existing IFDS call graph and function model map.
    pub fn new(
        graph: &'a DiGraph<String, ()>,
        node_by_name: &'a HashMap<String, NodeIndex>,
        models: &'a HashMap<String, FunctionModel>,
        registry: &'a SanitizerRegistry,
    ) -> Self {
        Self {
            graph,
            node_by_name,
            models,
            registry,
        }
    }

    /// Analyze one proven source-to-sink reachability witness.
    pub fn analyze(&self, source: &str, sink: &str) -> NegTaintReport {
        let Some(&source_idx) = self.node_by_name.get(source) else {
            return self.fail_closed_report();
        };
        let Some(&sink_idx) = self.node_by_name.get(sink) else {
            return self.fail_closed_report();
        };

        let mut fold = PathFold::default();
        let mut reverse_path = vec![sink_idx];
        let mut visited = HashSet::from([sink_idx]);
        self.walk_backward_paths(
            source_idx,
            sink_idx,
            &mut visited,
            &mut reverse_path,
            &mut fold,
        );

        let mut observed_validation_nodes = fold
            .observed_validation_nodes
            .iter()
            .cloned()
            .collect::<Vec<_>>();
        observed_validation_nodes.sort();

        let label = if fold.reachable_paths > 0 && fold.all_paths_validated {
            NegTaintLabel::Validated
        } else {
            NegTaintLabel::Unvalidated
        };

        let sanitizer_audit = if label == NegTaintLabel::Unvalidated {
            Some(self.build_audit_string(fold.any_path_unvalidated, &observed_validation_nodes))
        } else {
            None
        };

        NegTaintReport {
            label,
            reachable_paths: fold.reachable_paths,
            observed_validation_nodes,
            sanitizer_audit,
        }
    }

    fn fail_closed_report(&self) -> NegTaintReport {
        NegTaintReport {
            label: NegTaintLabel::Unvalidated,
            reachable_paths: 0,
            observed_validation_nodes: Vec::new(),
            sanitizer_audit: Some(self.build_audit_string(true, &[])),
        }
    }

    fn build_audit_string(
        &self,
        any_path_unvalidated: bool,
        observed_validation_nodes: &[String],
    ) -> String {
        let examples = self.registry.audit_examples(3).join(", ");
        if observed_validation_nodes.is_empty() {
            return format!(
                "Path analysis confirms no registered sanitizers or validators (e.g., {examples}) were invoked on this variable prior to the sink."
            );
        }
        if any_path_unvalidated {
            return format!(
                "Path analysis confirms at least one reachable source-to-sink path bypasses all registered sanitizers or validators prior to the sink. Alternate paths invoked: {}.",
                observed_validation_nodes.join(", ")
            );
        }
        format!(
            "Path analysis confirmed registered validation on every reachable path prior to the sink: {}.",
            observed_validation_nodes.join(", ")
        )
    }

    fn walk_backward_paths(
        &self,
        source_idx: NodeIndex,
        current_idx: NodeIndex,
        visited: &mut HashSet<NodeIndex>,
        reverse_path: &mut Vec<NodeIndex>,
        fold: &mut PathFold,
    ) {
        if current_idx == source_idx {
            let path = reverse_path.iter().rev().copied().collect::<Vec<_>>();
            fold.observe_path(self.validation_nodes_for_path(&path));
            return;
        }

        for predecessor in self
            .graph
            .neighbors_directed(current_idx, Direction::Incoming)
        {
            if !visited.insert(predecessor) {
                continue;
            }
            reverse_path.push(predecessor);
            self.walk_backward_paths(source_idx, predecessor, visited, reverse_path, fold);
            reverse_path.pop();
            visited.remove(&predecessor);
        }
    }

    fn validation_nodes_for_path(&self, path: &[NodeIndex]) -> HashSet<String> {
        let mut validations = HashSet::new();
        for idx in path {
            let function = &self.graph[*idx];
            for node in self.effective_validation_nodes(function) {
                validations.insert(node);
            }
        }
        validations
    }

    fn effective_validation_nodes(&self, function_name: &str) -> Vec<String> {
        let mut nodes = self
            .models
            .get(function_name)
            .map(|model| model.validation_nodes.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for candidate in validation_name_candidates(function_name) {
            if self.registry.is_validation_function(candidate) {
                nodes.push(candidate.to_string());
            }
        }
        nodes.retain(|candidate| self.registry.is_validation_function(candidate));
        nodes.sort();
        nodes.dedup();
        nodes
    }
}

fn validation_name_candidates(function_name: &str) -> impl Iterator<Item = &str> {
    let mut candidates = Vec::with_capacity(4);
    candidates.push(function_name);
    if let Some(last) = function_name.rsplit("::").next() {
        candidates.push(last);
    }
    if let Some(last) = function_name.rsplit('.').next() {
        candidates.push(last);
    }
    if let Some(last) = function_name.rsplit('/').next() {
        candidates.push(last);
    }
    candidates.into_iter()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use petgraph::graph::DiGraph;
    use smallvec::SmallVec;

    use super::{NegTaintLabel, NegTaintSolver};
    use crate::ifds::FunctionModel;
    use crate::sanitizer::SanitizerRegistry;

    #[test]
    fn true_positive_unsanitized_path_is_unvalidated() {
        let mut graph = DiGraph::<String, ()>::new();
        let source = graph.add_node("Controller.handle".to_string());
        let passthrough = graph.add_node("Service.pass".to_string());
        let sink = graph.add_node("Dangerous.render".to_string());
        graph.add_edge(source, passthrough, ());
        graph.add_edge(passthrough, sink, ());

        let node_by_name = graph
            .node_indices()
            .map(|idx| (graph[idx].clone(), idx))
            .collect::<HashMap<_, _>>();
        let models = HashMap::<String, FunctionModel>::new();
        let registry = SanitizerRegistry::with_defaults();
        let solver = NegTaintSolver::new(&graph, &node_by_name, &models, &registry);

        let report = solver.analyze("Controller.handle", "Dangerous.render");

        assert_eq!(report.label, NegTaintLabel::Unvalidated);
        assert_eq!(report.reachable_paths, 1);
        assert!(report
            .sanitizer_audit
            .as_deref()
            .is_some_and(|audit| audit.contains("no registered sanitizers or validators")));
    }

    #[test]
    fn true_negative_sanitized_path_is_validated() {
        let mut graph = DiGraph::<String, ()>::new();
        let source = graph.add_node("Controller.handle".to_string());
        let sanitizer = graph.add_node("escapeHtml".to_string());
        let sink = graph.add_node("Dangerous.render".to_string());
        graph.add_edge(source, sanitizer, ());
        graph.add_edge(sanitizer, sink, ());

        let node_by_name = graph
            .node_indices()
            .map(|idx| (graph[idx].clone(), idx))
            .collect::<HashMap<_, _>>();
        let mut models = HashMap::new();
        models.insert(
            "escapeHtml".to_string(),
            FunctionModel {
                validation_nodes: SmallVec::from_vec(vec!["escapeHtml".to_string()]),
                ..FunctionModel::default()
            },
        );
        let registry = SanitizerRegistry::with_defaults();
        let solver = NegTaintSolver::new(&graph, &node_by_name, &models, &registry);

        let report = solver.analyze("Controller.handle", "Dangerous.render");

        assert_eq!(report.label, NegTaintLabel::Validated);
        assert_eq!(report.reachable_paths, 1);
        assert!(report.sanitizer_audit.is_none());
    }
}
