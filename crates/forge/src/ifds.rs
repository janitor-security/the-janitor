//! Interprocedural finite distributive subset (IFDS) taint solver.
//!
//! This module implements a summary-caching IFDS-style reachability engine over
//! the function-level `petgraph::DiGraph` produced by `callgraph.rs`.

use std::collections::{HashMap, HashSet, VecDeque};

use common::slop::ExploitWitness;
use ena::unify::{InPlaceUnificationTable, NoError, UnifyKey, UnifyValue};
use fixedbitset::FixedBitSet;
use petgraph::graph::{DiGraph, NodeIndex};
use smallvec::SmallVec;

/// Canonical taint label propagated by the IFDS solver.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TaintLabel {
    /// Stable label name, e.g. `"param:user_input"`.
    pub name: String,
}

impl TaintLabel {
    /// Construct a new taint label.
    pub fn new(name: impl Into<String>) -> Self {
        Self { name: name.into() }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct LabelKey(u32);

impl UnifyKey for LabelKey {
    type Value = LabelValue;

    fn index(&self) -> u32 {
        self.0
    }

    fn from_index(index: u32) -> Self {
        Self(index)
    }

    fn tag() -> &'static str {
        "ifds_label"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LabelValue(String);

impl UnifyValue for LabelValue {
    type Error = NoError;

    fn unify_values(value1: &Self, value2: &Self) -> Result<Self, Self::Error> {
        if value1.0 <= value2.0 {
            Ok(value1.clone())
        } else {
            Ok(value2.clone())
        }
    }
}

/// Input fact entering a function summary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InputFact {
    /// Function receiving the tainted fact.
    pub function: String,
    /// Taint label reaching the function.
    pub label: TaintLabel,
}

/// Output fact emitted by a function summary.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OutputFact {
    /// Function that emitted the output.
    pub function: String,
    /// Taint label emitted by the summary.
    pub label: TaintLabel,
}

/// Mapping from an incoming taint label to a callee parameter label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallBinding {
    /// Caller-side label consumed by the call site.
    pub caller_label: TaintLabel,
    /// Callee-side label produced at the call boundary.
    pub callee_label: TaintLabel,
}

/// Sink reached inside a function when a particular taint label is live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SinkBinding {
    /// Incoming label that triggers the sink.
    pub label: TaintLabel,
    /// Human-readable sink label, e.g. `"sql:Database.query"`.
    pub sink_label: String,
}

/// Per-edge dataflow semantics for a caller→callee relationship.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSite {
    /// Callee function name.
    pub callee: String,
    /// Fact translations at the call boundary.
    pub bindings: SmallVec<[CallBinding; 4]>,
}

/// Function-level dataflow model consumed by the IFDS solver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FunctionModel {
    /// Known sinks reachable inside the function.
    pub sinks: SmallVec<[SinkBinding; 2]>,
    /// Outgoing calls that can forward taint into callees.
    pub calls: SmallVec<[CallSite; 4]>,
    /// Summary outputs returned to callers for cross-file reuse.
    pub passthroughs: SmallVec<[(TaintLabel, TaintLabel); 2]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct SummaryKey {
    function: String,
    label: String,
}

/// Cached function summary for a single input fact.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Summary {
    /// Output facts emitted by the function for the given input fact.
    pub outputs: SmallVec<[OutputFact; 4]>,
    /// Proven exploit witnesses discovered under this input fact.
    pub witnesses: SmallVec<[ExploitWitness; 2]>,
}

/// Mutable summary cache.
#[derive(Debug, Clone, Default)]
pub struct SummaryCache {
    entries: HashMap<SummaryKey, Summary>,
}

impl SummaryCache {
    /// Fetch a cached summary in O(1).
    pub fn get(&self, input: &InputFact) -> Option<&Summary> {
        self.entries.get(&SummaryKey {
            function: input.function.clone(),
            label: input.label.name.clone(),
        })
    }

    fn insert(&mut self, input: &InputFact, summary: Summary) {
        self.entries.insert(
            SummaryKey {
                function: input.function.clone(),
                label: input.label.name.clone(),
            },
            summary,
        );
    }
}

/// Solver output for a set of seeded taint facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IfdsResult {
    /// Reachability bitmap per graph node.
    pub reachable: HashMap<String, Vec<String>>,
    /// Proven exploit witnesses.
    pub witnesses: Vec<ExploitWitness>,
}

/// Summary-caching IFDS solver over a function call graph.
#[derive(Debug)]
pub struct IfdsSolver {
    graph: DiGraph<String, ()>,
    node_by_name: HashMap<String, NodeIndex>,
    models: HashMap<String, FunctionModel>,
    label_table: InPlaceUnificationTable<LabelKey>,
    label_keys: HashMap<String, LabelKey>,
    labels: Vec<String>,
    pub summary_cache: SummaryCache,
}

impl IfdsSolver {
    /// Construct a solver from the call graph and per-function models.
    ///
    /// Accepts any `DiGraph<String, E>` — the IFDS reachability engine only
    /// needs the topology, not the edge weight.  This lets callers pass the
    /// richer [`crate::callgraph::CallGraph`] (which carries arg-position
    /// bindings on each edge) without a lossy pre-conversion.
    pub fn new<E>(graph: DiGraph<String, E>, models: HashMap<String, FunctionModel>) -> Self
    where
        E: Clone,
    {
        let graph: DiGraph<String, ()> = graph.map(|_, n| n.clone(), |_, _| ());
        let node_by_name = graph
            .node_indices()
            .map(|idx| (graph[idx].clone(), idx))
            .collect::<HashMap<_, _>>();
        Self {
            graph,
            node_by_name,
            models,
            label_table: InPlaceUnificationTable::new(),
            label_keys: HashMap::new(),
            labels: Vec::new(),
            summary_cache: SummaryCache::default(),
        }
    }

    /// Compute reachable taint facts and exploit witnesses from the seed facts.
    pub fn solve(&mut self, seeds: &[InputFact]) -> IfdsResult {
        let label_count = self.prime_labels(seeds);
        let seed_keys = seeds
            .iter()
            .map(|seed| (seed.function.clone(), seed.label.name.clone()))
            .collect::<HashSet<_>>();
        let mut reachable_bits = self
            .graph
            .node_indices()
            .map(|idx| {
                let mut bits = FixedBitSet::with_capacity(label_count);
                bits.clear();
                (idx, bits)
            })
            .collect::<HashMap<_, _>>();
        let mut worklist = VecDeque::new();

        for seed in seeds {
            let Some(&node) = self.node_by_name.get(&seed.function) else {
                continue;
            };
            let label_id = self.label_id(&seed.label);
            if let Some(bits) = reachable_bits.get_mut(&node) {
                bits.insert(label_id);
            }
            worklist.push_back(seed.clone());
        }

        let mut witnesses = Vec::new();
        while let Some(input) = worklist.pop_front() {
            let summary = self.compute_summary(&input, &mut Vec::new());
            if seed_keys.contains(&(input.function.clone(), input.label.name.clone())) {
                witnesses.extend(summary.witnesses.iter().cloned());
            }
            for output in &summary.outputs {
                let Some(&node) = self.node_by_name.get(&output.function) else {
                    continue;
                };
                let label_id = self.label_id(&output.label);
                let Some(bits) = reachable_bits.get_mut(&node) else {
                    continue;
                };
                if bits.contains(label_id) {
                    continue;
                }
                bits.insert(label_id);
                worklist.push_back(InputFact {
                    function: output.function.clone(),
                    label: output.label.clone(),
                });
            }
        }

        let reachable = reachable_bits
            .into_iter()
            .map(|(idx, bits)| {
                let labels = bits
                    .ones()
                    .map(|id| self.labels[id].clone())
                    .collect::<Vec<_>>();
                (self.graph[idx].clone(), labels)
            })
            .collect::<HashMap<_, _>>();

        IfdsResult {
            reachable,
            witnesses: dedup_result_witnesses(witnesses),
        }
    }

    fn prime_labels(&mut self, seeds: &[InputFact]) -> usize {
        let mut pending_labels = Vec::new();
        for seed in seeds {
            pending_labels.push(seed.label.name.clone());
        }
        for model in self.models.values() {
            for sink in &model.sinks {
                pending_labels.push(sink.label.name.clone());
            }
            for (input, output) in &model.passthroughs {
                pending_labels.push(input.name.clone());
                pending_labels.push(output.name.clone());
            }
            for call in &model.calls {
                for binding in &call.bindings {
                    pending_labels.push(binding.caller_label.name.clone());
                    pending_labels.push(binding.callee_label.name.clone());
                }
            }
        }
        for label in pending_labels {
            self.intern_label(&label);
        }
        self.labels.len()
    }

    fn intern_label(&mut self, label: &str) -> LabelKey {
        if let Some(&key) = self.label_keys.get(label) {
            return self.label_table.find(key);
        }
        let key = self.label_table.new_key(LabelValue(label.to_owned()));
        self.label_keys.insert(label.to_owned(), key);
        self.labels.push(label.to_owned());
        key
    }

    fn label_id(&mut self, label: &TaintLabel) -> usize {
        let key = self.intern_label(&label.name);
        self.label_table.find(key).index() as usize
    }

    fn compute_summary(&mut self, input: &InputFact, stack: &mut Vec<SummaryKey>) -> Summary {
        if let Some(summary) = self.summary_cache.get(input) {
            return summary.clone();
        }
        let key = SummaryKey {
            function: input.function.clone(),
            label: input.label.name.clone(),
        };
        if stack.contains(&key) {
            return Summary::default();
        }
        stack.push(key.clone());

        let mut summary = Summary::default();
        let Some(model) = self.models.get(&input.function).cloned() else {
            stack.pop();
            self.summary_cache.insert(input, summary.clone());
            return summary;
        };

        for sink in &model.sinks {
            if sink.label == input.label {
                summary.witnesses.push(ExploitWitness {
                    source_function: input.function.clone(),
                    source_label: input.label.name.clone(),
                    sink_function: input.function.clone(),
                    sink_label: sink.sink_label.clone(),
                    call_chain: vec![input.function.clone()],
                    repro_cmd: None,
                });
            }
        }

        for (incoming, outgoing) in &model.passthroughs {
            if incoming == &input.label {
                summary.outputs.push(OutputFact {
                    function: input.function.clone(),
                    label: outgoing.clone(),
                });
            }
        }

        for call in &model.calls {
            let Some(&caller_idx) = self.node_by_name.get(&input.function) else {
                continue;
            };
            let Some(&callee_idx) = self.node_by_name.get(&call.callee) else {
                continue;
            };
            if !self.graph.contains_edge(caller_idx, callee_idx) {
                continue;
            }
            for binding in &call.bindings {
                if binding.caller_label != input.label {
                    continue;
                }
                let callee_input = InputFact {
                    function: call.callee.clone(),
                    label: binding.callee_label.clone(),
                };
                let callee_summary = self.compute_summary(&callee_input, stack);
                summary.outputs.push(OutputFact {
                    function: call.callee.clone(),
                    label: binding.callee_label.clone(),
                });
                summary
                    .outputs
                    .extend(callee_summary.outputs.iter().cloned());
                for witness in &callee_summary.witnesses {
                    let mut call_chain = Vec::with_capacity(witness.call_chain.len() + 1);
                    call_chain.push(input.function.clone());
                    call_chain.extend(witness.call_chain.iter().cloned());
                    summary.witnesses.push(ExploitWitness {
                        source_function: input.function.clone(),
                        source_label: input.label.name.clone(),
                        sink_function: witness.sink_function.clone(),
                        sink_label: witness.sink_label.clone(),
                        call_chain,
                        repro_cmd: witness.repro_cmd.clone(),
                    });
                }
            }
        }

        stack.pop();
        dedup_outputs(&mut summary.outputs);
        dedup_witnesses(&mut summary.witnesses);
        self.summary_cache.insert(input, summary.clone());
        summary
    }
}

fn dedup_outputs(outputs: &mut SmallVec<[OutputFact; 4]>) {
    let mut seen = HashMap::<(String, String), ()>::new();
    outputs.retain(|output| {
        seen.insert((output.function.clone(), output.label.name.clone()), ())
            .is_none()
    });
}

fn dedup_witnesses(witnesses: &mut SmallVec<[ExploitWitness; 2]>) {
    let mut seen = HashMap::<(String, String, Vec<String>), ()>::new();
    witnesses.retain(|witness| {
        seen.insert(
            (
                witness.source_function.clone(),
                witness.sink_label.clone(),
                witness.call_chain.clone(),
            ),
            (),
        )
        .is_none()
    });
}

fn dedup_result_witnesses(witnesses: Vec<ExploitWitness>) -> Vec<ExploitWitness> {
    let mut seen = HashMap::<(String, String, Vec<String>), ()>::new();
    let mut deduped = Vec::with_capacity(witnesses.len());
    for witness in witnesses {
        if seen
            .insert(
                (
                    witness.source_function.clone(),
                    witness.sink_label.clone(),
                    witness.call_chain.clone(),
                ),
                (),
            )
            .is_none()
        {
            deduped.push(witness);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use petgraph::graph::DiGraph;
    use smallvec::SmallVec;

    use super::{
        CallBinding, CallSite, FunctionModel, IfdsSolver, InputFact, SinkBinding, TaintLabel,
    };

    #[test]
    fn traces_taint_across_three_hops_to_sink() {
        let mut graph = DiGraph::<String, ()>::new();
        let controller = graph.add_node("Controller.handle".to_string());
        let service = graph.add_node("UserService.validate".to_string());
        let database = graph.add_node("Database.query".to_string());
        graph.add_edge(controller, service, ());
        graph.add_edge(service, database, ());

        let mut models = HashMap::new();
        models.insert(
            "Controller.handle".to_string(),
            FunctionModel {
                calls: SmallVec::from_vec(vec![CallSite {
                    callee: "UserService.validate".to_string(),
                    bindings: SmallVec::from_vec(vec![CallBinding {
                        caller_label: TaintLabel::new("param:user_input"),
                        callee_label: TaintLabel::new("param:validated_input"),
                    }]),
                }]),
                ..FunctionModel::default()
            },
        );
        models.insert(
            "UserService.validate".to_string(),
            FunctionModel {
                calls: SmallVec::from_vec(vec![CallSite {
                    callee: "Database.query".to_string(),
                    bindings: SmallVec::from_vec(vec![CallBinding {
                        caller_label: TaintLabel::new("param:validated_input"),
                        callee_label: TaintLabel::new("param:sql_text"),
                    }]),
                }]),
                ..FunctionModel::default()
            },
        );
        models.insert(
            "Database.query".to_string(),
            FunctionModel {
                sinks: SmallVec::from_vec(vec![SinkBinding {
                    label: TaintLabel::new("param:sql_text"),
                    sink_label: "sink:sql_query".to_string(),
                }]),
                ..FunctionModel::default()
            },
        );

        let mut solver = IfdsSolver::new(graph, models);
        let result = solver.solve(&[InputFact {
            function: "Controller.handle".to_string(),
            label: TaintLabel::new("param:user_input"),
        }]);

        assert!(result
            .reachable
            .get("Database.query")
            .is_some_and(|labels| labels.iter().any(|label| label == "param:sql_text")));
        assert_eq!(result.witnesses.len(), 1);
        assert_eq!(
            result.witnesses[0].call_chain,
            vec![
                "Controller.handle".to_string(),
                "UserService.validate".to_string(),
                "Database.query".to_string(),
            ]
        );
        assert!(solver
            .summary_cache
            .get(&InputFact {
                function: "UserService.validate".to_string(),
                label: TaintLabel::new("param:validated_input"),
            })
            .is_some());
    }
}
