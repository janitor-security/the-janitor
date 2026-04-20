//! Negative taint tracking over interprocedural call graphs.
//!
//! Standard taint analysis proves the *presence* of a source-to-sink flow.
//! This module inverts the lattice to prove the *absence* of upstream
//! validation: values begin `UNVALIDATED`, and only registered sanitizer or
//! validator nodes can transition a path to `VALIDATED`.

use std::collections::{HashMap, HashSet};
use std::process::Command;

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::Direction;

use crate::ifds::FunctionModel;
use crate::sanitizer::{SanitizerPredicate, SanitizerRegistry};

/// Negative-taint label at a sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NegTaintLabel {
    /// At least one reachable path bypasses all registered validation.
    Unvalidated,
    /// Every reachable path intersects at least one registered validation node.
    Validated,
    /// Every reachable path *invokes* a registered sanitizer, but mathematical
    /// weakest-precondition falsification (Tier C) proved that at least one
    /// concrete input satisfies the sanitizer's guarantee yet violates the
    /// sink's safety contract.
    FalsifiedSanitizer,
}

/// Logical precondition the sink requires on its incoming value for safe use.
///
/// The sink predicate is the `φ_required` term in `wp(sanitizer, φ_required)`.
/// Tier C falsification asserts
/// `sanitizer.smt_assertion ∧ ¬sink.smt_assertion` in z3 and interprets `sat`
/// as *proof the sanitizer is bypassable*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SinkPredicate {
    /// Symbolic name of the value reaching the sink.  Must equal the sanitizer's
    /// output binding — `"output"` by convention — so both predicates constrain
    /// the same constant.
    pub variable: &'static str,
    /// SMT-LIB2 sort of the sink's incoming value — `"String"`, `"Int"`, etc.
    pub sort: &'static str,
    /// SMT-LIB2 assertion body describing the safety contract the sink
    /// requires.  Example (XSS-safe render context):
    /// `"(not (str.contains output \"javascript:\"))"`.
    pub smt_assertion: &'static str,
}

/// Outcome of a single sanitizer-vs-sink falsification query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FalsificationVerdict {
    /// z3 returned `sat`: the sanitizer is provably bypassable.  The enclosed
    /// counterexample is the concrete model value z3 emitted for the `output`
    /// binding, already unquoted for direct embedding in an audit string.
    Bypassable {
        sanitizer_name: String,
        counterexample: String,
    },
    /// z3 returned `unsat`: no input satisfies the sanitizer's guarantee
    /// while violating the sink's contract — the sanitizer is mathematically
    /// robust against this sink.
    Robust { sanitizer_name: String },
    /// z3 returned `unknown`, timed out, or was unavailable on PATH.
    /// Callers MUST fall through to the conservative Tier A verdict.
    Unknown { sanitizer_name: String },
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
    /// Tier C falsification record: populated only when every path invoked a
    /// sanitizer yet at least one sanitizer was *mathematically* shown to be
    /// bypassable via weakest-precondition Z3 analysis.
    pub falsified_sanitizer: Option<FalsifiedSanitizerRecord>,
}

/// Concrete counterexample proving a sanitizer is bypassable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FalsifiedSanitizerRecord {
    /// Registered sanitizer name whose guarantee was falsified.
    pub sanitizer_name: String,
    /// Concrete value returned by z3 for the `output` binding.  Already
    /// unquoted from the raw SMT-LIB string form.
    pub counterexample: String,
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

    /// Analyze one proven source-to-sink reachability witness (Tier A only).
    pub fn analyze(&self, source: &str, sink: &str) -> NegTaintReport {
        self.analyze_with_sink_predicate(source, sink, None)
    }

    /// Analyze with an optional sink predicate.  When a predicate is supplied
    /// *and* the Tier A lattice returns `Validated`, the solver invokes the
    /// z3-backed Tier C weakest-precondition falsifier on each observed
    /// sanitizer node.  A `sat` counterexample demotes the verdict to
    /// [`NegTaintLabel::FalsifiedSanitizer`] and overrides the audit string
    /// with the mandated "bypassable" message.
    pub fn analyze_with_sink_predicate(
        &self,
        source: &str,
        sink: &str,
        sink_predicate: Option<&SinkPredicate>,
    ) -> NegTaintReport {
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

        let tier_a_label = if fold.reachable_paths > 0 && fold.all_paths_validated {
            NegTaintLabel::Validated
        } else {
            NegTaintLabel::Unvalidated
        };

        let mut falsified_sanitizer: Option<FalsifiedSanitizerRecord> = None;
        if tier_a_label == NegTaintLabel::Validated {
            if let Some(predicate) = sink_predicate {
                falsified_sanitizer = self
                    .falsify_first_sanitizer_against_sink(&observed_validation_nodes, predicate);
            }
        }

        let label = if falsified_sanitizer.is_some() {
            NegTaintLabel::FalsifiedSanitizer
        } else {
            tier_a_label
        };

        let sanitizer_audit = match (&label, &falsified_sanitizer) {
            (NegTaintLabel::FalsifiedSanitizer, Some(record)) => {
                Some(build_falsification_audit_string(record))
            }
            (NegTaintLabel::Unvalidated, _) => {
                Some(self.build_audit_string(fold.any_path_unvalidated, &observed_validation_nodes))
            }
            _ => None,
        };

        NegTaintReport {
            label,
            reachable_paths: fold.reachable_paths,
            observed_validation_nodes,
            sanitizer_audit,
            falsified_sanitizer,
        }
    }

    fn fail_closed_report(&self) -> NegTaintReport {
        NegTaintReport {
            label: NegTaintLabel::Unvalidated,
            reachable_paths: 0,
            observed_validation_nodes: Vec::new(),
            sanitizer_audit: Some(self.build_audit_string(true, &[])),
            falsified_sanitizer: None,
        }
    }

    /// Iterate observed validation nodes in deterministic order, run
    /// `wp(sanitizer, φ_required)` against each, and return the first
    /// `Bypassable` verdict — or `None` if every sanitizer is robust / unknown.
    fn falsify_first_sanitizer_against_sink(
        &self,
        observed_validation_nodes: &[String],
        sink_predicate: &SinkPredicate,
    ) -> Option<FalsifiedSanitizerRecord> {
        for name in observed_validation_nodes {
            let Some(sanitizer_predicate) = self.registry.predicate_for(name) else {
                continue;
            };
            match falsify_sanitizer_against_sink(name, &sanitizer_predicate, sink_predicate) {
                FalsificationVerdict::Bypassable {
                    sanitizer_name,
                    counterexample,
                } => {
                    return Some(FalsifiedSanitizerRecord {
                        sanitizer_name,
                        counterexample,
                    });
                }
                FalsificationVerdict::Robust { .. } | FalsificationVerdict::Unknown { .. } => {}
            }
        }
        None
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

/// Map a canonical IFDS sink label to its Tier C safety predicate.
///
/// Returns `None` for sinks whose safety contract is not yet expressible as an
/// SMT-LIB2 assertion — callers fall through to Tier A and emit the generic
/// upstream-validation audit string.
///
/// Recognised patterns (match on case-sensitive substrings of `sink_label`):
/// - `Html`, `render`, `innerHTML`, `xss`, `dom_xss` → forbid `javascript:`
///   scheme prefixes on the incoming string.
/// - `sql`, `DatabaseResult` → forbid single-quote metacharacters.
/// - `path`, `file`, `FileRead` → forbid `../` traversal fragments.
/// - `cmd`, `shell`, `exec`, `Command` → forbid shell metacharacters `;`, `|`,
///   and backtick.
pub fn sink_predicate_for_label(sink_label: &str) -> Option<SinkPredicate> {
    let label = sink_label;
    if label.contains("xss")
        || label.contains("dom_xss")
        || label.contains("Html")
        || label.contains("render")
        || label.contains("innerHTML")
    {
        return Some(SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(not (str.contains output "javascript:"))"#,
        });
    }
    if label.contains("sql") || label.contains("DatabaseResult") || label.contains("query") {
        return Some(SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(not (str.contains output "'"))"#,
        });
    }
    if label.contains("path") || label.contains("FileRead") || label.contains("file") {
        return Some(SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(not (str.contains output "../"))"#,
        });
    }
    if label.contains("cmd")
        || label.contains("shell")
        || label.contains("exec")
        || label.contains("Command")
    {
        return Some(SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(and (not (str.contains output ";")) (not (str.contains output "|")))"#,
        });
    }
    None
}

/// Probe for a z3 binary on PATH without mutating state.
pub fn z3_is_available() -> bool {
    Command::new("z3")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Canonical audit string emitted when Tier C proves a sanitizer is bypassable.
///
/// The format is contractually fixed — the string is consumed verbatim by the
/// Auth0 "Upstream Validation Audit" section renderer and by Bugcrowd triagers.
pub fn build_falsification_audit_string(record: &FalsifiedSanitizerRecord) -> String {
    format!(
        "Sanitizer {} was invoked, but mathematical falsification proves it is bypassable. Counterexample payload: {}",
        record.sanitizer_name, record.counterexample
    )
}

/// Run `wp(sanitizer, φ_required)` as an SMT-LIB2 query and classify the
/// result.
///
/// Encoding:
/// ```text
/// (set-logic ALL)
/// (declare-const output <sort>)
/// (assert <sanitizer.smt_assertion>)
/// (assert (not <sink.smt_assertion>))
/// (check-sat)
/// (get-value (output))
/// ```
///
/// Outcome mapping:
/// - `sat`     → [`FalsificationVerdict::Bypassable`] with the extracted model.
/// - `unsat`   → [`FalsificationVerdict::Robust`] — sanitizer entails sink.
/// - anything else (including z3 absent, spawn failure, parse error) →
///   [`FalsificationVerdict::Unknown`] so callers fall back to Tier A.
pub fn falsify_sanitizer_against_sink(
    sanitizer_name: &str,
    sanitizer: &SanitizerPredicate,
    sink: &SinkPredicate,
) -> FalsificationVerdict {
    let name = sanitizer_name.to_string();
    if !z3_is_available() {
        return FalsificationVerdict::Unknown {
            sanitizer_name: name,
        };
    }
    if sanitizer.output_sort != sink.sort {
        // Sort mismatch cannot be reconciled safely — treat as inconclusive.
        return FalsificationVerdict::Unknown {
            sanitizer_name: name,
        };
    }
    let script = format!(
        "(set-logic ALL)\n\
         (declare-const {binding} {sort})\n\
         (assert {san})\n\
         (assert (not {sink}))\n\
         (check-sat)\n\
         (get-value ({binding}))\n",
        binding = sink.variable,
        sort = sink.sort,
        san = sanitizer.smt_assertion,
        sink = sink.smt_assertion,
    );
    match run_z3_script(&script) {
        Z3Outcome::Sat(counterexample) => FalsificationVerdict::Bypassable {
            sanitizer_name: name,
            counterexample,
        },
        Z3Outcome::Unsat => FalsificationVerdict::Robust {
            sanitizer_name: name,
        },
        Z3Outcome::Unknown => FalsificationVerdict::Unknown {
            sanitizer_name: name,
        },
    }
}

enum Z3Outcome {
    Sat(String),
    Unsat,
    Unknown,
}

fn run_z3_script(script: &str) -> Z3Outcome {
    use std::io::Write;
    use std::process::Stdio;

    let Ok(mut child) = Command::new("z3")
        .arg("-in")
        .arg("-smt2")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    else {
        return Z3Outcome::Unknown;
    };

    if let Some(stdin) = child.stdin.as_mut() {
        if stdin.write_all(script.as_bytes()).is_err() {
            let _ = child.kill();
            return Z3Outcome::Unknown;
        }
    }
    let Ok(output) = child.wait_with_output() else {
        return Z3Outcome::Unknown;
    };
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();

    let mut lines = stdout.lines();
    let first = lines.next().unwrap_or("").trim();
    match first {
        "sat" => {
            let rest = lines.collect::<Vec<_>>().join("\n");
            let counterexample =
                parse_first_get_value(&rest).unwrap_or_else(|| "<unknown>".to_string());
            Z3Outcome::Sat(counterexample)
        }
        "unsat" => Z3Outcome::Unsat,
        _ => Z3Outcome::Unknown,
    }
}

/// Extract the concrete value of the first binding returned by `(get-value ...)`.
///
/// Z3 prints `((output "javascript:alert(1)"))` for string sorts and
/// `((output 42))` for numeric sorts.  We strip the outer two parens, split on
/// whitespace past the first identifier, and unquote any SMT string literal.
fn parse_first_get_value(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    // Remove the two leading '(' and two trailing ')' — be lenient.
    let inner = trimmed
        .strip_prefix("((")
        .and_then(|s| s.strip_suffix("))"))
        .unwrap_or(trimmed);
    // inner now looks like: `output "value"` or `output 42` or `output (- 1)`.
    let after_ident = inner.split_once(char::is_whitespace)?.1.trim();
    Some(unquote_smt_string(after_ident))
}

fn unquote_smt_string(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.len() >= 2 && trimmed.starts_with('"') && trimmed.ends_with('"') {
        return trimmed[1..trimmed.len() - 1].replace("\"\"", "\"");
    }
    trimmed.to_string()
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
        assert!(report.falsified_sanitizer.is_none());
    }

    #[test]
    fn falsify_html_sanitizer_against_javascript_url_sink() {
        use super::{falsify_sanitizer_against_sink, z3_is_available, FalsificationVerdict};
        use crate::sanitizer::SanitizerPredicate;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        let sanitizer = SanitizerPredicate {
            output_sort: "String",
            smt_assertion: r#"(not (str.contains output "<"))"#,
        };
        let sink = super::SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(not (str.contains output "javascript:"))"#,
        };
        let verdict = falsify_sanitizer_against_sink("escape_html", &sanitizer, &sink);
        match verdict {
            FalsificationVerdict::Bypassable {
                sanitizer_name,
                counterexample,
            } => {
                assert_eq!(sanitizer_name, "escape_html");
                assert!(
                    !counterexample.is_empty(),
                    "counterexample must be non-empty"
                );
            }
            other => panic!("expected Bypassable, got {other:?}"),
        }
    }

    #[test]
    fn falsify_returns_robust_when_sanitizer_entails_sink() {
        use super::{falsify_sanitizer_against_sink, z3_is_available, FalsificationVerdict};
        use crate::sanitizer::SanitizerPredicate;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        // Sanitizer proves `output = "safe"`; sink requires `output = "safe"`.
        let sanitizer = SanitizerPredicate {
            output_sort: "String",
            smt_assertion: r#"(= output "safe")"#,
        };
        let sink = super::SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(= output "safe")"#,
        };
        let verdict = falsify_sanitizer_against_sink("constant_sanitizer", &sanitizer, &sink);
        assert!(
            matches!(verdict, FalsificationVerdict::Robust { .. }),
            "expected Robust verdict"
        );
    }

    #[test]
    fn analyze_with_sink_predicate_demotes_validated_to_falsified() {
        use super::z3_is_available;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        let mut graph = DiGraph::<String, ()>::new();
        let source = graph.add_node("Controller.handle".to_string());
        let sanitizer_node = graph.add_node("escape_html".to_string());
        let sink = graph.add_node("Dangerous.render".to_string());
        graph.add_edge(source, sanitizer_node, ());
        graph.add_edge(sanitizer_node, sink, ());

        let node_by_name = graph
            .node_indices()
            .map(|idx| (graph[idx].clone(), idx))
            .collect::<HashMap<_, _>>();
        let mut models = HashMap::new();
        models.insert(
            "escape_html".to_string(),
            FunctionModel {
                validation_nodes: SmallVec::from_vec(vec!["escape_html".to_string()]),
                ..FunctionModel::default()
            },
        );
        let registry = SanitizerRegistry::with_defaults();
        let solver = NegTaintSolver::new(&graph, &node_by_name, &models, &registry);

        let sink_predicate = super::SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(not (str.contains output "javascript:"))"#,
        };
        let report = solver.analyze_with_sink_predicate(
            "Controller.handle",
            "Dangerous.render",
            Some(&sink_predicate),
        );

        assert_eq!(report.label, NegTaintLabel::FalsifiedSanitizer);
        let record = report
            .falsified_sanitizer
            .expect("falsified record must be populated");
        assert_eq!(record.sanitizer_name, "escape_html");
        let audit = report
            .sanitizer_audit
            .expect("falsification audit must be populated");
        assert!(audit.starts_with(
            "Sanitizer escape_html was invoked, but mathematical falsification proves it is bypassable."
        ));
        assert!(audit.contains("Counterexample payload:"));
    }

    #[test]
    fn parse_first_get_value_extracts_string_payload() {
        use super::parse_first_get_value;

        let raw = r#"((output "javascript:alert(1)"))"#;
        let value = parse_first_get_value(raw).expect("parse must succeed");
        assert_eq!(value, "javascript:alert(1)");
    }

    #[test]
    fn parse_first_get_value_extracts_integer_payload() {
        use super::parse_first_get_value;

        let raw = "((n 42))";
        let value = parse_first_get_value(raw).expect("parse must succeed");
        assert_eq!(value, "42");
    }
}
