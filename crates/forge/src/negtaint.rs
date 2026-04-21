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
use crate::sanitizer::{SanitizerOrigin, SanitizerPredicate, SanitizerRegistry};

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

/// Outcome of a Tier B path-level SMT entailment proof.
///
/// Tier B accumulates the logical conjunction `φ_path = φ₁ ∧ φ₂ ∧ ...` of every
/// [`SanitizerPredicate`] stamped on a specific execution path, then asks z3
/// whether `φ_path ⊨ φ_required`.  The query form is
/// `(and φ_path (not φ_required))`:
///
/// - `unsat` → the conjunction entails the sink contract; suppress the
///   finding on this path.
/// - `sat`   → the conjunction fails to entail the sink contract; the concrete
///   model value is a counterexample payload that satisfies every stamped
///   sanitizer yet reaches the sink.
/// - `unknown` / z3 unavailable → conservative pass-through; callers keep the
///   Tier A verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathEntailmentVerdict {
    /// z3 returned `unsat`: `φ_path` entails `φ_required` on this path.
    Entails,
    /// z3 returned `sat`: at least one concrete payload satisfies every
    /// stamped sanitizer on this path yet violates the sink contract.
    DoesNotEntail {
        path_sanitizers: Vec<String>,
        counterexample: String,
    },
    /// z3 unavailable, sort mismatch, or result unparsable.  Callers MUST
    /// treat as inconclusive and fall through to Tier A.
    UnknownOrUnavailable,
}

/// Concrete Tier B witness: a specific execution path whose cumulative
/// sanitizer conjunction fails to entail the sink's safety contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialSanitizationRecord {
    /// Ordered list of registered sanitizer names stamped on the failing
    /// path, in source-to-sink order.  Only sanitizers whose predicate is
    /// registered in the [`SanitizerRegistry`] are listed — un-predicated
    /// validators are elided because they contribute no SMT constraint.
    pub path_sanitizers: Vec<String>,
    /// Concrete model value returned by z3 for the `output` binding after
    /// asserting `(and φ_path (not φ_required))`.  Already unquoted from the
    /// raw SMT-LIB string form.
    pub counterexample: String,
    /// Human-readable interpretation of the SMT gap, e.g.
    /// `"path is sanitized against XSS but fails to satisfy SSRF constraints"`.
    pub gap_summary: String,
    /// Tier D framework-origin citations, one line per
    /// [`SanitizerOrigin::FrameworkImplicit`] entry on the failing path.
    /// Each string is fully-formed for verbatim embedding in the Auth0
    /// "Upstream Validation Audit" section, e.g.
    /// `"The Express.js framework implicit validator (express.json) was
    /// evaluated, but Z3 proves it does not entail safety for this sink."`
    /// Empty when no framework-implicit sanitizer contributed to the failing
    /// path.
    pub framework_notes: Vec<String>,
    /// Tier E non-monotonic exclusion witnesses: for every *other* reachable
    /// path whose predicate conjunction DID entail the sink's safety
    /// contract, the ordered list of that path's sanitizers.  Presence of
    /// any entry proves the triager's "this is validated" claim was
    /// analyzed and a concurrent bypass path was still found.  Empty when no
    /// concurrent path entailed — the Tier B-only case.
    pub excluded_safe_paths: Vec<Vec<String>>,
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
    /// Tier C falsification record: populated when a single sanitizer's
    /// predicate was individually shown bypassable via weakest-precondition.
    /// Retained for callers that invoke the pairwise API directly; Tier B
    /// path-level analysis is preferred and populates
    /// [`NegTaintReport::partial_sanitization`] instead.
    pub falsified_sanitizer: Option<FalsifiedSanitizerRecord>,
    /// Tier B SMT-entailment witness: populated when at least one reachable
    /// path's cumulative sanitizer conjunction fails to entail the sink's
    /// safety contract.  The record names the ordered sanitizers on that
    /// path, the concrete counterexample payload, and a human-readable gap
    /// summary for embedding in Auth0/Bugcrowd "Upstream Validation Audit"
    /// sections.
    pub partial_sanitization: Option<PartialSanitizationRecord>,
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
    /// Ordered list of registered validation/sanitizer names per reachable
    /// path, preserved in source-to-sink order.  Tier B SMT entailment
    /// consumes these sequences to build per-path predicate conjunctions.
    per_path_validations: Vec<Vec<String>>,
}

impl PathFold {
    fn observe_path(&mut self, validations_ordered: Vec<String>) {
        self.reachable_paths += 1;
        let path_validated = !validations_ordered.is_empty();
        if self.reachable_paths == 1 {
            self.all_paths_validated = path_validated;
        } else {
            self.all_paths_validated &= path_validated;
        }
        self.any_path_unvalidated |= !path_validated;
        for node in &validations_ordered {
            self.observed_validation_nodes.insert(node.clone());
        }
        self.per_path_validations.push(validations_ordered);
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
    /// *and* the Tier A lattice returns `Validated`, the solver runs the
    /// Tier B path-level SMT entailment prover: for each reachable path, it
    /// accumulates `φ_path = φ₁ ∧ φ₂ ∧ ...` of every [`SanitizerPredicate`]
    /// stamped by that path's validators, then asks z3 whether
    /// `φ_path ⊨ φ_required` (via `(and φ_path (not φ_required))`).
    ///
    /// - Every path entails → Tier A `Validated` stands; no finding emitted.
    /// - Any path fails to entail → verdict demoted to
    ///   [`NegTaintLabel::FalsifiedSanitizer`] with the first failing path
    ///   captured in [`NegTaintReport::partial_sanitization`] as a
    ///   [`PartialSanitizationRecord`].  The audit string names the gap
    ///   mathematically ("Path sanitizers [X] do not entail ...").
    ///
    /// Paths whose validators have no registered SMT predicate are treated
    /// conservatively (skipped) — Tier B never fabricates constraints.
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

        let mut partial_sanitization: Option<PartialSanitizationRecord> = None;
        if tier_a_label == NegTaintLabel::Validated {
            if let Some(predicate) = sink_predicate {
                partial_sanitization =
                    self.prove_first_path_fails_entailment(&fold.per_path_validations, predicate);
            }
        }

        let label = if partial_sanitization.is_some() {
            NegTaintLabel::FalsifiedSanitizer
        } else {
            tier_a_label
        };

        let sanitizer_audit = match (&label, &partial_sanitization) {
            (NegTaintLabel::FalsifiedSanitizer, Some(record)) => {
                Some(build_partial_sanitization_audit_string(record))
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
            falsified_sanitizer: None,
            partial_sanitization,
        }
    }

    fn fail_closed_report(&self) -> NegTaintReport {
        NegTaintReport {
            label: NegTaintLabel::Unvalidated,
            reachable_paths: 0,
            observed_validation_nodes: Vec::new(),
            sanitizer_audit: Some(self.build_audit_string(true, &[])),
            falsified_sanitizer: None,
            partial_sanitization: None,
        }
    }

    /// Tier B + D + E path-level SMT entailment prover.
    ///
    /// Iterate every reachable path in observed order.  For each path whose
    /// validators include at least one registered [`SanitizerPredicate`],
    /// assert `(and φ_path (not φ_required))` and ask z3 for a counterexample.
    /// The verdict is partitioned into two buckets:
    ///
    /// - **`DoesNotEntail`** — bypass path; the first such path becomes the
    ///   failing record.  Framework-implicit origins on that path are
    ///   captured as [`PartialSanitizationRecord::framework_notes`] (Tier D).
    /// - **`Entails`** — safe path; its sanitizer list is accumulated into
    ///   [`PartialSanitizationRecord::excluded_safe_paths`] (Tier E
    ///   non-monotonic exclusion), proving we analyzed the path the
    ///   triager would cite and still found a bypass elsewhere.
    ///
    /// Paths whose validators have no registered predicate are treated
    /// conservatively (skipped) — Tier B never fabricates constraints.
    /// Returns `None` when z3 is unavailable, no path carries predicated
    /// sanitizers, or every predicated path entails the sink (Tier A
    /// `Validated` stands).
    fn prove_first_path_fails_entailment(
        &self,
        per_path_validations: &[Vec<String>],
        sink_predicate: &SinkPredicate,
    ) -> Option<PartialSanitizationRecord> {
        if !z3_is_available() {
            return None;
        }
        let mut failing: Option<(Vec<String>, String, Vec<String>)> = None;
        let mut excluded_safe_paths: Vec<Vec<String>> = Vec::new();

        for path in per_path_validations {
            if path.is_empty() {
                continue;
            }
            let enriched: Vec<(String, SanitizerPredicate, Option<&'static str>)> = path
                .iter()
                .filter_map(|name| {
                    let spec = self.registry.spec_for(name)?;
                    let pred = spec.predicate?;
                    let fw = match spec.origin {
                        SanitizerOrigin::FrameworkImplicit => spec.framework_label,
                        _ => None,
                    };
                    Some((name.clone(), pred, fw))
                })
                .collect();
            if enriched.is_empty() {
                continue;
            }
            if enriched
                .iter()
                .any(|(_, pred, _)| pred.output_sort != sink_predicate.sort)
            {
                continue;
            }
            let predicated_names: Vec<String> =
                enriched.iter().map(|(n, _, _)| n.clone()).collect();
            let predicate_list: Vec<SanitizerPredicate> =
                enriched.iter().map(|(_, p, _)| *p).collect();
            match prove_path_entailment(&predicate_list, sink_predicate) {
                PathEntailmentVerdict::DoesNotEntail { counterexample, .. } => {
                    if failing.is_none() {
                        let framework_notes: Vec<String> = enriched
                            .iter()
                            .filter_map(|(name, _, fw)| {
                                fw.map(|framework| {
                                    format!(
                                        "The {framework} framework implicit validator ({name}) was evaluated, but Z3 proves it does not entail safety for this sink."
                                    )
                                })
                            })
                            .collect();
                        failing = Some((predicated_names, counterexample, framework_notes));
                    }
                }
                PathEntailmentVerdict::Entails => {
                    excluded_safe_paths.push(predicated_names);
                }
                PathEntailmentVerdict::UnknownOrUnavailable => {}
            }
        }

        failing.map(|(path_sanitizers, counterexample, framework_notes)| {
            let gap_summary = summarize_entailment_gap(&path_sanitizers, sink_predicate);
            PartialSanitizationRecord {
                path_sanitizers,
                counterexample,
                gap_summary,
                framework_notes,
                excluded_safe_paths,
            }
        })
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

    fn validation_nodes_for_path(&self, path: &[NodeIndex]) -> Vec<String> {
        let mut validations: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for idx in path {
            let function = &self.graph[*idx];
            for node in self.effective_validation_nodes(function) {
                if seen.insert(node.clone()) {
                    validations.push(node);
                }
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

/// Map a canonical IFDS sink label to its SMT safety predicate.
///
/// Returns `None` for sinks whose safety contract is not yet expressible as an
/// SMT-LIB2 assertion — callers fall through to Tier A and emit the generic
/// upstream-validation audit string.
///
/// Recognised patterns (match on case-sensitive substrings of `sink_label`):
/// - `ssrf`, `fetch`, `HttpRequest` → forbid `http://internal` prefix (SSRF).
/// - `Html`, `render`, `innerHTML`, `xss`, `dom_xss` → forbid `javascript:`
///   scheme prefixes on the incoming string.
/// - `sql`, `DatabaseResult`, `query` → forbid single-quote metacharacters.
/// - `path`, `file`, `FileRead` → forbid `../` traversal fragments.
/// - `cmd`, `shell`, `exec`, `Command` → forbid shell metacharacters `;`, `|`.
pub fn sink_predicate_for_label(sink_label: &str) -> Option<SinkPredicate> {
    let label = sink_label;
    if label.contains("ssrf") || label.contains("HttpRequest") || label.contains("fetch") {
        return Some(SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(not (str.prefixof "http://internal" output))"#,
        });
    }
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

/// Canonical audit string emitted when Tier C proves a single sanitizer is
/// pairwise-bypassable against the sink.
///
/// The format is contractually fixed — the string is consumed verbatim by the
/// Auth0 "Upstream Validation Audit" section renderer and by Bugcrowd triagers.
pub fn build_falsification_audit_string(record: &FalsifiedSanitizerRecord) -> String {
    format!(
        "Sanitizer {} was invoked, but mathematical falsification proves it is bypassable. Counterexample payload: {}",
        record.sanitizer_name, record.counterexample
    )
}

/// Canonical audit string emitted when Tier B proves a specific execution
/// path's sanitizer conjunction fails to entail the sink's safety contract.
///
/// Contractually fixed format; consumed verbatim by Auth0 "Upstream Validation
/// Audit" section and Bugcrowd report renderers.  The string names every
/// stamped sanitizer, the concrete counterexample payload, a domain-mapped
/// gap summary, one citation per [`SanitizerOrigin::FrameworkImplicit`]
/// contributor (Tier D), and one exclusion sentence per concurrently-safe
/// path (Tier E).
pub fn build_partial_sanitization_audit_string(record: &PartialSanitizationRecord) -> String {
    let mut out = format!(
        "Path sanitizers [{}] do not mathematically entail the sink's safety contract. Counterexample: output = {}. Gap: {}.",
        record.path_sanitizers.join(", "),
        record.counterexample,
        record.gap_summary
    );
    for note in &record.framework_notes {
        out.push(' ');
        out.push_str(note);
    }
    for safe_path in &record.excluded_safe_paths {
        out.push_str(&format!(
            " A concurrent path correctly sanitized by [{}] was analyzed, but the vulnerability remains exploitable via this bypass path.",
            safe_path.join(", ")
        ));
    }
    out
}

/// Summarize the mathematical gap between a path's sanitizer conjunction and
/// the sink's required predicate in a triager-ready sentence.
///
/// Produces strings of the form `"path is sanitized against {san_domain} but
/// fails to satisfy {sink_domain} constraints"`, where the domain names are
/// derived by scanning sanitizer function names and the sink's SMT assertion
/// for canonical substring markers.  Unrecognised predicates fall back to
/// `"generic input validation"` / `"sink-specific"` — the report still names
/// the sanitizers and counterexample, which carry the mathematical force.
pub fn summarize_entailment_gap(
    path_sanitizers: &[String],
    sink_predicate: &SinkPredicate,
) -> String {
    let san_domain = sanitizer_domain_label(path_sanitizers);
    let sink_domain = sink_domain_label(sink_predicate);
    format!("path is sanitized against {san_domain} but fails to satisfy {sink_domain} constraints")
}

fn sanitizer_domain_label(names: &[String]) -> String {
    let mut domains: std::collections::BTreeSet<&'static str> = std::collections::BTreeSet::new();
    for name in names {
        if name.contains("html")
            || name.contains("Html")
            || name.contains("htmlentities")
            || name.contains("htmlspecialchars")
        {
            domains.insert("XSS");
        } else if name.contains("url")
            || name.contains("URI")
            || name.contains("URL")
            || name.contains("quote_plus")
        {
            domains.insert("URL-encoding");
        } else if name.contains("sql")
            || name.contains("escape_literal")
            || name.contains("escape_string")
            || name.contains("parameterize")
            || name.contains("quote_sql")
        {
            domains.insert("SQL-quoting");
        }
    }
    if domains.is_empty() {
        return "generic input validation".to_string();
    }
    domains.into_iter().collect::<Vec<_>>().join(" + ")
}

fn sink_domain_label(sink: &SinkPredicate) -> &'static str {
    let a = sink.smt_assertion;
    if a.contains("javascript:") {
        "XSS URL-scheme"
    } else if a.contains("str.prefixof") || a.contains("http://internal") {
        "SSRF"
    } else if a.contains("str.contains output \"'\"") {
        "SQL-injection"
    } else if a.contains("../") {
        "path-traversal"
    } else if a.contains(';') && a.contains('|') {
        "shell-metacharacter"
    } else {
        "sink-specific"
    }
}

/// Run a Tier B per-path SMT entailment proof.
///
/// Asserts `(and φ₁ ... φₙ)` together with `(not φ_required)` and interprets
/// the z3 verdict:
///
/// - `sat`   → [`PathEntailmentVerdict::DoesNotEntail`] with the concrete
///   `output` counterexample.
/// - `unsat` → [`PathEntailmentVerdict::Entails`].
/// - anything else (z3 absent, spawn failure, parse error, sort mismatch) →
///   [`PathEntailmentVerdict::UnknownOrUnavailable`] so callers fall back to
///   the conservative Tier A verdict.
pub fn prove_path_entailment(
    path_predicates: &[SanitizerPredicate],
    sink: &SinkPredicate,
) -> PathEntailmentVerdict {
    if path_predicates.is_empty() {
        return PathEntailmentVerdict::UnknownOrUnavailable;
    }
    if !z3_is_available() {
        return PathEntailmentVerdict::UnknownOrUnavailable;
    }
    if path_predicates.iter().any(|p| p.output_sort != sink.sort) {
        return PathEntailmentVerdict::UnknownOrUnavailable;
    }
    let conj = if path_predicates.len() == 1 {
        path_predicates[0].smt_assertion.to_string()
    } else {
        let joined = path_predicates
            .iter()
            .map(|p| p.smt_assertion)
            .collect::<Vec<_>>()
            .join(" ");
        format!("(and {joined})")
    };
    let script = format!(
        "(set-logic ALL)\n\
         (declare-const {binding} {sort})\n\
         (assert {conj})\n\
         (assert (not {sink}))\n\
         (check-sat)\n\
         (get-value ({binding}))\n",
        binding = sink.variable,
        sort = sink.sort,
        conj = conj,
        sink = sink.smt_assertion,
    );
    match run_z3_script(&script) {
        Z3Outcome::Sat(counterexample) => PathEntailmentVerdict::DoesNotEntail {
            path_sanitizers: Vec::new(),
            counterexample,
        },
        Z3Outcome::Unsat => PathEntailmentVerdict::Entails,
        Z3Outcome::Unknown => PathEntailmentVerdict::UnknownOrUnavailable,
    }
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
    fn tier_b_single_sanitizer_path_fails_entailment_against_javascript_url_sink() {
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
            .partial_sanitization
            .expect("partial sanitization record must be populated");
        assert_eq!(record.path_sanitizers, vec!["escape_html".to_string()]);
        assert!(!record.counterexample.is_empty(), "counterexample required");
        assert!(record.gap_summary.contains("XSS"));
        assert!(record.gap_summary.contains("XSS URL-scheme"));
        let audit = report
            .sanitizer_audit
            .expect("partial sanitization audit must be populated");
        assert!(audit.starts_with(
            "Path sanitizers [escape_html] do not mathematically entail the sink's safety contract."
        ));
        assert!(audit.contains("Counterexample: output ="));
        assert!(audit.contains("Gap: path is sanitized against XSS"));
    }

    #[test]
    fn tier_b_escape_html_fails_entailment_against_ssrf_sink() {
        use super::z3_is_available;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        // escapeHtml's XSS predicate (`output` has no `<`) must NOT entail
        // an SSRF sink's safety predicate (`output` has no `http://internal`
        // prefix).  Z3 should return `sat` with a counterexample payload
        // that contains no `<` but does start with `http://internal`.
        let mut graph = DiGraph::<String, ()>::new();
        let source = graph.add_node("Controller.fetchRemote".to_string());
        let sanitizer_node = graph.add_node("escapeHtml".to_string());
        let sink = graph.add_node("Http.ssrf_fetch".to_string());
        graph.add_edge(source, sanitizer_node, ());
        graph.add_edge(sanitizer_node, sink, ());

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

        let sink_predicate = super::sink_predicate_for_label("ssrf_fetch")
            .expect("SSRF sink label must map to a concrete predicate");
        let report = solver.analyze_with_sink_predicate(
            "Controller.fetchRemote",
            "Http.ssrf_fetch",
            Some(&sink_predicate),
        );

        assert_eq!(
            report.label,
            NegTaintLabel::FalsifiedSanitizer,
            "path sanitized by escapeHtml must not entail SSRF safety"
        );
        let record = report
            .partial_sanitization
            .expect("partial sanitization record must be populated");
        assert_eq!(record.path_sanitizers, vec!["escapeHtml".to_string()]);
        assert!(!record.counterexample.is_empty(), "counterexample required");
        assert!(
            record.gap_summary.contains("XSS") && record.gap_summary.contains("SSRF"),
            "gap summary must name both the sanitizer and sink domains"
        );
        let audit = report
            .sanitizer_audit
            .expect("partial sanitization audit must be populated");
        assert!(audit.contains("Path sanitizers [escapeHtml]"));
        assert!(audit.contains("fails to satisfy SSRF constraints"));
    }

    #[test]
    fn tier_b_suppresses_finding_when_path_conjunction_entails_sink() {
        use super::z3_is_available;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        // Register a custom predicate whose guarantee strictly entails the
        // sink: both predicates assert `output = "safe"`.  Tier B must
        // return Validated (no partial sanitization record).
        let mut graph = DiGraph::<String, ()>::new();
        let source = graph.add_node("Controller.handle".to_string());
        let sanitizer_node = graph.add_node("ConstSafe.sanitize".to_string());
        let sink = graph.add_node("Dangerous.render".to_string());
        graph.add_edge(source, sanitizer_node, ());
        graph.add_edge(sanitizer_node, sink, ());

        let node_by_name = graph
            .node_indices()
            .map(|idx| (graph[idx].clone(), idx))
            .collect::<HashMap<_, _>>();
        let mut models = HashMap::new();
        models.insert(
            "ConstSafe.sanitize".to_string(),
            FunctionModel {
                validation_nodes: SmallVec::from_vec(vec!["const_safe_sanitize".to_string()]),
                ..FunctionModel::default()
            },
        );
        let mut registry = SanitizerRegistry::empty();
        registry.push(crate::sanitizer::SanitizerSpec {
            name: "const_safe_sanitize",
            kills: vec![common::taint::TaintKind::UserInput],
            role: crate::sanitizer::SanitizerRole::Sanitizer,
            predicate: Some(crate::sanitizer::SanitizerPredicate {
                output_sort: "String",
                smt_assertion: r#"(= output "safe")"#,
            }),
            origin: crate::sanitizer::SanitizerOrigin::UserDefined,
            framework_label: None,
        });
        let solver = NegTaintSolver::new(&graph, &node_by_name, &models, &registry);

        let sink_predicate = super::SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(= output "safe")"#,
        };
        let report = solver.analyze_with_sink_predicate(
            "Controller.handle",
            "Dangerous.render",
            Some(&sink_predicate),
        );

        assert_eq!(
            report.label,
            NegTaintLabel::Validated,
            "path whose conjunction entails the sink must stay Validated"
        );
        assert!(report.partial_sanitization.is_none());
        assert!(report.sanitizer_audit.is_none());
    }

    #[test]
    fn tier_b_prove_path_entailment_returns_entails_on_matching_predicates() {
        use super::{prove_path_entailment, z3_is_available, PathEntailmentVerdict};
        use crate::sanitizer::SanitizerPredicate;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        let predicate = SanitizerPredicate {
            output_sort: "String",
            smt_assertion: r#"(= output "safe")"#,
        };
        let sink = super::SinkPredicate {
            variable: "output",
            sort: "String",
            smt_assertion: r#"(= output "safe")"#,
        };
        let verdict = prove_path_entailment(&[predicate], &sink);
        assert!(matches!(verdict, PathEntailmentVerdict::Entails));
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

    #[test]
    fn tier_d_spring_request_body_audit_cites_framework_origin() {
        use super::z3_is_available;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        // Controller receives a `@RequestBody`-bound value (Jackson coercion
        // modeled as `springRequestBody`), which then flows into an SSRF
        // sink. Spring's implicit φ does not entail SSRF safety; Z3 finds a
        // counterexample and the audit must cite Spring by name.
        let mut graph = DiGraph::<String, ()>::new();
        let source = graph.add_node("UserController.createUser".to_string());
        let sanitizer_node = graph.add_node("springRequestBody".to_string());
        let sink = graph.add_node("InternalFetch.ssrf_fetch".to_string());
        graph.add_edge(source, sanitizer_node, ());
        graph.add_edge(sanitizer_node, sink, ());

        let node_by_name = graph
            .node_indices()
            .map(|idx| (graph[idx].clone(), idx))
            .collect::<HashMap<_, _>>();
        let mut models = HashMap::new();
        models.insert(
            "springRequestBody".to_string(),
            FunctionModel {
                validation_nodes: SmallVec::from_vec(vec!["springRequestBody".to_string()]),
                ..FunctionModel::default()
            },
        );
        let registry = SanitizerRegistry::with_defaults();
        let solver = NegTaintSolver::new(&graph, &node_by_name, &models, &registry);

        let sink_predicate = super::sink_predicate_for_label("ssrf_fetch")
            .expect("SSRF sink label must map to a concrete predicate");
        let report = solver.analyze_with_sink_predicate(
            "UserController.createUser",
            "InternalFetch.ssrf_fetch",
            Some(&sink_predicate),
        );

        assert_eq!(
            report.label,
            NegTaintLabel::FalsifiedSanitizer,
            "Spring implicit validator must not entail SSRF safety"
        );
        let record = report
            .partial_sanitization
            .expect("partial sanitization record must be populated");
        assert_eq!(
            record.path_sanitizers,
            vec!["springRequestBody".to_string()]
        );
        assert_eq!(
            record.framework_notes.len(),
            1,
            "Tier D must emit one framework citation for Spring"
        );
        assert!(record.framework_notes[0]
            .contains("The Spring framework implicit validator (springRequestBody) was evaluated"));
        assert!(record.framework_notes[0].contains("does not entail safety for this sink"));
        let audit = report
            .sanitizer_audit
            .expect("partial sanitization audit must be populated");
        assert!(audit.contains("Path sanitizers [springRequestBody]"));
        assert!(audit.contains("The Spring framework implicit validator"));
    }

    #[test]
    fn tier_e_non_monotonic_emits_finding_with_exclusion_clause() {
        use super::z3_is_available;

        if !z3_is_available() {
            eprintln!("skipping: z3 binary not present");
            return;
        }

        // Two concurrent paths into the SSRF sink:
        //   Path 1: source → validateSsrfUrl (entails SSRF safety) → sink
        //   Path 2: source → escapeHtml      (does NOT entail SSRF) → sink
        // Tier E must emit the finding on Path 2 and cite Path 1's
        // sanitizer in the exclusion clause.
        let mut graph = DiGraph::<String, ()>::new();
        let source = graph.add_node("Controller.handle".to_string());
        let safe_node = graph.add_node("validateSsrfUrl".to_string());
        let bypass_node = graph.add_node("escapeHtml".to_string());
        let sink = graph.add_node("Http.ssrf_fetch".to_string());
        graph.add_edge(source, safe_node, ());
        graph.add_edge(safe_node, sink, ());
        graph.add_edge(source, bypass_node, ());
        graph.add_edge(bypass_node, sink, ());

        let node_by_name = graph
            .node_indices()
            .map(|idx| (graph[idx].clone(), idx))
            .collect::<HashMap<_, _>>();
        let mut models = HashMap::new();
        models.insert(
            "validateSsrfUrl".to_string(),
            FunctionModel {
                validation_nodes: SmallVec::from_vec(vec!["validateSsrfUrl".to_string()]),
                ..FunctionModel::default()
            },
        );
        models.insert(
            "escapeHtml".to_string(),
            FunctionModel {
                validation_nodes: SmallVec::from_vec(vec!["escapeHtml".to_string()]),
                ..FunctionModel::default()
            },
        );

        // Custom registry: defaults (escapeHtml is already there) plus a
        // bespoke `validateSsrfUrl` whose φ matches the SSRF sink's
        // required predicate, so Z3 returns `unsat` → entails.
        let mut registry = SanitizerRegistry::with_defaults();
        registry.push(crate::sanitizer::SanitizerSpec {
            name: "validateSsrfUrl",
            kills: vec![common::taint::TaintKind::UserInput],
            role: crate::sanitizer::SanitizerRole::Sanitizer,
            predicate: Some(crate::sanitizer::SanitizerPredicate {
                output_sort: "String",
                smt_assertion: r#"(not (str.prefixof "http://internal" output))"#,
            }),
            origin: crate::sanitizer::SanitizerOrigin::UserDefined,
            framework_label: None,
        });
        let solver = NegTaintSolver::new(&graph, &node_by_name, &models, &registry);

        let sink_predicate = super::sink_predicate_for_label("ssrf_fetch")
            .expect("SSRF sink label must map to a concrete predicate");
        let report = solver.analyze_with_sink_predicate(
            "Controller.handle",
            "Http.ssrf_fetch",
            Some(&sink_predicate),
        );

        assert_eq!(
            report.label,
            NegTaintLabel::FalsifiedSanitizer,
            "finding must fire when any path fails entailment"
        );
        let record = report
            .partial_sanitization
            .expect("partial sanitization record required");
        assert_eq!(record.path_sanitizers, vec!["escapeHtml".to_string()]);
        assert_eq!(
            record.excluded_safe_paths.len(),
            1,
            "Tier E must record the concurrent safe path"
        );
        assert_eq!(
            record.excluded_safe_paths[0],
            vec!["validateSsrfUrl".to_string()]
        );
        let audit = report
            .sanitizer_audit
            .expect("audit string must be populated");
        assert!(audit.contains("Path sanitizers [escapeHtml]"));
        assert!(audit.contains(
            "A concurrent path correctly sanitized by [validateSsrfUrl] was analyzed, but the vulnerability remains exploitable via this bypass path."
        ));
    }
}
