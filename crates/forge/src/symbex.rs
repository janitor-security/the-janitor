//! Bounded symbolic-execution bridge for IFDS exploit witnesses.
//!
//! The first sprint version is intentionally narrow: it converts simple AST
//! binary predicates into SMT-LIB assertions and delegates satisfiability to Z3
//! through `rsmt2`.  Family-specific transfer functions plug into this module
//! later without changing the public executor shape.

use common::slop::ExploitWitness;
use rsmt2::Solver;
use tree_sitter::Node;

/// Path feasibility outcome for a bounded symbolic execution slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathFeasibility {
    /// Z3 proved at least one assignment satisfies the collected path guards.
    Satisfiable,
    /// Z3 proved the collected path guards are contradictory.
    Unsatisfiable,
    /// Solver unavailable or the AST slice was outside the current bridge.
    Unknown,
}

/// Vulnerability families supported by the symbolic-execution transfer table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VulnerabilityFamily {
    /// Unsafe object graph or byte-stream deserialization.
    Deserialization,
    /// Filesystem path traversal from attacker-controlled path segments.
    PathTraversal,
    /// Server-side request forgery through dynamic outbound URLs.
    SSRF,
    /// Authorization or authentication guard bypass.
    AuthBypass,
    /// Template rendering with attacker-controlled template source or context.
    TemplateInjection,
    /// OS command construction from attacker-controlled values.
    CommandInjection,
    /// Browser DOM XSS through HTML/script execution sinks.
    DOMXSS,
    /// SQL injection through attacker-controlled query fragments reaching a database sink.
    SQLInjection,
}

/// Template engine metadata carried by template-injection facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TemplateEngine {
    /// Shopify Liquid / LiquidJS-style template markers.
    Liquid,
}

/// Canonical IFDS fact class emitted by grammar adapters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalFactKind {
    /// Assignment transfer, e.g. `route = "/login"`.
    Assignment,
    /// Call transfer, e.g. `fetch(route)`.
    Call,
}

/// Canonical IFDS fact emitted by the JavaScript/TypeScript adapters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalFact {
    /// Fact class.
    pub kind: CanonicalFactKind,
    /// Assigned variable or called function.
    pub symbol: String,
    /// Literal value for assignments.
    pub value: Option<String>,
    /// Argument expressions for calls.
    pub arguments: Vec<String>,
    /// SMT-LIB assertion produced by the transfer function, when applicable.
    pub smt_constraint: Option<String>,
    /// Template engine inferred from the fact payload or render call context.
    pub template_engine: Option<TemplateEngine>,
}

/// Bounded symbolic executor seeded by an IFDS exploit witness and an AST node.
pub struct SymbolicExecutor<'tree> {
    witness: ExploitWitness,
    node: Node<'tree>,
    max_assertions: usize,
}

impl<'tree> SymbolicExecutor<'tree> {
    /// Construct an executor for one witness-bound AST slice.
    pub fn new(witness: ExploitWitness, node: Node<'tree>) -> Self {
        Self {
            witness,
            node,
            max_assertions: 64,
        }
    }

    /// Return the witness this executor is evaluating.
    pub fn witness(&self) -> &ExploitWitness {
        &self.witness
    }

    /// Check whether a Z3 process can be spawned through `rsmt2`.
    pub fn z3_context_available() -> bool {
        Solver::default_z3(()).is_ok()
    }

    /// Evaluate the collected path predicates for satisfiability.
    ///
    /// The current bridge recognizes `==`, `!=`, `<`, and `>` over integer
    /// literals or identifier-like symbols. Unknown expressions are skipped.
    pub fn evaluate_path_feasibility(&self, source: &[u8]) -> PathFeasibility {
        let mut solver = match Solver::default_z3(()) {
            Ok(solver) => solver,
            Err(_) => return PathFeasibility::Unknown,
        };

        let assertions = collect_binary_assertions(self.node, source, self.max_assertions);
        let mut declared = std::collections::BTreeSet::new();
        for assertion in &assertions {
            for ident in &assertion.identifiers {
                if declared.insert(ident.clone()) && solver.declare_const(ident, "Int").is_err() {
                    return PathFeasibility::Unknown;
                }
            }
            if solver.assert(assertion.smt.as_str()).is_err() {
                return PathFeasibility::Unknown;
            }
        }

        match solver.check_sat() {
            Ok(true) => PathFeasibility::Satisfiable,
            Ok(false) => PathFeasibility::Unsatisfiable,
            Err(_) => PathFeasibility::Unknown,
        }
    }

    /// Extract JavaScript/TypeScript canonical IFDS facts from the executor AST.
    ///
    /// Assignments to string literals produce string-theory SMT bindings. For
    /// example, `route = "/login"` emits `(= route "/login")`.
    pub fn extract_js_ts_facts(&self, source: &[u8]) -> Vec<CanonicalFact> {
        collect_js_ts_facts(self.node, source, self.max_assertions)
    }

    /// Evaluate JavaScript/TypeScript assignment transfer constraints.
    pub fn evaluate_js_ts_fact_constraints(&self, source: &[u8]) -> PathFeasibility {
        let facts = self.extract_js_ts_facts(source);
        evaluate_canonical_fact_constraints(&facts)
    }

    /// Build a minimal counterexample constraint for a high-value vulnerability
    /// family. The returned payload objective is deterministic and injects a
    /// concrete witness string into the exploitability pipeline.
    pub fn build_minimal_counterexample_constraint(
        &self,
        family: VulnerabilityFamily,
        witness_symbol: &str,
    ) -> crate::exploitability::PathConstraint {
        let symbol = sanitize_identifier(witness_symbol).unwrap_or_else(|| {
            sanitize_identifier(&self.witness.source_label)
                .unwrap_or_else(|| "user_input".to_string())
        });
        crate::exploitability::PathConstraint {
            family: Some(family),
            variables: vec![(symbol.clone(), crate::exploitability::SmtSort::String)],
            assertions: minimal_counterexample_assertions(family, &symbol),
            witnesses_of_interest: vec![symbol],
        }
    }
}

/// Family-specific payload objective used to force a concrete SMT witness.
pub fn minimal_counterexample_assertions(
    family: VulnerabilityFamily,
    witness_symbol: &str,
) -> Vec<String> {
    let Some(symbol) = sanitize_identifier(witness_symbol) else {
        return Vec::new();
    };
    match family {
        VulnerabilityFamily::PathTraversal => vec![
            format!("(str.contains {symbol} \"../\")"),
            format!("(str.suffixof \"/etc/passwd\" {symbol})"),
            format!("(= {symbol} \"../etc/passwd\")"),
        ],
        VulnerabilityFamily::SSRF => vec![
            format!("(str.prefixof \"http://\" {symbol})"),
            format!("(str.contains {symbol} \"169.254.169.254\")"),
            format!("(= {symbol} \"http://169.254.169.254/latest/meta-data/\")"),
        ],
        VulnerabilityFamily::CommandInjection => vec![
            format!("(str.contains {symbol} \";\")"),
            format!("(str.contains {symbol} \" id\")"),
            format!("(= {symbol} \"; id\")"),
        ],
        VulnerabilityFamily::SQLInjection => vec![
            format!("(str.contains {symbol} \"'\")"),
            format!("(str.contains {symbol} \" OR \")"),
            format!("(= {symbol} \"' OR 1=1 --\")"),
        ],
        _ => Vec::new(),
    }
}

/// Evaluate canonical SMT constraints emitted by grammar adapters.
pub fn evaluate_canonical_fact_constraints(facts: &[CanonicalFact]) -> PathFeasibility {
    let mut solver = match Solver::default_z3(()) {
        Ok(solver) => solver,
        Err(_) => return PathFeasibility::Unknown,
    };
    let mut declared = std::collections::BTreeSet::new();
    for fact in facts {
        let Some(assertion) = fact.smt_constraint.as_deref() else {
            continue;
        };
        // Use the sanitized form for SMT constant names so that member
        // expressions (e.g. config.scope → config_scope) produce valid
        // SMT-LIB2 identifiers consistent with the assertion string.
        let smt_name = sanitize_identifier(&fact.symbol).unwrap_or_else(|| fact.symbol.clone());
        if declared.insert(smt_name.clone()) && solver.declare_const(&smt_name, "String").is_err() {
            return PathFeasibility::Unknown;
        }
        if solver.assert(assertion).is_err() {
            return PathFeasibility::Unknown;
        }
    }

    match solver.check_sat() {
        Ok(true) => PathFeasibility::Satisfiable,
        Ok(false) => PathFeasibility::Unsatisfiable,
        Err(_) => PathFeasibility::Unknown,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SmtAssertion {
    smt: String,
    identifiers: Vec<String>,
}

fn collect_binary_assertions(root: Node<'_>, source: &[u8], limit: usize) -> Vec<SmtAssertion> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if out.len() >= limit {
            break;
        }
        if is_binary_node(node) {
            if let Some(assertion) = node
                .utf8_text(source)
                .ok()
                .and_then(translate_binary_expression)
            {
                out.push(assertion);
            }
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out
}

fn collect_js_ts_facts(root: Node<'_>, source: &[u8], limit: usize) -> Vec<CanonicalFact> {
    let mut out = Vec::new();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if out.len() >= limit {
            break;
        }
        if let Some(fact) = assignment_fact(node, source).or_else(|| call_fact(node, source)) {
            out.push(fact);
        }
        let mut cursor = node.walk();
        for child in node.children(&mut cursor) {
            stack.push(child);
        }
    }
    out.reverse();
    out
}

fn assignment_fact(node: Node<'_>, source: &[u8]) -> Option<CanonicalFact> {
    let (left, right) = match node.kind() {
        "variable_declarator" => (
            node.child_by_field_name("name")?,
            node.child_by_field_name("value")?,
        ),
        "assignment_expression" => (
            node.child_by_field_name("left")?,
            node.child_by_field_name("right")
                .or_else(|| nth_named_child(node, 2))?,
        ),
        _ => return None,
    };
    let symbol = left_identifier(left, source)?;
    let value = string_literal_value(right, source)?;
    let template_engine = liquid_marker_in_text(&value).then_some(TemplateEngine::Liquid);
    let smt_constraint = Some(format!(
        "(= {} {})",
        sanitize_identifier(&symbol)?,
        smt_string_literal(&value)
    ));
    Some(CanonicalFact {
        kind: CanonicalFactKind::Assignment,
        symbol,
        value: Some(value),
        arguments: Vec::new(),
        smt_constraint,
        template_engine,
    })
}

fn call_fact(node: Node<'_>, source: &[u8]) -> Option<CanonicalFact> {
    if node.kind() != "call_expression" {
        return None;
    }
    let function = node.child_by_field_name("function")?;
    let symbol = function.utf8_text(source).ok()?.trim().to_owned();
    if symbol.is_empty() {
        return None;
    }
    let arguments = node
        .child_by_field_name("arguments")
        .map(|args| {
            let mut cursor = args.walk();
            args.named_children(&mut cursor)
                .filter_map(|arg| arg.utf8_text(source).ok())
                .map(|arg| arg.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let template_engine = symbol
        .to_ascii_lowercase()
        .contains("render")
        .then(|| {
            arguments
                .iter()
                .any(|arg| liquid_marker_in_text(arg))
                .then_some(TemplateEngine::Liquid)
        })
        .flatten();
    Some(CanonicalFact {
        kind: CanonicalFactKind::Call,
        symbol,
        value: None,
        arguments,
        smt_constraint: None,
        template_engine,
    })
}

fn left_identifier(node: Node<'_>, source: &[u8]) -> Option<String> {
    match node.kind() {
        "identifier" => node.utf8_text(source).ok().map(str::to_owned),
        // Capture member expressions (e.g. config.scope) so object property
        // assignments produce SMT bindings for the full dotted path.
        "member_expression" => node.utf8_text(source).ok().map(str::to_owned),
        _ => None,
    }
}

fn string_literal_value(node: Node<'_>, source: &[u8]) -> Option<String> {
    if !matches!(node.kind(), "string" | "template_string" | "string_literal") {
        return None;
    }
    let text = node.utf8_text(source).ok()?.trim();
    text.strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .or_else(|| {
            text.strip_prefix('\'')
                .and_then(|value| value.strip_suffix('\''))
        })
        .or_else(|| {
            text.strip_prefix('`')
                .and_then(|value| value.strip_suffix('`'))
        })
        .map(str::to_owned)
}

fn nth_named_child(node: Node<'_>, index: usize) -> Option<Node<'_>> {
    let mut cursor = node.walk();
    let child = node.named_children(&mut cursor).nth(index);
    child
}

fn smt_string_literal(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\"\"");
    format!("\"{escaped}\"")
}

fn liquid_marker_in_text(text: &str) -> bool {
    text.contains("{{") || text.contains("{%")
}

fn is_binary_node(node: Node<'_>) -> bool {
    let kind = node.kind();
    kind.contains("binary") || kind.contains("comparison")
}

fn translate_binary_expression(expr: &str) -> Option<SmtAssertion> {
    for op in ["==", "!=", "<", ">"] {
        if let Some((lhs, rhs)) = split_once_operator(expr, op) {
            let lhs = smt_atom(lhs)?;
            let rhs = smt_atom(rhs)?;
            let smt = match op {
                "==" => format!("(= {} {})", lhs.0, rhs.0),
                "!=" => format!("(not (= {} {}))", lhs.0, rhs.0),
                "<" => format!("(< {} {})", lhs.0, rhs.0),
                ">" => format!("(> {} {})", lhs.0, rhs.0),
                _ => return None,
            };
            let mut identifiers = lhs.1.into_iter().chain(rhs.1).collect::<Vec<_>>();
            identifiers.sort();
            identifiers.dedup();
            return Some(SmtAssertion { smt, identifiers });
        }
    }
    None
}

fn split_once_operator<'a>(expr: &'a str, op: &str) -> Option<(&'a str, &'a str)> {
    let index = expr.find(op)?;
    let lhs = expr[..index].trim();
    let rhs = expr[index + op.len()..].trim();
    if lhs.is_empty() || rhs.is_empty() {
        return None;
    }
    Some((lhs, rhs))
}

fn smt_atom(raw: &str) -> Option<(String, Vec<String>)> {
    let trimmed = raw.trim().trim_matches(';').trim();
    if trimmed.parse::<i128>().is_ok() {
        return Some((trimmed.to_string(), Vec::new()));
    }
    let ident = sanitize_identifier(trimmed)?;
    Some((ident.clone(), vec![ident]))
}

fn sanitize_identifier(raw: &str) -> Option<String> {
    let mut ident = String::with_capacity(raw.len());
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            ident.push(ch);
        } else if ch == '.' || ch == '[' || ch == ']' {
            ident.push('_');
        } else {
            return None;
        }
    }
    if ident.is_empty() || ident.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        return None;
    }
    Some(ident)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_solidity(source: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_solidity::LANGUAGE;
        parser
            .set_language(&language.into())
            .expect("Solidity grammar must load");
        parser.parse(source, None).expect("Solidity must parse")
    }

    fn parse_js(source: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        let language = tree_sitter_javascript::LANGUAGE;
        parser
            .set_language(&language.into())
            .expect("JavaScript grammar must load");
        parser.parse(source, None).expect("JavaScript must parse")
    }

    fn witness() -> ExploitWitness {
        ExploitWitness {
            source_function: "withdraw".to_string(),
            source_label: "amount".to_string(),
            sink_function: "withdraw".to_string(),
            sink_label: "call.value".to_string(),
            call_chain: vec!["withdraw".to_string()],
            ..ExploitWitness::default()
        }
    }

    #[test]
    fn z3_context_spawn_does_not_panic() {
        let _available = SymbolicExecutor::z3_context_available();
    }

    #[test]
    fn evaluates_simple_solidity_binary_expression() {
        let source = br#"
pragma solidity ^0.8.20;
contract Guard {
    function f(uint256 amount) external pure returns (uint256) {
        if (amount > 0) { return amount; }
        return 0;
    }
}
"#;
        let tree = parse_solidity(source);
        let executor = SymbolicExecutor::new(witness(), tree.root_node());
        let verdict = executor.evaluate_path_feasibility(source);
        assert!(matches!(
            verdict,
            PathFeasibility::Satisfiable | PathFeasibility::Unknown
        ));
    }

    #[test]
    fn translates_basic_binary_expression() {
        let assertion = translate_binary_expression("amount > 0").expect("must translate");
        assert_eq!(assertion.smt, "(> amount 0)");
        assert_eq!(assertion.identifiers, vec!["amount"]);
    }

    #[test]
    fn extracts_js_assignment_fact_as_string_smt_binding() {
        let source = br#"
const route = "/login";
fetch(route);
"#;
        let tree = parse_js(source);
        let executor = SymbolicExecutor::new(witness(), tree.root_node());
        let facts = executor.extract_js_ts_facts(source);
        let assignment = facts
            .iter()
            .find(|fact| fact.kind == CanonicalFactKind::Assignment && fact.symbol == "route")
            .expect("route assignment must become a canonical fact");
        assert_eq!(assignment.value.as_deref(), Some("/login"));
        assert_eq!(
            assignment.smt_constraint.as_deref(),
            Some("(= route \"/login\")")
        );
        assert_eq!(assignment.template_engine, None);
        assert!(
            facts
                .iter()
                .any(|fact| fact.kind == CanonicalFactKind::Call && fact.symbol == "fetch"),
            "fetch(route) must become a canonical call fact"
        );
    }

    #[test]
    fn evaluates_js_assignment_constraints_without_panic() {
        let source = br#"let route = "/login";"#;
        let tree = parse_js(source);
        let executor = SymbolicExecutor::new(witness(), tree.root_node());
        let verdict = executor.evaluate_js_ts_fact_constraints(source);
        assert!(matches!(
            verdict,
            PathFeasibility::Satisfiable | PathFeasibility::Unknown
        ));
    }

    #[test]
    fn extracts_liquid_template_assignment_and_render_context() {
        let source = br#"
const template = "{{ payload }}";
renderTemplate(template);
renderTemplate("{% if user %}{{ payload }}{% endif %}");
"#;
        let tree = parse_js(source);
        let executor = SymbolicExecutor::new(witness(), tree.root_node());
        let facts = executor.extract_js_ts_facts(source);

        let assignment = facts
            .iter()
            .find(|fact| fact.kind == CanonicalFactKind::Assignment && fact.symbol == "template")
            .expect("template assignment must become a canonical fact");
        assert_eq!(assignment.template_engine, Some(TemplateEngine::Liquid));

        assert!(
            facts.iter().any(|fact| {
                fact.kind == CanonicalFactKind::Call
                    && fact.symbol == "renderTemplate"
                    && fact.template_engine == Some(TemplateEngine::Liquid)
            }),
            "render calls carrying Liquid markers must retain Liquid context"
        );
    }

    #[test]
    fn build_minimal_path_traversal_constraint_carries_concrete_payload_goal() {
        let source = br#"const path = user_input;"#;
        let tree = parse_js(source);
        let executor = SymbolicExecutor::new(witness(), tree.root_node());
        let constraint = executor.build_minimal_counterexample_constraint(
            VulnerabilityFamily::PathTraversal,
            "path_input",
        );

        assert_eq!(constraint.family, Some(VulnerabilityFamily::PathTraversal));
        assert_eq!(
            constraint.variables,
            vec![(
                "path_input".to_string(),
                crate::exploitability::SmtSort::String
            )]
        );
        assert!(
            constraint
                .assertions
                .iter()
                .any(|assertion| assertion.contains("../etc/passwd")),
            "path traversal objective must force a concrete traversal payload"
        );
    }

    #[test]
    fn command_injection_minimal_counterexample_anchors_shell_metacharacters() {
        let assertions =
            minimal_counterexample_assertions(VulnerabilityFamily::CommandInjection, "cmd");
        assert!(assertions
            .iter()
            .any(|assertion| assertion.contains("; id")));
        assert!(assertions
            .iter()
            .any(|assertion| assertion.contains("str.contains cmd \";\"")));
    }

    #[test]
    fn member_expression_assignment_tracks_object_property_scope() {
        let source = br#"
const config = {};
config.scope = "admin:org";
fetchData(config);
"#;
        let tree = parse_js(source);
        let executor = SymbolicExecutor::new(witness(), tree.root_node());
        let facts = executor.extract_js_ts_facts(source);
        let member_fact = facts
            .iter()
            .find(|f| f.kind == CanonicalFactKind::Assignment && f.symbol.contains("scope"));
        assert!(
            member_fact.is_some(),
            "config.scope = 'admin:org' must be captured as a canonical assignment fact"
        );
        let fact = member_fact.unwrap();
        assert_eq!(fact.value.as_deref(), Some("admin:org"));
        assert!(
            fact.smt_constraint
                .as_deref()
                .unwrap_or_default()
                .contains("admin"),
            "SMT constraint must bind the member expression to its literal value"
        );
    }

    #[test]
    fn sql_injection_minimal_counterexample_yields_or_1_eq_1_payload() {
        let assertions =
            minimal_counterexample_assertions(VulnerabilityFamily::SQLInjection, "user_input");
        assert!(
            assertions.iter().any(|a| a.contains("' OR 1=1 --")),
            "SQLi objective must include the canonical OR 1=1 payload"
        );
        assert!(
            assertions.iter().any(|a| a.contains("str.contains")),
            "SQLi objective must include string containment constraints"
        );
    }
}
