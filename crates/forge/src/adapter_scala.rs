//! Scala Tree-sitter adapter for canonical IFDS facts.

use tree_sitter::Node;

use crate::ast_adapter::{collect_canonical_facts, CanonicalFact, NodeMap};

/// Exact P2-1 Scala Tree-sitter node map.
pub const SCALA_NODE_MAP: NodeMap = NodeMap {
    entry_nodes: &[
        "function_definition",
        "function_declaration",
        "class_definition",
        "object_definition",
        "trait_definition",
        "given_definition",
        "extension_definition",
        "lambda_expression",
        "case_clause",
    ],
    parameter_nodes: &[
        "parameter",
        "class_parameter",
        "binding",
        "bindings",
        "val_definition",
        "var_definition",
        "case_class_pattern",
        "capture_pattern",
        "typed_pattern",
        "given_pattern",
    ],
    propagation_nodes: &[
        "assignment_expression",
        "call_expression",
        "field_expression",
        "generic_function",
        "infix_expression",
        "postfix_expression",
        "prefix_expression",
        "match_expression",
        "try_expression",
        "for_expression",
        "tuple_expression",
        "interpolated_string_expression",
        "instance_expression",
    ],
    sink_nodes: &["call_expression", "infix_expression", "postfix_expression"],
};

const SCALA_SINK_TARGETS: &[&str] = &[
    "Runtime.exec",
    "Runtime.getRuntime().exec",
    "ProcessBuilder",
    "scala.sys.process",
    ".!",
    ".!!",
    "lineStream",
    "java.sql.Statement.execute",
    "PreparedStatement.execute",
    "Slick.sql",
    "Anorm.SQL",
    "WSClient.url",
    "sttp.",
    ".send",
    "Http().singleRequest",
    "XML.loadString",
    "scala.xml.XML.load",
    "ObjectInputStream.readObject",
    "Play",
    "Akka",
    "Pekko",
];

/// Emit canonical IFDS facts for Scala.
pub fn collect_scala_facts(root: Node<'_>, source: &[u8]) -> Vec<CanonicalFact> {
    collect_canonical_facts(root, source, SCALA_NODE_MAP, SCALA_SINK_TARGETS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_adapter::CanonicalFactKind;

    fn parse(source: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_scala::LANGUAGE.into())
            .expect("Scala grammar must load");
        parser.parse(source, None).expect("Scala must parse")
    }

    #[test]
    fn scala_adapter_emits_entry_parameter_call_sanitizer_and_sink() {
        let source = br#"
object App {
  def run(cmd: String) =
    Runtime.getRuntime().exec(html_escape(cmd))
}
"#;
        let tree = parse(source);
        let facts = collect_scala_facts(tree.root_node(), source);
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Entry));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Parameter));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Call));
        assert!(facts
            .iter()
            .any(|f| f.kind == CanonicalFactKind::SanitizerCall));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::SinkCall));
    }

    #[test]
    fn scala_adapter_does_not_promote_same_shape_benign_call_to_sink() {
        let source = br#"
object App {
  def run(cmd: String) = LocalWorker.run(cmd)
}
"#;
        let tree = parse(source);
        let facts = collect_scala_facts(tree.root_node(), source);
        assert!(!facts.iter().any(|f| f.kind == CanonicalFactKind::SinkCall));
    }
}
