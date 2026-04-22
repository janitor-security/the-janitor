//! Swift Tree-sitter adapter for canonical IFDS facts.

use tree_sitter::Node;

use crate::ast_adapter::{collect_canonical_facts, CanonicalFact, NodeMap};

/// Exact P2-1 Swift Tree-sitter node map.
pub const SWIFT_NODE_MAP: NodeMap = NodeMap {
    entry_nodes: &[
        "function_declaration",
        "init_declaration",
        "property_declaration",
        "subscript_declaration",
        "class_declaration",
        "lambda_literal",
        "computed_property",
        "computed_getter",
        "computed_setter",
        "willset_clause",
        "didset_clause",
    ],
    parameter_nodes: &[
        "parameter",
        "value_argument",
        "lambda_parameter",
        "capture_list_item",
        "for_statement",
        "catch_block",
        "_if_let_binding",
    ],
    propagation_nodes: &[
        "assignment",
        "call_expression",
        "constructor_expression",
        "navigation_expression",
        "navigation_suffix",
        "value_arguments",
        "tuple_expression",
        "array_literal",
        "dictionary_literal",
        "as_expression",
        "try_expression",
        "await_expression",
        "nil_coalescing_expression",
        "ternary_expression",
        "key_path_expression",
        "key_path_string_expression",
    ],
    sink_nodes: &[
        "call_expression",
        "constructor_expression",
        "macro_invocation",
    ],
};

const SWIFT_SINK_TARGETS: &[&str] = &[
    "URLSession.dataTask",
    "URLSession.uploadTask",
    "URLSession.downloadTask",
    "Process.run",
    "FileManager.",
    "NSPredicate(format:",
    "NSExpression(format:",
    "WKWebView.loadHTMLString",
    "evaluateJavaScript",
    "SecItemAdd",
    "SecItemUpdate",
    "NSKeyedUnarchiver",
    "JSONDecoder.decode",
    "SQLDatabase.execute",
    "UnsafePointer",
    "UnsafeMutablePointer",
    "unsafeBitCast",
];

/// Emit canonical IFDS facts for Swift.
pub fn collect_swift_facts(root: Node<'_>, source: &[u8]) -> Vec<CanonicalFact> {
    collect_canonical_facts(root, source, SWIFT_NODE_MAP, SWIFT_SINK_TARGETS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_adapter::CanonicalFactKind;

    fn parse(source: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_swift::LANGUAGE.into())
            .expect("Swift grammar must load");
        parser.parse(source, None).expect("Swift must parse")
    }

    #[test]
    fn swift_adapter_emits_entry_parameter_call_sanitizer_and_sink() {
        let source = br#"
func load(input: String) {
  let clean = html_escape(input)
  URLSession.dataTask(with: URL(string: clean)!)
}
"#;
        let tree = parse(source);
        let facts = collect_swift_facts(tree.root_node(), source);
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Entry));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Parameter));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Call));
        assert!(facts
            .iter()
            .any(|f| f.kind == CanonicalFactKind::SanitizerCall));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::SinkCall));
    }

    #[test]
    fn swift_adapter_does_not_promote_same_shape_benign_call_to_sink() {
        let source = br#"
func load(input: String) {
  LocalClient.dataTask(with: input)
}
"#;
        let tree = parse(source);
        let facts = collect_swift_facts(tree.root_node(), source);
        assert!(!facts.iter().any(|f| f.kind == CanonicalFactKind::SinkCall));
    }
}
