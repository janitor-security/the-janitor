//! Kotlin Tree-sitter adapter for canonical IFDS facts.

use tree_sitter::Node;

use crate::ast_adapter::{collect_canonical_facts, CanonicalFact, NodeMap};

/// Exact P2-1 Kotlin Tree-sitter node map.
pub const KOTLIN_NODE_MAP: NodeMap = NodeMap {
    entry_nodes: &[
        "function_declaration",
        "primary_constructor",
        "secondary_constructor",
        "property_declaration",
        "getter",
        "setter",
        "class_declaration",
        "object_declaration",
        "companion_object",
        "anonymous_initializer",
        "lambda_literal",
        "anonymous_function",
    ],
    parameter_nodes: &[
        "parameter",
        "class_parameter",
        "function_value_parameters",
        "value_argument",
        "variable_declaration",
        "multi_variable_declaration",
        "catch_block",
        "when_subject",
        "when_entry",
        "lambda_parameters",
    ],
    propagation_nodes: &[
        "assignment",
        "call_expression",
        "call_suffix",
        "value_arguments",
        "navigation_expression",
        "navigation_suffix",
        "indexing_expression",
        "indexing_suffix",
        "infix_expression",
        "elvis_expression",
        "as_expression",
        "try_expression",
        "when_expression",
        "if_expression",
        "string_literal",
        "interpolated_expression",
        "property_delegate",
        "constructor_invocation",
    ],
    sink_nodes: &[
        "call_expression",
        "constructor_invocation",
        "infix_expression",
    ],
};

const KOTLIN_SINK_TARGETS: &[&str] = &[
    "Runtime.getRuntime().exec",
    "ProcessBuilder",
    "java.sql.Statement.execute",
    "JdbcTemplate.query",
    "JdbcTemplate.execute",
    "JdbcTemplate.update",
    "HttpClient.request",
    "OkHttpClient.newCall",
    "URL.openConnection",
    "ObjectInputStream.readObject",
    "Yaml.load",
    "Json.decodeFromString",
    "Class.forName",
    "Method.invoke",
    "File(",
    "Files.",
    "Paths.get",
    "loadUrl",
    "Intent(",
    "WebView",
];

/// Emit canonical IFDS facts for Kotlin.
pub fn collect_kotlin_facts(root: Node<'_>, source: &[u8]) -> Vec<CanonicalFact> {
    collect_canonical_facts(root, source, KOTLIN_NODE_MAP, KOTLIN_SINK_TARGETS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast_adapter::CanonicalFactKind;

    fn parse(source: &[u8]) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_kotlin_ng::LANGUAGE.into())
            .expect("Kotlin grammar must load");
        parser.parse(source, None).expect("Kotlin must parse")
    }

    #[test]
    fn kotlin_adapter_emits_entry_parameter_call_sanitizer_and_sink() {
        let source = br#"
fun run(cmd: String) {
  Runtime.getRuntime().exec(urlencode(cmd))
}
"#;
        let tree = parse(source);
        let facts = collect_kotlin_facts(tree.root_node(), source);
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Entry));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Parameter));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::Call));
        assert!(facts
            .iter()
            .any(|f| f.kind == CanonicalFactKind::SanitizerCall));
        assert!(facts.iter().any(|f| f.kind == CanonicalFactKind::SinkCall));
    }

    #[test]
    fn kotlin_adapter_preserves_safe_call_and_non_null_lattice_transitions() {
        let source = br#"
fun render(webView: WebView?, html: String?) {
  webView?.loadUrl(html!!)
}
"#;
        let tree = parse(source);
        let facts = collect_kotlin_facts(tree.root_node(), source);
        assert!(facts
            .iter()
            .any(|f| f.kind == CanonicalFactKind::ControlGuard));
    }

    #[test]
    fn kotlin_adapter_does_not_promote_same_shape_benign_call_to_sink() {
        let source = br#"
fun run(cmd: String) {
  LocalRuntime.exec(cmd)
}
"#;
        let tree = parse(source);
        let facts = collect_kotlin_facts(tree.root_node(), source);
        assert!(!facts.iter().any(|f| f.kind == CanonicalFactKind::SinkCall));
    }
}
