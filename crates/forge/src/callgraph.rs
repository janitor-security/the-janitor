//! Call graph extraction for interprocedural taint analysis (P1-1).
//!
//! Builds a directed call graph from a single source file using the tree-sitter
//! AST.  Edges represent "function A calls function B".
//!
//! ## Supported languages
//!
//! | Extension(s)      | Definition node           | Call node         |
//! |-------------------|---------------------------|-------------------|
//! | `py`              | `function_definition`     | `call`            |
//! | `js`, `jsx`       | `function_declaration`,   | `call_expression` |
//! |                   | `method_definition`,      |                   |
//! |                   | `function`                |                   |
//! | `ts`, `tsx`       | same as JS                | `call_expression` |
//! | `java`            | `method_declaration`,     | `method_invocation` |
//! |                   | `constructor_declaration` |                   |
//! | `go`              | `function_declaration`,   | `call_expression` |
//! |                   | `method_declaration`      |                   |
//!
//! ## Depth guard
//! The recursive walk caps at 200 levels to prevent stack overflow on
//! adversarially deep ASTs.  This matches the depth guards in `taint_propagate`.

use std::collections::HashMap;

use petgraph::graph::{DiGraph, NodeIndex};
use tree_sitter::{Node, Parser};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A directed call graph over a single source file.
///
/// Nodes are function names (bare identifiers, not qualified paths).
/// A directed edge A → B means "function A contains a call to function B."
pub type CallGraph = DiGraph<String, ()>;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a call graph from `source` bytes for the given file `language`
/// extension.
///
/// Returns an empty graph when the language is unsupported or when
/// tree-sitter parsing fails.  Never panics.
pub fn build_call_graph(language: &str, source: &[u8]) -> CallGraph {
    let Some(ts_lang) = get_language(language) else {
        return DiGraph::new();
    };
    let mut parser = Parser::new();
    if parser.set_language(&ts_lang).is_err() {
        return DiGraph::new();
    }
    let Some(tree) = parser.parse(source, None) else {
        return DiGraph::new();
    };

    let mut graph = DiGraph::new();
    let mut node_map: HashMap<String, NodeIndex> = HashMap::new();

    walk_node(
        tree.root_node(),
        source,
        language,
        None,
        &mut graph,
        &mut node_map,
        0,
    );

    graph
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns `true` when `kind` is a function/method definition node for the
/// given language.
fn is_fn_def_kind(kind: &str, language: &str) -> bool {
    match language {
        "py" => matches!(kind, "function_definition"),
        "js" | "jsx" | "ts" | "tsx" => {
            matches!(
                kind,
                "function_declaration" | "method_definition" | "function"
            )
        }
        "java" => matches!(kind, "method_declaration" | "constructor_declaration"),
        "go" => matches!(kind, "function_declaration" | "method_declaration"),
        "rb" => matches!(kind, "method"),
        _ => false,
    }
}

/// Returns `true` when `kind` is a call/invocation node for the given language.
fn is_call_kind(kind: &str, language: &str) -> bool {
    match language {
        "py" => matches!(kind, "call"),
        "js" | "jsx" | "ts" | "tsx" => matches!(kind, "call_expression"),
        "java" => matches!(kind, "method_invocation"),
        "go" => matches!(kind, "call_expression"),
        "rb" => matches!(kind, "call" | "method_call"),
        _ => false,
    }
}

/// Extract the bare function name from a definition node.
///
/// Most languages expose a `name` field on the definition node.
/// Returns `None` for anonymous functions (arrow functions with no `name`
/// binding at the definition site).
fn extract_fn_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    let name_node = node.child_by_field_name("name")?;
    let text = name_node.utf8_text(source).ok()?.trim().to_owned();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// Extract the callee name from a call/invocation node.
///
/// For simple calls (`foo()`), returns `"foo"`.
/// For method calls (`obj.method()`), returns the method name (`"method"`).
/// Returns `None` when the callee cannot be determined statically (e.g.,
/// computed property calls).
fn extract_callee(node: Node<'_>, source: &[u8], language: &str) -> Option<String> {
    match language {
        "py" => {
            let fn_node = node.child_by_field_name("function")?;
            match fn_node.kind() {
                "identifier" => Some(fn_node.utf8_text(source).ok()?.trim().to_owned()),
                "attribute" => {
                    let attr = fn_node.child_by_field_name("attribute")?;
                    Some(attr.utf8_text(source).ok()?.trim().to_owned())
                }
                _ => None,
            }
        }
        "js" | "jsx" | "ts" | "tsx" => {
            let fn_node = node.child_by_field_name("function")?;
            match fn_node.kind() {
                "identifier" => Some(fn_node.utf8_text(source).ok()?.trim().to_owned()),
                "member_expression" => {
                    let prop = fn_node.child_by_field_name("property")?;
                    Some(prop.utf8_text(source).ok()?.trim().to_owned())
                }
                _ => None,
            }
        }
        "java" => {
            let name = node.child_by_field_name("name")?;
            Some(name.utf8_text(source).ok()?.trim().to_owned())
        }
        "go" => {
            let fn_node = node.child_by_field_name("function")?;
            match fn_node.kind() {
                "identifier" => Some(fn_node.utf8_text(source).ok()?.trim().to_owned()),
                "selector_expression" => {
                    let field = fn_node.child_by_field_name("field")?;
                    Some(field.utf8_text(source).ok()?.trim().to_owned())
                }
                _ => None,
            }
        }
        "rb" => {
            // Ruby: `call` has a `method` field for the method name
            let m = node.child_by_field_name("method")?;
            Some(m.utf8_text(source).ok()?.trim().to_owned())
        }
        _ => None,
    }
}

/// Get-or-create a node index for `name` in the graph.
fn get_or_insert(
    name: &str,
    graph: &mut CallGraph,
    node_map: &mut HashMap<String, NodeIndex>,
) -> NodeIndex {
    *node_map
        .entry(name.to_owned())
        .or_insert_with(|| graph.add_node(name.to_owned()))
}

/// Recursive tree walk that populates the call graph.
///
/// `current_fn` is the name of the innermost enclosing function definition,
/// or `None` at module/file scope.  The `depth` guard prevents stack overflow
/// on adversarially nested ASTs.
fn walk_node(
    node: Node<'_>,
    source: &[u8],
    language: &str,
    current_fn: Option<&str>,
    graph: &mut CallGraph,
    node_map: &mut HashMap<String, NodeIndex>,
    depth: usize,
) {
    if depth > 200 {
        return;
    }

    let kind = node.kind();

    // If this node introduces a new function scope, extract the name.
    let new_fn_name: Option<String> = if is_fn_def_kind(kind, language) {
        extract_fn_name(node, source)
    } else {
        None
    };

    // Effective caller context: the new function name, or the inherited one.
    let effective_fn: Option<&str> = new_fn_name.as_deref().or(current_fn);

    // If this is a call expression, record caller → callee.
    if is_call_kind(kind, language) {
        if let (Some(caller), Some(callee)) = (effective_fn, extract_callee(node, source, language))
        {
            let caller_idx = get_or_insert(caller, graph, node_map);
            let callee_idx = get_or_insert(&callee, graph, node_map);
            // Avoid duplicate edges (petgraph DiGraph is a multigraph by default).
            if !graph.contains_edge(caller_idx, callee_idx) {
                graph.add_edge(caller_idx, callee_idx, ());
            }
        }
    }

    // Recurse into children, passing the updated function context.
    let child_fn = new_fn_name.as_deref().or(current_fn);
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        walk_node(
            child,
            source,
            language,
            child_fn,
            graph,
            node_map,
            depth + 1,
        );
    }
}

/// Returns the tree-sitter `Language` for a given file extension.
fn get_language(language: &str) -> Option<tree_sitter::Language> {
    match language {
        "py" => Some(tree_sitter_python::LANGUAGE.into()),
        "js" | "jsx" => Some(tree_sitter_javascript::LANGUAGE.into()),
        "ts" | "tsx" => Some(tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into()),
        "java" => Some(tree_sitter_java::LANGUAGE.into()),
        "go" => Some(tree_sitter_go::LANGUAGE.into()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use petgraph::visit::EdgeRef as _;

    #[test]
    fn call_graph_python_direct_call() {
        // Indentation must be explicit — \\ line-continuation strips leading spaces.
        let src = b"def helper(x):\n    return x + 1\n\ndef process(val):\n    result = helper(val)\n    return result\n";
        let graph = build_call_graph("py", src);
        let process_idx = graph.node_indices().find(|i| graph[*i] == "process");
        let helper_idx = graph.node_indices().find(|i| graph[*i] == "helper");
        assert!(process_idx.is_some(), "process node must exist");
        assert!(helper_idx.is_some(), "helper node must exist");
        assert!(
            graph.contains_edge(process_idx.unwrap(), helper_idx.unwrap()),
            "process must have a call edge to helper"
        );
    }

    #[test]
    fn call_graph_python_no_cross_call() {
        let src = b"def a():\n    pass\n\ndef b():\n    pass\n";
        let graph = build_call_graph("py", src);
        assert_eq!(graph.edge_count(), 0, "no calls between a and b");
    }

    #[test]
    fn call_graph_python_multiple_callees() {
        let src = b"def validate(x):\n    return x\n\ndef sanitize(x):\n    return x\n\ndef handle(input):\n    v = validate(input)\n    s = sanitize(v)\n    return s\n";
        let graph = build_call_graph("py", src);
        let handle_idx = graph
            .node_indices()
            .find(|i| graph[*i] == "handle")
            .expect("handle node must exist");
        let validate_idx = graph
            .node_indices()
            .find(|i| graph[*i] == "validate")
            .expect("validate node must exist");
        let sanitize_idx = graph
            .node_indices()
            .find(|i| graph[*i] == "sanitize")
            .expect("sanitize node must exist");
        assert!(
            graph.contains_edge(handle_idx, validate_idx),
            "handle must call validate"
        );
        assert!(
            graph.contains_edge(handle_idx, sanitize_idx),
            "handle must call sanitize"
        );
    }

    #[test]
    fn call_graph_js_direct_call() {
        let src = b"function sanitize(input) {\n    return input.replace(/[<>]/g, '');\n}\n\nfunction render(data) {\n    return sanitize(data);\n}\n";
        let graph = build_call_graph("js", src);
        let render_idx = graph.node_indices().find(|i| graph[*i] == "render");
        let sanitize_idx = graph.node_indices().find(|i| graph[*i] == "sanitize");
        assert!(render_idx.is_some(), "render node must exist");
        assert!(sanitize_idx.is_some(), "sanitize node must exist");
        assert!(
            graph.contains_edge(render_idx.unwrap(), sanitize_idx.unwrap()),
            "render must have a call edge to sanitize"
        );
    }

    #[test]
    fn call_graph_unsupported_language_is_empty() {
        let graph = build_call_graph("cobol", b"PROCEDURE DIVISION.");
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn call_graph_empty_source_is_empty() {
        let graph = build_call_graph("py", b"");
        assert_eq!(graph.node_count(), 0);
        assert_eq!(graph.edge_count(), 0);
    }

    #[test]
    fn call_graph_no_duplicate_edges() {
        // Even if a function calls another function twice, only one edge.
        let src = b"def foo():\n    pass\n\ndef bar():\n    foo()\n    foo()\n";
        let graph = build_call_graph("py", src);
        let bar_idx = graph
            .node_indices()
            .find(|i| graph[*i] == "bar")
            .expect("bar node must exist");
        let foo_idx = graph
            .node_indices()
            .find(|i| graph[*i] == "foo")
            .expect("foo node must exist");
        let edge_count = graph
            .edges_directed(bar_idx, petgraph::Direction::Outgoing)
            .filter(|e| e.target() == foo_idx)
            .count();
        assert_eq!(edge_count, 1, "duplicate calls must produce only one edge");
    }
}
