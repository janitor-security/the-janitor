//! Intra-file interprocedural taint propagation — parameter-to-sink tracking.
//!
//! Current scope (v9.7.1): Go `database/sql` SQLi confirmation (Go-3 gate).
//!
//! A function parameter is treated as a `UserInput` taint source.  When that
//! parameter appears as a non-literal operand in a `db.Query(... + param ...)`
//! concatenation, a [`TaintFlow`] is emitted confirming the source-to-sink path.
//!
//! ## Why intra-file first
//! Cross-file 3-hop propagation requires a persistent `TaintExportRecord`
//! catalog (see `crates/common/src/taint.rs`).  Intra-file analysis is
//! self-contained and proves the mechanism before the catalog I/O layer is
//! introduced.
//!
//! ## Fail-open contract
//! All functions in this module return empty `Vec` rather than errors.  A parse
//! failure or missing parameter list never blocks a bounce — it only means taint
//! confirmation is absent, leaving the base Go-3 gate as the sole signal.

use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A confirmed intra-file taint flow from a function parameter to a SQL sink.
///
/// Emitted when a named function parameter directly appears as a non-literal
/// operand in a Go `database/sql` concatenation call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintFlow {
    /// Name of the function parameter that carries taint into the SQL sink.
    pub taint_source: String,
    /// Start byte of the `call_expression` that is the SQL sink.
    pub sink_byte: usize,
    /// End byte of the `call_expression` that is the SQL sink.
    pub sink_end_byte: usize,
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Go `database/sql` method names whose first argument must not be a dynamic
/// string concatenation (mirrors the Go-3 gate in `slop_hunter.rs`).
const GO_SQL_METHODS: &[&str] = &["Query", "Exec", "QueryRow", "QueryContext", "ExecContext"];
const PHP_SQL_METHODS: &[&str] = &["query", "real_query"];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Track intra-file taint from Go function parameters to `database/sql` sinks.
///
/// ## Algorithm
/// 1. Walk the entire file tree and collect every parameter `identifier` name
///    from `parameter_declaration` nodes into a parameter set.
/// 2. Walk the tree again to find `call_expression` nodes whose selector field
///    matches a Go SQL method, whose first argument is a `binary_expression`
///    containing `+`, and where at least one non-literal operand (recursive)
///    matches a collected parameter name.
/// 3. Return a [`TaintFlow`] per confirmed parameter→sink pair.
///
/// Returns an empty `Vec` (fail-open) when no confirmed flow exists.
pub fn track_taint_go_sqli(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let mut params: Vec<String> = Vec::new();
    collect_go_params(root, source, &mut params, 0);
    if params.is_empty() {
        return Vec::new();
    }
    let mut flows: Vec<TaintFlow> = Vec::new();
    find_tainted_sql_sinks(root, source, &params, &mut flows, 0);
    flows
}

/// Collect Ruby method parameters from the parsed AST.
pub fn collect_ruby_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_named_params_by_kind(root, source, "method_parameters", &mut params, 0);
    params
}

/// Track Ruby ActiveRecord SQLi flows from method parameters into `where("#{...}")`.
pub fn find_tainted_ruby_sql_sinks(
    root: Node<'_>,
    source: &[u8],
    params: &[String],
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    find_ruby_sql_sinks(root, source, params, &mut flows, 0);
    flows
}

/// Collect PHP function or method parameters from the parsed AST.
pub fn collect_php_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_php_parameter_names(root, source, &mut params, 0);
    params
}

/// Track PHP SQLi flows into raw PDO / mysqli query concatenation.
pub fn find_tainted_php_sql_sinks(
    root: Node<'_>,
    source: &[u8],
    params: &[String],
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    find_php_sql_sinks(root, source, params, &mut flows, 0);
    flows
}

/// Kotlin taint stub — reserved for a subsequent release.
pub fn collect_kotlin_params(_root: Node<'_>, _source: &[u8]) -> Vec<String> {
    Vec::new()
}

/// C/C++ taint stub — reserved for a subsequent release.
pub fn collect_cpp_params(_root: Node<'_>, _source: &[u8]) -> Vec<String> {
    Vec::new()
}

/// Swift taint stub — reserved for a subsequent release.
pub fn collect_swift_params(_root: Node<'_>, _source: &[u8]) -> Vec<String> {
    Vec::new()
}

// ---------------------------------------------------------------------------
// Parameter collection
// ---------------------------------------------------------------------------

/// Recursively collect parameter names from `parameter_declaration` nodes.
///
/// In tree-sitter-go a `parameter_declaration` has zero or more `identifier`
/// children (the parameter names) followed by a type node.  Both named and
/// unnamed parameters are handled: unnamed parameters (`_`) are collected but
/// will never match an identifier in a call site, so they produce no false
/// positives.
fn collect_go_params(node: Node<'_>, source: &[u8], params: &mut Vec<String>, depth: u32) {
    if depth > 100 {
        return;
    }
    if node.kind() == "parameter_declaration" {
        let mut cur = node.walk();
        for child in node.named_children(&mut cur) {
            if child.kind() == "identifier" {
                if let Ok(name) = child.utf8_text(source) {
                    if !name.is_empty() {
                        params.push(name.to_string());
                    }
                }
            }
        }
        // Do not recurse into parameter_declaration children — they carry
        // type nodes, not nested parameters.
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_go_params(child, source, params, depth + 1);
    }
}

fn collect_named_params_by_kind(
    node: Node<'_>,
    source: &[u8],
    param_list_kind: &str,
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == param_list_kind {
        let mut cur = node.walk();
        for child in node.named_children(&mut cur) {
            if child.kind() == "identifier" {
                if let Ok(name) = child.utf8_text(source) {
                    if !name.is_empty() {
                        params.push(name.to_string());
                    }
                }
            }
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_named_params_by_kind(child, source, param_list_kind, params, depth + 1);
    }
}

fn collect_php_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "simple_parameter" || node.kind() == "variadic_parameter" {
        let name = node
            .child_by_field_name("name")
            .or_else(|| {
                let mut cur = node.walk();
                let child = node
                    .named_children(&mut cur)
                    .find(|child| child.kind().contains("variable"));
                child
            })
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("")
            .trim_start_matches('$')
            .to_string();
        if !name.is_empty() {
            params.push(name);
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_php_parameter_names(child, source, params, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Sink detection
// ---------------------------------------------------------------------------

/// Recursively walk the tree and record SQL sinks whose concat operand is a
/// known parameter.
fn find_tainted_sql_sinks(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    flows: &mut Vec<TaintFlow>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call_expression" {
        if let Some(func) = node.child_by_field_name("function") {
            if func.kind() == "selector_expression" {
                let field_text = func
                    .child_by_field_name("field")
                    .and_then(|n| n.utf8_text(source).ok())
                    .unwrap_or("");
                if GO_SQL_METHODS.contains(&field_text) {
                    if let Some(args) = node.child_by_field_name("arguments") {
                        if let Some(first_arg) = args.named_children(&mut args.walk()).next() {
                            if first_arg.kind() == "binary_expression" {
                                let has_plus = first_arg.children(&mut first_arg.walk()).any(|c| {
                                    !c.is_named()
                                        && c.utf8_text(source).map(|t| t == "+").unwrap_or(false)
                                });
                                if has_plus {
                                    if let Some(src) =
                                        find_tainted_operand(first_arg, source, params, 0)
                                    {
                                        flows.push(TaintFlow {
                                            taint_source: src,
                                            sink_byte: node.start_byte(),
                                            sink_end_byte: node.end_byte(),
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_tainted_sql_sinks(child, source, params, flows, depth + 1);
    }
}

fn find_ruby_sql_sinks(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    flows: &mut Vec<TaintFlow>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "call" {
        let method_text = node
            .child_by_field_name("method")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        if method_text == "where" {
            if let Some(args) = node.child_by_field_name("arguments") {
                if let Some(first_arg) = args.named_children(&mut args.walk()).next() {
                    if let Ok(arg_text) = first_arg.utf8_text(source) {
                        if let Some(param) = params
                            .iter()
                            .find(|param| arg_text.contains(&format!("#{{{param}}}")))
                        {
                            flows.push(TaintFlow {
                                taint_source: param.clone(),
                                sink_byte: node.start_byte(),
                                sink_end_byte: node.end_byte(),
                            });
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_ruby_sql_sinks(child, source, params, flows, depth + 1);
    }
}

fn find_php_sql_sinks(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    flows: &mut Vec<TaintFlow>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    match node.kind() {
        "function_call_expression" => {
            let func_text = node
                .child_by_field_name("function")
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            if func_text == "mysqli_query" {
                if let Some(args) = node.child_by_field_name("arguments") {
                    let mut arg_walk = args.walk();
                    let mut named = args.named_children(&mut arg_walk);
                    let _conn = named.next();
                    if let Some(query_arg) = named.next() {
                        record_php_taint_flow(node, query_arg, source, params, flows);
                    }
                }
            }
        }
        "member_call_expression" | "method_call_expression" => {
            let method_text = node
                .child_by_field_name("name")
                .or_else(|| node.child_by_field_name("member"))
                .and_then(|n| n.utf8_text(source).ok())
                .unwrap_or("");
            if PHP_SQL_METHODS.contains(&method_text) {
                if let Some(args) = node.child_by_field_name("arguments") {
                    if let Some(query_arg) = args.named_children(&mut args.walk()).next() {
                        record_php_taint_flow(node, query_arg, source, params, flows);
                    }
                }
            }
        }
        _ => {}
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_php_sql_sinks(child, source, params, flows, depth + 1);
    }
}

fn record_php_taint_flow(
    sink_node: Node<'_>,
    arg_node: Node<'_>,
    source: &[u8],
    params: &[String],
    flows: &mut Vec<TaintFlow>,
) {
    let Ok(arg_text) = arg_node.utf8_text(source) else {
        return;
    };
    if !arg_text.contains('.') && !arg_text.contains('{') {
        return;
    }
    if let Some(param) = params.iter().find(|param| {
        arg_text.contains(&format!("${param}"))
            && (arg_text.contains('.') || arg_text.contains(&format!("{{${param}}}")))
    }) {
        flows.push(TaintFlow {
            taint_source: param.clone(),
            sink_byte: sink_node.start_byte(),
            sink_end_byte: sink_node.end_byte(),
        });
    }
}

/// Recursively inspect `binary_expression` operands to find a parameter name.
///
/// Handles nested concatenation: `"prefix" + table + " WHERE " + filter`
/// produces a left-skewed binary tree; recursive descent on the `left` field
/// discovers `table` even though it is two levels deep.
fn find_tainted_operand(
    binary_expr: Node<'_>,
    source: &[u8],
    params: &[String],
    depth: u32,
) -> Option<String> {
    if depth > 100 {
        return None;
    }
    for field in ["left", "right"] {
        let Some(operand) = binary_expr.child_by_field_name(field) else {
            continue;
        };
        match operand.kind() {
            "identifier" => {
                let name = operand.utf8_text(source).unwrap_or("");
                if params.iter().any(|p| p == name) {
                    return Some(name.to_string());
                }
            }
            "binary_expression" => {
                // Recursive: handle multi-level concatenation chains.
                if let Some(src) = find_tainted_operand(operand, source, params, depth + 1) {
                    return Some(src);
                }
            }
            _ => {}
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_go(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_go::LANGUAGE.into())
            .expect("Go grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Go source must parse")
    }

    fn parse_ruby(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .expect("Ruby grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Ruby source must parse")
    }

    fn parse_php(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_php::LANGUAGE_PHP.into())
            .expect("PHP grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("PHP source must parse")
    }

    /// True positive: named parameter directly concatenated into db.Query.
    #[test]
    fn taint_confirmed_param_in_sql_concat() {
        let src = r#"package main
func GetUser(db *sql.DB, userID string) {
    db.Query("SELECT * FROM users WHERE id = " + userID)
}
"#;
        let tree = parse_go(src);
        let flows = track_taint_go_sqli(src.as_bytes(), tree.root_node());
        assert!(
            !flows.is_empty(),
            "taint flow must be confirmed for parameter in SQL concat"
        );
        assert_eq!(flows[0].taint_source, "userID");
    }

    /// True negative: both operands are string literals — no taint.
    #[test]
    fn taint_not_confirmed_literal_concat() {
        let src = r#"package main
func GetUser(db *sql.DB) {
    db.Query("SELECT * FROM users" + " WHERE active = 1")
}
"#;
        let tree = parse_go(src);
        let flows = track_taint_go_sqli(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "literal-only concat must not emit taint flow"
        );
    }

    /// True negative: local variable (not a parameter) — no taint.
    #[test]
    fn taint_not_confirmed_local_variable() {
        let src = r#"package main
func GetUser(db *sql.DB) {
    status := "active"
    db.Query("SELECT * FROM users WHERE status = " + status)
}
"#;
        let tree = parse_go(src);
        let flows = track_taint_go_sqli(src.as_bytes(), tree.root_node());
        assert!(flows.is_empty(), "local variable must not emit taint flow");
    }

    /// True positive: nested concat chain with parameter deeper in the tree.
    #[test]
    fn taint_confirmed_nested_concat_chain() {
        let src = r#"package main
func Search(db *sql.DB, table string, filter string) {
    db.Exec("SELECT * FROM " + table + " WHERE " + filter)
}
"#;
        let tree = parse_go(src);
        let flows = track_taint_go_sqli(src.as_bytes(), tree.root_node());
        assert!(
            !flows.is_empty(),
            "nested concat chain with parameter must confirm taint"
        );
    }

    /// True negative: no functions — no parameters to collect.
    #[test]
    fn taint_empty_when_no_functions() {
        let src = r#"package main
var q = "SELECT 1"
"#;
        let tree = parse_go(src);
        let flows = track_taint_go_sqli(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "no functions means no parameters and no taint flows"
        );
    }

    #[test]
    fn ruby_taint_confirmed_for_where_interpolation() {
        let src = r#"def fetch_user(user_id)
  User.where("id = #{user_id}")
end
"#;
        let tree = parse_ruby(src);
        let params = collect_ruby_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_ruby_sql_sinks(tree.root_node(), src.as_bytes(), &params);
        assert_eq!(params, vec!["user_id".to_string()]);
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].taint_source, "user_id");
    }

    #[test]
    fn ruby_taint_not_confirmed_for_literal_where() {
        let src = r#"def fetch_user
  User.where("active = true")
end
"#;
        let tree = parse_ruby(src);
        let params = collect_ruby_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_ruby_sql_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(flows.is_empty());
    }

    #[test]
    fn php_taint_confirmed_for_mysqli_query_concat() {
        let src = r#"<?php
function fetch_user($conn, $user) {
    mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $user . "'");
}
"#;
        let tree = parse_php(src);
        let params = collect_php_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_php_sql_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(params.iter().any(|param| param == "user"));
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].taint_source, "user");
    }

    #[test]
    fn php_taint_not_confirmed_for_literal_query() {
        let src = r#"<?php
function fetch_user($conn) {
    mysqli_query($conn, "SELECT * FROM users");
}
"#;
        let tree = parse_php(src);
        let params = collect_php_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_php_sql_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(flows.is_empty());
    }
}
