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

use common::taint::{TaintExportRecord, TaintKind, TaintedParam};

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

/// Collect Kotlin function parameter names from the parsed AST.
///
/// Extracts `simple_identifier` nodes from `function_value_parameters` lists.
pub fn collect_kotlin_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_kotlin_parameter_names(root, source, &mut params, 0);
    params
}

/// Track Kotlin OS-injection taint flows from parameters into dangerous sinks.
///
/// Sinks: `Runtime.getRuntime().exec()`, `ProcessBuilder(...)`, raw JDBC
/// `executeQuery`/`executeUpdate` with string concatenation.
pub fn find_tainted_kotlin_sinks(
    root: Node<'_>,
    source: &[u8],
    params: &[String],
) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    find_kotlin_os_sinks(root, source, params, &mut flows, 0);
    flows
}

/// Collect C/C++ function parameter names from the parsed AST.
///
/// Extracts `identifier` nodes from `pointer_declarator` / direct
/// `declarator` children of `parameter_declaration` nodes.
pub fn collect_cpp_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_cpp_parameter_names(root, source, &mut params, 0);
    params
}

/// Track C/C++ OS-injection taint flows from parameters into dangerous sinks.
///
/// Sinks: `system()`, `popen()`, `execl()`, `execle()`, `execlp()`,
/// `execv()`, `execve()`, `execvp()` — any call whose first argument is a
/// direct parameter identifier.
pub fn find_tainted_cpp_sinks(root: Node<'_>, source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    find_cpp_os_sinks(root, source, params, &mut flows, 0);
    flows
}

/// Collect Rust public function parameter names from the parsed AST.
///
/// Extracts `identifier` nodes from the `pattern` field of `parameter` nodes
/// within `function_item` definitions that carry a `pub` visibility keyword.
pub fn collect_rust_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_rust_parameter_names(root, source, &mut params, 0);
    params
}

/// Track Rust command-injection taint flows from parameters into dangerous sinks.
///
/// Sinks: `Command::new(param)`, `process::Command::new(param)`,
/// `libc::system(param)` — OS-command injection via `std::process` or libc FFI.
/// Also flags when a tainted param flows into an `unsafe {}` block that
/// invokes a known dangerous function.
pub fn find_tainted_rust_sinks(root: Node<'_>, source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    find_rust_os_sinks(root, source, params, &mut flows, 0);
    flows
}

/// Collect Swift function parameter names from the parsed AST.
pub fn collect_swift_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_swift_parameter_names(root, source, &mut params, 0);
    if params.is_empty() {
        params = collect_signature_params_from_source(source, "func");
    }
    params
}

/// Track Swift command-execution taint into `NSTask`, `Process`, and `launch()`.
pub fn track_taint_swift(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_swift_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    let mut flows = Vec::new();
    find_swift_exec_sinks(root, source, &params, &mut flows, 0);
    if flows.is_empty() {
        flows = find_textual_taint_flows(
            source,
            &params,
            &["Foundation.Process", "Process", "NSTask", "launch"],
        );
    }
    flows
}

/// Collect Scala function parameter names from the parsed AST.
pub fn collect_scala_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_scala_parameter_names(root, source, &mut params, 0);
    if params.is_empty() {
        params = collect_signature_params_from_source(source, "def");
    }
    params
}

/// Track Scala command-execution taint into `Runtime.exec` and `sys.process.Process`.
pub fn track_taint_scala(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_scala_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    let mut flows = Vec::new();
    find_scala_exec_sinks(root, source, &params, &mut flows, 0);
    if flows.is_empty() {
        flows = find_textual_taint_flows(
            source,
            &params,
            &["Runtime.getRuntime().exec", "sys.process.Process"],
        );
    }
    flows
}

/// Build cross-file taint export records for supported languages.
///
/// The producer side intentionally operates only on exported / public
/// boundaries so the catalog remains narrow: module-level Python functions,
/// exported JS/TS functions, public Java/C# methods, and exported Go symbols.
pub fn export_cross_file_records(
    lang: &str,
    file_path: &str,
    source: &[u8],
    root: Node<'_>,
) -> Vec<TaintExportRecord> {
    match lang {
        "py" => collect_python_exports(root, source, file_path),
        "js" | "jsx" => collect_javascript_exports(root, source, file_path),
        "ts" | "tsx" => collect_javascript_exports(root, source, file_path),
        "java" => collect_java_exports(root, source, file_path),
        "go" => collect_go_exports(root, source, file_path),
        "cs" => collect_csharp_exports(root, source, file_path),
        "cpp" | "cxx" | "cc" | "c" | "h" | "hpp" => collect_cpp_exports(root, source, file_path),
        "rs" => collect_rust_exports(root, source, file_path),
        "kt" | "kts" => collect_kotlin_exports(root, source, file_path),
        "swift" => collect_swift_exports(root, source, file_path),
        "scala" => collect_scala_exports(root, source, file_path),
        "sh" | "bash" | "cmd" | "zsh" => collect_bash_exports(root, source, file_path),
        "nix" => collect_nix_exports(root, source, file_path),
        "tf" | "hcl" => collect_hcl_exports(root, source, file_path),
        "lua" => collect_lua_exports(root, source, file_path),
        "gd" => collect_gdscript_exports(root, source, file_path),
        "zig" => collect_zig_exports(root, source, file_path),
        "m" | "mm" => collect_objc_exports(root, source, file_path),
        "glsl" | "vert" | "frag" => collect_glsl_exports(root, source, file_path),
        _ => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Parameter collection
// ---------------------------------------------------------------------------

/// C/C++ libc/POSIX function names that accept an OS command as first arg.
const CPP_DANGEROUS_CALLS: &[&str] = &[
    "system",
    "popen",
    "execl",
    "execle",
    "execlp",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "ShellExecute",
    "ShellExecuteA",
    "ShellExecuteW",
];

/// Rust method names in `std::process` / `libc` that accept a command string.
const RUST_DANGEROUS_CALLS: &[&str] = &["system", "exec", "spawn"];

/// Kotlin method / constructor names that trigger OS command execution.
const KOTLIN_DANGEROUS_CALLS: &[&str] = &[
    "exec",
    "ProcessBuilder",
    "executeQuery",
    "executeUpdate",
    "execute",
    "createStatement",
    "prepareStatement",
];
const SWIFT_DANGEROUS_CALLS: &[&str] = &["NSTask", "Process", "launch"];
const SCALA_DANGEROUS_CALLS: &[&str] = &["exec", "Process"];

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

fn collect_python_exports(
    root: Node<'_>,
    source: &[u8],
    file_path: &str,
) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_python_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_python_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "function_definition" && is_python_export_boundary(node, source) {
        if let Some(record) = build_record_from_function_like(
            node,
            source,
            file_path,
            "parameters",
            "body",
            "name",
            collect_param_names_python,
            find_tainted_call_params_python,
        ) {
            records.push(record);
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_python_exports(child, source, file_path, records, depth + 1);
    }
}

fn is_python_export_boundary(node: Node<'_>, source: &[u8]) -> bool {
    let name = node
        .child_by_field_name("name")
        .and_then(|n| n.utf8_text(source).ok())
        .unwrap_or("");
    if name.starts_with('_') {
        return false;
    }
    match node.parent().map(|parent| parent.kind()) {
        Some("module") => true,
        Some("block") => node
            .parent()
            .and_then(|block| block.parent())
            .map(|parent| parent.kind() == "class_definition")
            .unwrap_or(false),
        _ => false,
    }
}

fn collect_javascript_exports(
    root: Node<'_>,
    source: &[u8],
    file_path: &str,
) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_javascript_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_javascript_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "function_declaration" && is_javascript_export_boundary(node) {
        if let Some(record) = build_record_from_function_like(
            node,
            source,
            file_path,
            "parameters",
            "body",
            "name",
            collect_param_names_generic_identifiers,
            find_tainted_call_params_js,
        ) {
            records.push(record);
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_javascript_exports(child, source, file_path, records, depth + 1);
    }
}

fn is_javascript_export_boundary(node: Node<'_>) -> bool {
    matches!(
        node.parent().map(|parent| parent.kind()),
        Some("export_statement") | Some("export_declaration")
    )
}

fn collect_java_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_java_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_java_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "method_declaration" && has_public_modifier(node, source) {
        if let Some(record) = build_record_from_function_like(
            node,
            source,
            file_path,
            "parameters",
            "body",
            "name",
            collect_param_names_java,
            find_tainted_call_params_java,
        ) {
            records.push(record);
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_java_exports(child, source, file_path, records, depth + 1);
    }
}

fn collect_go_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_go_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_go_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if matches!(node.kind(), "function_declaration" | "method_declaration")
        && is_go_export_boundary(node, source)
    {
        if let Some(record) = build_record_from_function_like(
            node,
            source,
            file_path,
            "parameters",
            "body",
            "name",
            collect_param_names_go,
            find_tainted_call_params_go,
        ) {
            records.push(record);
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_go_exports(child, source, file_path, records, depth + 1);
    }
}

fn is_go_export_boundary(node: Node<'_>, source: &[u8]) -> bool {
    node.child_by_field_name("name")
        .and_then(|n| n.utf8_text(source).ok())
        .and_then(|name| name.chars().next())
        .map(|first| first.is_ascii_uppercase())
        .unwrap_or(false)
}

fn collect_csharp_exports(
    root: Node<'_>,
    source: &[u8],
    file_path: &str,
) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_csharp_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_csharp_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "method_declaration" && has_public_modifier(node, source) {
        if let Some(record) = build_record_from_function_like(
            node,
            source,
            file_path,
            "parameters",
            "body",
            "name",
            collect_param_names_csharp,
            find_tainted_call_params_csharp,
        ) {
            records.push(record);
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_csharp_exports(child, source, file_path, records, depth + 1);
    }
}

#[allow(clippy::too_many_arguments)]
fn build_record_from_function_like(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    params_field: &str,
    body_field: &str,
    name_field: &str,
    param_collector: fn(Node<'_>, &[u8]) -> Vec<String>,
    taint_finder: fn(Node<'_>, &[u8], &[String]) -> Vec<String>,
) -> Option<TaintExportRecord> {
    let symbol_name = node
        .child_by_field_name(name_field)
        .and_then(|n| n.utf8_text(source).ok())
        .unwrap_or("")
        .to_string();
    if symbol_name.is_empty() {
        return None;
    }

    let params_node = node
        .child_by_field_name(params_field)
        .or_else(|| find_named_child_by_kind_fragment(node, "parameter"))?;
    let body_node = node
        .child_by_field_name(body_field)
        .or_else(|| find_named_child_by_kind_fragment(node, "block"))
        .or_else(|| find_named_child_by_kind_fragment(node, "body"))?;
    let params = param_collector(params_node, source);
    if params.is_empty() {
        return None;
    }
    let tainted_params = taint_finder(body_node, source, &params);
    if tainted_params.is_empty() {
        return None;
    }

    let tainted_params = tainted_params
        .into_iter()
        .filter_map(|name| {
            params
                .iter()
                .position(|param| param == &name)
                .map(|index| TaintedParam {
                    param_index: index as u32,
                    param_name: name,
                    kind: TaintKind::UserInput,
                })
        })
        .collect::<Vec<_>>();

    if tainted_params.is_empty() {
        return None;
    }

    Some(TaintExportRecord {
        symbol_name,
        file_path: file_path.replace('\\', "/"),
        tainted_params,
        sink_kinds: vec![TaintKind::Unknown],
        propagates_to_return: function_returns_tainted_param(body_node, source, &params),
    })
}

fn has_public_modifier(node: Node<'_>, source: &[u8]) -> bool {
    node.child_by_field_name("modifiers")
        .and_then(|n| n.utf8_text(source).ok())
        .or_else(|| {
            let mut cur = node.walk();
            let text = node
                .named_children(&mut cur)
                .find(|child| child.kind().contains("modifier"))
                .and_then(|child| child.utf8_text(source).ok());
            text
        })
        .map(|text| text.split_whitespace().any(|token| token == "public"))
        .unwrap_or(false)
}

fn function_returns_tainted_param(node: Node<'_>, source: &[u8], params: &[String]) -> bool {
    let mut found = false;
    walk_return_nodes(node, source, params, &mut found, 0);
    found
}

fn walk_return_nodes(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    found: &mut bool,
    depth: u32,
) {
    if *found || depth > 100 {
        return;
    }
    if node.kind().contains("return") && subtree_contains_any_identifier(node, source, params) {
        *found = true;
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_return_nodes(child, source, params, found, depth + 1);
    }
}

fn collect_param_names_python(params_node: Node<'_>, source: &[u8]) -> Vec<String> {
    collect_param_names_by_kinds(params_node, source, &["identifier"], &["self", "cls"], 0)
}

fn collect_param_names_generic_identifiers(params_node: Node<'_>, source: &[u8]) -> Vec<String> {
    collect_param_names_by_kinds(params_node, source, &["identifier"], &[], 0)
}

fn collect_param_names_java(params_node: Node<'_>, source: &[u8]) -> Vec<String> {
    collect_param_names_by_kinds(params_node, source, &["identifier"], &[], 0)
}

fn collect_param_names_go(params_node: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_go_params(params_node, source, &mut params, 0);
    params
}

fn collect_param_names_csharp(params_node: Node<'_>, source: &[u8]) -> Vec<String> {
    collect_param_names_by_kinds(params_node, source, &["identifier"], &["this"], 0)
}

fn collect_param_names_by_kinds(
    node: Node<'_>,
    source: &[u8],
    identifier_kinds: &[&str],
    ignored_names: &[&str],
    depth: u32,
) -> Vec<String> {
    let mut params = Vec::new();
    collect_param_names_into(
        node,
        source,
        identifier_kinds,
        ignored_names,
        &mut params,
        depth,
    );
    params
}

fn collect_signature_params_from_source(source: &[u8], function_keyword: &str) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let Some(keyword_idx) = text.find(function_keyword) else {
        return Vec::new();
    };
    let signature = &text[keyword_idx..];
    let Some(paren_start) = signature.find('(') else {
        return Vec::new();
    };
    let Some(paren_end) = signature[paren_start + 1..].find(')') else {
        return Vec::new();
    };
    signature[paren_start + 1..paren_start + 1 + paren_end]
        .split(',')
        .filter_map(|segment| {
            let binding = segment.split(':').next()?.trim();
            binding
                .split_whitespace()
                .last()
                .filter(|name| !name.is_empty() && *name != "_" && *name != "self")
                .map(str::to_string)
        })
        .collect()
}

fn find_textual_taint_flows(
    source: &[u8],
    params: &[String],
    sink_prefixes: &[&str],
) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let normalized: String = text.chars().filter(|ch| !ch.is_whitespace()).collect();
    let mut flows = Vec::new();
    for param in params {
        for prefix in sink_prefixes {
            let needle = format!("{prefix}({param}");
            if normalized.contains(&needle) {
                flows.push(TaintFlow {
                    taint_source: param.clone(),
                    sink_byte: 0,
                    sink_end_byte: needle.len(),
                });
                break;
            }
        }
    }
    flows
}

fn collect_param_names_into(
    node: Node<'_>,
    source: &[u8],
    identifier_kinds: &[&str],
    ignored_names: &[&str],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if identifier_kinds.contains(&node.kind()) {
        if let Ok(name) = node.utf8_text(source) {
            if !name.is_empty() && !ignored_names.iter().any(|ignored| ignored == &name) {
                params.push(name.to_string());
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_param_names_into(
            child,
            source,
            identifier_kinds,
            ignored_names,
            params,
            depth + 1,
        );
    }
}

fn find_tainted_call_params_python(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
) -> Vec<String> {
    find_tainted_call_params(node, source, params, &["call"], &["arguments"], 0)
}

fn find_tainted_call_params_js(node: Node<'_>, source: &[u8], params: &[String]) -> Vec<String> {
    find_tainted_call_params(
        node,
        source,
        params,
        &["call_expression"],
        &["arguments"],
        0,
    )
}

fn find_tainted_call_params_java(node: Node<'_>, source: &[u8], params: &[String]) -> Vec<String> {
    find_tainted_call_params(
        node,
        source,
        params,
        &["method_invocation"],
        &["arguments"],
        0,
    )
}

fn find_tainted_call_params_go(node: Node<'_>, source: &[u8], params: &[String]) -> Vec<String> {
    find_tainted_call_params(
        node,
        source,
        params,
        &["call_expression"],
        &["arguments"],
        0,
    )
}

fn find_tainted_call_params_csharp(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
) -> Vec<String> {
    find_tainted_call_params(
        node,
        source,
        params,
        &["invocation_expression"],
        &["argument_list", "arguments"],
        0,
    )
}

fn find_tainted_call_params(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    call_kinds: &[&str],
    arg_fields: &[&str],
    depth: u32,
) -> Vec<String> {
    let mut found = Vec::new();
    collect_tainted_call_params(
        node, source, params, call_kinds, arg_fields, &mut found, depth,
    );
    found.sort();
    found.dedup();
    found
}

fn collect_tainted_call_params(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    call_kinds: &[&str],
    arg_fields: &[&str],
    found: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if call_kinds.contains(&node.kind()) {
        let args_node = arg_fields
            .iter()
            .find_map(|field| node.child_by_field_name(field))
            .or_else(|| {
                let mut cur = node.walk();
                let found = node
                    .named_children(&mut cur)
                    .find(|child| child.kind().contains("argument"));
                found
            });
        if let Some(args_node) = args_node {
            for param in params {
                if subtree_contains_identifier(args_node, source, param) {
                    found.push(param.clone());
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_tainted_call_params(
            child,
            source,
            params,
            call_kinds,
            arg_fields,
            found,
            depth + 1,
        );
    }
}

fn subtree_contains_any_identifier(node: Node<'_>, source: &[u8], params: &[String]) -> bool {
    params
        .iter()
        .any(|param| subtree_contains_identifier(node, source, param))
}

fn subtree_contains_identifier(node: Node<'_>, source: &[u8], target: &str) -> bool {
    if matches!(node.kind(), "identifier" | "simple_identifier") {
        return node
            .utf8_text(source)
            .map(|text| text == target)
            .unwrap_or(false);
    }
    let mut cur = node.walk();
    let found = node
        .children(&mut cur)
        .any(|child| subtree_contains_identifier(child, source, target));
    found
}

// ---------------------------------------------------------------------------
// C / C++ implementation
// ---------------------------------------------------------------------------

/// Extract the parameter name identifier from a `parameter_declaration` node.
///
/// In tree-sitter-cpp the declarator tree looks like:
///   `parameter_declaration → pointer_declarator → identifier`
/// or simply:
///   `parameter_declaration → identifier` (for value parameters)
fn extract_cpp_param_name(node: Node<'_>, source: &[u8]) -> Option<String> {
    // Depth-limited DFS: stop at the first identifier inside any
    // declarator-family node, skipping type-specifier subtrees.
    fn find_ident_in_declarator(node: Node<'_>, source: &[u8], depth: u32) -> Option<String> {
        if depth > 8 {
            return None;
        }
        let kind = node.kind();
        // Skip type-specifier nodes so we don't collect the type name.
        if matches!(
            kind,
            "type_identifier"
                | "primitive_type"
                | "qualified_identifier"
                | "template_type"
                | "scoped_type_identifier"
        ) {
            return None;
        }
        if kind == "identifier" {
            return node.utf8_text(source).ok().map(str::to_string);
        }
        let mut cur = node.walk();
        for child in node.named_children(&mut cur) {
            if let Some(name) = find_ident_in_declarator(child, source, depth + 1) {
                return Some(name);
            }
        }
        None
    }
    find_ident_in_declarator(node, source, 0)
}

fn collect_cpp_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "parameter_declaration" {
        if let Some(name) = extract_cpp_param_name(node, source) {
            if !name.is_empty() {
                params.push(name.to_string());
            }
        }
        // Do not recurse into parameter_declaration — the name extraction
        // already walks the subtree.
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_cpp_parameter_names(child, source, params, depth + 1);
    }
}

fn find_cpp_os_sinks(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    flows: &mut Vec<TaintFlow>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // Match `call_expression` where the callee is a known dangerous function.
    if node.kind() == "call_expression" {
        let func_name = node
            .child_by_field_name("function")
            .and_then(|f| {
                if f.kind() == "identifier" {
                    f.utf8_text(source).ok()
                } else {
                    // Handle scoped calls like `std::system` — take the last segment.
                    f.child_by_field_name("name")
                        .and_then(|n| n.utf8_text(source).ok())
                }
            })
            .unwrap_or("");
        if CPP_DANGEROUS_CALLS.contains(&func_name) {
            // Check if the first argument is (or contains) a tainted param identifier.
            if let Some(args) = node.child_by_field_name("arguments") {
                if let Some(first_arg) = args.named_children(&mut args.walk()).next() {
                    for param in params {
                        if subtree_contains_identifier(first_arg, source, param) {
                            flows.push(TaintFlow {
                                taint_source: param.clone(),
                                sink_byte: node.start_byte(),
                                sink_end_byte: node.end_byte(),
                            });
                            break; // one flow per call site
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_cpp_os_sinks(child, source, params, flows, depth + 1);
    }
}

fn collect_cpp_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_cpp_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_cpp_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // Collect definitions that are NOT static (i.e., potentially externally visible).
    if node.kind() == "function_definition" && !has_static_specifier(node, source) {
        let symbol_name = node
            .child_by_field_name("declarator")
            .and_then(|d| find_function_identifier(d, source))
            .unwrap_or_default();
        if !symbol_name.is_empty() {
            let params = collect_cpp_params(node, source);
            if !params.is_empty() {
                let body_opt = node.child_by_field_name("body");
                if let Some(body) = body_opt {
                    let tainted: Vec<String> = params
                        .iter()
                        .filter(|p| subtree_contains_identifier(body, source, p))
                        .cloned()
                        .collect();
                    let tainted_params: Vec<TaintedParam> = tainted
                        .into_iter()
                        .filter_map(|name| {
                            params
                                .iter()
                                .position(|p| p == &name)
                                .map(|index| TaintedParam {
                                    param_index: index as u32,
                                    param_name: name,
                                    kind: TaintKind::UserInput,
                                })
                        })
                        .collect();
                    if !tainted_params.is_empty() {
                        records.push(TaintExportRecord {
                            symbol_name,
                            file_path: file_path.replace('\\', "/"),
                            tainted_params,
                            sink_kinds: vec![TaintKind::Unknown],
                            propagates_to_return: false,
                        });
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_cpp_exports(child, source, file_path, records, depth + 1);
    }
}

/// Return `true` when the `function_definition` carries a `static` storage
/// specifier, meaning it has internal linkage and is NOT a public boundary.
fn has_static_specifier(node: Node<'_>, source: &[u8]) -> bool {
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        if child.kind() == "storage_class_specifier"
            && child
                .utf8_text(source)
                .map(|t| t == "static")
                .unwrap_or(false)
        {
            return true;
        }
    }
    false
}

/// Walk a C/C++ declarator subtree to find the function name identifier.
fn find_function_identifier(node: Node<'_>, source: &[u8]) -> Option<String> {
    // function_declarator → declarator (identifier)
    match node.kind() {
        "identifier" => node.utf8_text(source).ok().map(str::to_string),
        "function_declarator" => node
            .child_by_field_name("declarator")
            .and_then(|d| find_function_identifier(d, source)),
        "pointer_declarator" | "reference_declarator" => node
            .child_by_field_name("declarator")
            .and_then(|d| find_function_identifier(d, source)),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Rust implementation
// ---------------------------------------------------------------------------

fn collect_rust_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "parameter" {
        // The binding pattern is the `pattern` field — typically an `identifier`
        // or a `mut_pattern { (identifier) }`.
        if let Some(pattern) = node.child_by_field_name("pattern") {
            collect_rust_ident_from_pattern(pattern, source, params);
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_rust_parameter_names(child, source, params, depth + 1);
    }
}

fn collect_rust_ident_from_pattern(node: Node<'_>, source: &[u8], params: &mut Vec<String>) {
    match node.kind() {
        "identifier" => {
            if let Ok(name) = node.utf8_text(source) {
                if !name.is_empty() && name != "_" && name != "self" {
                    params.push(name.to_string());
                }
            }
        }
        "mut_pattern" | "ref_pattern" => {
            // mut_pattern wraps an inner identifier
            let mut cur = node.walk();
            for child in node.named_children(&mut cur) {
                collect_rust_ident_from_pattern(child, source, params);
            }
        }
        _ => {}
    }
}

fn find_rust_os_sinks(
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
        let func_text = node
            .child_by_field_name("function")
            .and_then(|f| f.utf8_text(source).ok())
            .unwrap_or("");
        // Match `Command::new(...)`, `process::Command::new(...)`, `libc::system(...)`, etc.
        let is_dangerous = RUST_DANGEROUS_CALLS
            .iter()
            .any(|sink| func_text.ends_with(&format!("::{sink}")) || func_text == *sink)
            || (func_text.ends_with("::new") && func_text.contains("Command"));
        if is_dangerous {
            if let Some(args) = node.child_by_field_name("arguments") {
                if let Some(first_arg) = args.named_children(&mut args.walk()).next() {
                    for param in params {
                        if subtree_contains_identifier(first_arg, source, param) {
                            flows.push(TaintFlow {
                                taint_source: param.clone(),
                                sink_byte: node.start_byte(),
                                sink_end_byte: node.end_byte(),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_rust_os_sinks(child, source, params, flows, depth + 1);
    }
}

fn collect_rust_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_rust_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_rust_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "function_item" && is_rust_pub(node, source) {
        if let Some(record) = build_record_from_function_like(
            node,
            source,
            file_path,
            "parameters",
            "body",
            "name",
            collect_param_names_rust,
            find_tainted_call_params_rust,
        ) {
            records.push(record);
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_rust_exports(child, source, file_path, records, depth + 1);
    }
}

fn is_rust_pub(node: Node<'_>, source: &[u8]) -> bool {
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        if child.kind() == "visibility_modifier" {
            return child
                .utf8_text(source)
                .map(|t| t.starts_with("pub"))
                .unwrap_or(false);
        }
    }
    false
}

fn collect_param_names_rust(params_node: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_rust_parameter_names(params_node, source, &mut params, 0);
    params
}

fn find_tainted_call_params_rust(node: Node<'_>, source: &[u8], params: &[String]) -> Vec<String> {
    find_tainted_call_params(
        node,
        source,
        params,
        &["call_expression"],
        &["arguments"],
        0,
    )
}

// ---------------------------------------------------------------------------
// Kotlin implementation
// ---------------------------------------------------------------------------

fn collect_kotlin_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // function_value_parameters → parameter → identifier (name) : type
    // The tree-sitter-kotlin-ng grammar wraps params in `parameter` nodes;
    // the binding name is the FIRST `identifier` named child.
    if node.kind() == "parameter" {
        let mut cur = node.walk();
        let x = node
            .named_children(&mut cur)
            .find(|c| c.kind() == "identifier" || c.kind() == "simple_identifier")
            .and_then(|c| c.utf8_text(source).ok())
            .map(str::to_string);
        if let Some(n) = x {
            if !n.is_empty() {
                params.push(n);
            }
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_kotlin_parameter_names(child, source, params, depth + 1);
    }
}

fn find_kotlin_os_sinks(
    node: Node<'_>,
    source: &[u8],
    params: &[String],
    flows: &mut Vec<TaintFlow>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // call_expression in Kotlin: navigation_expression or simple call
    if matches!(node.kind(), "call_expression" | "function_call") {
        // Resolve the callee node without closures to avoid `cur` lifetime issues.
        let callee_node = node
            .child_by_field_name("calleeExpression")
            .or_else(|| node.child_by_field_name("function"))
            .or_else(|| {
                let mut cur = node.walk();
                let found = node.named_children(&mut cur).find(|c| {
                    c.kind() == "navigation_expression" || c.kind() == "simple_identifier"
                });
                // `found` borrows `cur` — copy the result before `cur` drops.
                found
            });
        let callee_text = callee_node
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("");
        let is_dangerous = KOTLIN_DANGEROUS_CALLS
            .iter()
            .any(|sink| callee_text.ends_with(sink) || callee_text == *sink);
        if is_dangerous {
            let args_opt = {
                let by_field = node.child_by_field_name("valueArguments");
                if by_field.is_some() {
                    by_field
                } else {
                    let mut cur = node.walk();
                    let found = node
                        .named_children(&mut cur)
                        .find(|c| c.kind() == "value_arguments");
                    found
                }
            };
            if let Some(args) = args_opt {
                if let Some(first_arg) = args.named_children(&mut args.walk()).next() {
                    for param in params {
                        if subtree_contains_identifier(first_arg, source, param)
                            || first_arg
                                .utf8_text(source)
                                .map(|t| t.contains(param.as_str()))
                                .unwrap_or(false)
                        {
                            flows.push(TaintFlow {
                                taint_source: param.clone(),
                                sink_byte: node.start_byte(),
                                sink_end_byte: node.end_byte(),
                            });
                            break;
                        }
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_kotlin_os_sinks(child, source, params, flows, depth + 1);
    }
}

fn collect_kotlin_exports(
    root: Node<'_>,
    source: &[u8],
    file_path: &str,
) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_kotlin_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_kotlin_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // Kotlin default visibility is public — collect all function declarations.
    if matches!(
        node.kind(),
        "function_declaration" | "secondary_constructor"
    ) {
        let symbol_name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .unwrap_or("")
            .to_string();
        if !symbol_name.is_empty() {
            let params = collect_kotlin_params(node, source);
            if !params.is_empty() {
                let body_opt = node
                    .child_by_field_name("body")
                    .or_else(|| find_named_child_by_kind_fragment(node, "block"));
                if let Some(body) = body_opt {
                    let tainted: Vec<String> = params
                        .iter()
                        .filter(|p| subtree_contains_identifier(body, source, p))
                        .cloned()
                        .collect();
                    let tainted_params: Vec<TaintedParam> = tainted
                        .into_iter()
                        .filter_map(|name| {
                            params
                                .iter()
                                .position(|p| p == &name)
                                .map(|index| TaintedParam {
                                    param_index: index as u32,
                                    param_name: name,
                                    kind: TaintKind::UserInput,
                                })
                        })
                        .collect();
                    if !tainted_params.is_empty() {
                        records.push(TaintExportRecord {
                            symbol_name,
                            file_path: file_path.replace('\\', "/"),
                            tainted_params,
                            sink_kinds: vec![TaintKind::Unknown],
                            propagates_to_return: function_returns_tainted_param(
                                body, source, &params,
                            ),
                        });
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_kotlin_exports(child, source, file_path, records, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Swift implementation
// ---------------------------------------------------------------------------

fn collect_swift_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "parameter" {
        let name = node
            .child_by_field_name("name")
            .or_else(|| find_first_named_child_by_kinds(node, &["simple_identifier", "identifier"]))
            .and_then(|child| child.utf8_text(source).ok())
            .map(str::to_string);
        if let Some(name) = name {
            if !name.is_empty() {
                params.push(name);
            }
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_swift_parameter_names(child, source, params, depth + 1);
    }
}

fn find_first_named_child_by_kinds<'a>(node: Node<'a>, kinds: &[&str]) -> Option<Node<'a>> {
    let mut cur = node.walk();
    let found = node
        .named_children(&mut cur)
        .find(|child| kinds.contains(&child.kind()));
    found
}

fn swift_callee_name(node: Node<'_>, source: &[u8]) -> String {
    match node.kind() {
        "simple_identifier" | "identifier" => node.utf8_text(source).unwrap_or("").to_string(),
        "navigation_expression" => {
            let count = node.named_child_count();
            node.named_child(count.saturating_sub(1) as u32)
                .and_then(|child| child.utf8_text(source).ok())
                .unwrap_or("")
                .to_string()
        }
        _ => String::new(),
    }
}

fn swift_call_contains_param(node: Node<'_>, source: &[u8], params: &[String]) -> Option<String> {
    params
        .iter()
        .find(|param| subtree_contains_identifier(node, source, param))
        .cloned()
}

fn find_swift_exec_sinks(
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
        let callee = node
            .named_child(0)
            .map(|child| swift_callee_name(child, source))
            .unwrap_or_default();
        let dangerous = SWIFT_DANGEROUS_CALLS.iter().any(|sink| callee == *sink)
            || (callee == "launch"
                && node
                    .utf8_text(source)
                    .map(|text| text.contains("Process") || text.contains("NSTask"))
                    .unwrap_or(false))
            || (callee == "Process"
                && node
                    .utf8_text(source)
                    .map(|text| text.contains("Foundation.Process"))
                    .unwrap_or(false));
        if dangerous {
            if let Some(param) = swift_call_contains_param(node, source, params) {
                flows.push(TaintFlow {
                    taint_source: param,
                    sink_byte: node.start_byte(),
                    sink_end_byte: node.end_byte(),
                });
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_swift_exec_sinks(child, source, params, flows, depth + 1);
    }
}

fn collect_swift_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_swift_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_swift_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "function_declaration" {
        let symbol_name = node
            .child_by_field_name("name")
            .or_else(|| find_first_named_child_by_kinds(node, &["simple_identifier", "identifier"]))
            .and_then(|child| child.utf8_text(source).ok())
            .unwrap_or("")
            .to_string();
        if !symbol_name.is_empty() {
            let params = collect_swift_params(node, source);
            let flows = track_taint_swift(source, node);
            let tainted_params: Vec<TaintedParam> = flows
                .into_iter()
                .filter_map(|flow| {
                    params
                        .iter()
                        .position(|param| param == &flow.taint_source)
                        .map(|index| TaintedParam {
                            param_index: index as u32,
                            param_name: flow.taint_source,
                            kind: TaintKind::UserInput,
                        })
                })
                .collect();
            if !tainted_params.is_empty() {
                records.push(TaintExportRecord {
                    symbol_name,
                    file_path: file_path.replace('\\', "/"),
                    tainted_params,
                    sink_kinds: vec![TaintKind::Unknown],
                    propagates_to_return: false,
                });
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_swift_exports(child, source, file_path, records, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Scala implementation
// ---------------------------------------------------------------------------

fn collect_scala_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "parameter" {
        let name = node
            .child_by_field_name("name")
            .or_else(|| find_first_named_child_by_kinds(node, &["identifier"]))
            .and_then(|child| child.utf8_text(source).ok())
            .map(str::to_string);
        if let Some(name) = name {
            if !name.is_empty() {
                params.push(name);
            }
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_scala_parameter_names(child, source, params, depth + 1);
    }
}

fn scala_callee_name(node: Node<'_>, source: &[u8]) -> String {
    match node.kind() {
        "identifier" => node.utf8_text(source).unwrap_or("").to_string(),
        "field_expression" | "selection_expression" => node
            .child_by_field_name("name")
            .and_then(|child| child.utf8_text(source).ok())
            .unwrap_or("")
            .to_string(),
        _ => String::new(),
    }
}

fn scala_call_is_dangerous(call: Node<'_>, callee: &str, source: &[u8]) -> bool {
    if callee == "Process" {
        return true;
    }
    callee == "exec"
        && call
            .utf8_text(source)
            .map(|text| text.contains("Runtime.getRuntime") || text.contains(".exec("))
            .unwrap_or(false)
}

fn find_scala_exec_sinks(
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
        let callee = node
            .named_child(0)
            .map(|child| scala_callee_name(child, source))
            .unwrap_or_default();
        let dangerous = SCALA_DANGEROUS_CALLS.iter().any(|sink| callee == *sink)
            && scala_call_is_dangerous(node, &callee, source);
        if dangerous {
            let args = node
                .child_by_field_name("arguments")
                .or_else(|| find_first_named_child_by_kinds(node, &["arguments"]));
            if let Some(args) = args {
                for param in params {
                    if subtree_contains_identifier(args, source, param) {
                        flows.push(TaintFlow {
                            taint_source: param.clone(),
                            sink_byte: node.start_byte(),
                            sink_end_byte: node.end_byte(),
                        });
                        break;
                    }
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        find_scala_exec_sinks(child, source, params, flows, depth + 1);
    }
}

fn collect_scala_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_scala_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_scala_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if matches!(node.kind(), "function_definition" | "function_declaration") {
        let symbol_name = node
            .child_by_field_name("name")
            .or_else(|| find_first_named_child_by_kinds(node, &["identifier"]))
            .and_then(|child| child.utf8_text(source).ok())
            .unwrap_or("")
            .to_string();
        if !symbol_name.is_empty() {
            let params = collect_scala_params(node, source);
            let flows = track_taint_scala(source, node);
            let tainted_params: Vec<TaintedParam> = flows
                .into_iter()
                .filter_map(|flow| {
                    params
                        .iter()
                        .position(|param| param == &flow.taint_source)
                        .map(|index| TaintedParam {
                            param_index: index as u32,
                            param_name: flow.taint_source,
                            kind: TaintKind::UserInput,
                        })
                })
                .collect();
            if !tainted_params.is_empty() {
                records.push(TaintExportRecord {
                    symbol_name,
                    file_path: file_path.replace('\\', "/"),
                    tainted_params,
                    sink_kinds: vec![TaintKind::Unknown],
                    propagates_to_return: false,
                });
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_scala_exports(child, source, file_path, records, depth + 1);
    }
}

fn find_named_child_by_kind_fragment<'a>(node: Node<'a>, fragment: &str) -> Option<Node<'a>> {
    let mut cur = node.walk();
    let found = node
        .named_children(&mut cur)
        .find(|child| child.kind().contains(fragment));
    found
}

// ---------------------------------------------------------------------------
// Bash implementation
// ---------------------------------------------------------------------------

/// Bash/shell builtins that execute arbitrary strings as shell commands.
const BASH_DANGEROUS_CALLS: &[&str] = &["eval", "exec"];

/// Positional parameter tokens that are always user-controlled in bash functions.
const BASH_TAINTED_POSITIONALS: &[&str] = &["$1", "$2", "$3", "$4", "$5", "$@", "$*"];

/// Track intra-file taint from bash positional parameters and local aliases to
/// `eval` / `exec` sinks.
pub fn track_taint_bash(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_bash_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    find_bash_dangerous_flows(source, &params)
}

/// Collect bash parameter tokens: positional ($1, $@, …) and local aliases
/// assigned from a positional (`local cmd="$1"`).
pub fn collect_bash_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let _ = root; // AST unused — bash uses textual parameter extraction
    let mut found: Vec<String> = Vec::new();
    for positional in BASH_TAINTED_POSITIONALS {
        if text.contains(positional) && !found.contains(&positional.to_string()) {
            found.push(positional.to_string());
        }
    }
    // Also collect named locals assigned from positional: `local varname="$1"`
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("local ") {
            if let Some((name, value)) = rest.split_once('=') {
                let name = name.trim().to_string();
                let has_positional = BASH_TAINTED_POSITIONALS.iter().any(|p| value.contains(p));
                if !name.is_empty() && has_positional && !found.contains(&name) {
                    found.push(name);
                }
            }
        }
    }
    found
}

fn find_bash_dangerous_flows(source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let is_dangerous_line = BASH_DANGEROUS_CALLS.iter().any(|sink| {
            trimmed.starts_with(&format!("{sink} ")) || trimmed.starts_with(&format!("{sink}\t"))
        });
        if !is_dangerous_line {
            continue;
        }
        for param in params {
            let matches = if param.starts_with('$') {
                // positional: $1, $@, etc. — look for exact token
                trimmed.contains(param.as_str())
            } else {
                // named local: look for $varname or ${varname}
                trimmed.contains(&format!("${param}")) || trimmed.contains(&format!("${{{param}}}"))
            };
            if matches {
                flows.push(TaintFlow {
                    taint_source: param.clone(),
                    sink_byte: 0,
                    sink_end_byte: 0,
                });
                break;
            }
        }
    }
    flows
}

fn collect_bash_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_bash_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_bash_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "function_definition" {
        let symbol_name = node
            .child_by_field_name("name")
            .or_else(|| find_first_named_child_by_kinds(node, &["word"]))
            .and_then(|child| child.utf8_text(source).ok())
            .unwrap_or("")
            .to_string();
        if !symbol_name.is_empty() {
            let params = collect_bash_params(node, source);
            let flows = track_taint_bash(source, node);
            let tainted_params: Vec<TaintedParam> = flows
                .into_iter()
                .enumerate()
                .map(|(index, flow)| TaintedParam {
                    param_index: index as u32,
                    param_name: flow.taint_source,
                    kind: TaintKind::UserInput,
                })
                .filter(|tp| params.contains(&tp.param_name))
                .collect();
            if !tainted_params.is_empty() {
                records.push(TaintExportRecord {
                    symbol_name,
                    file_path: file_path.replace('\\', "/"),
                    tainted_params,
                    sink_kinds: vec![TaintKind::Unknown],
                    propagates_to_return: false,
                });
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_bash_exports(child, source, file_path, records, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Nix implementation
// ---------------------------------------------------------------------------

/// Nix builtins that execute OS commands.
const NIX_DANGEROUS_CALLS: &[&str] = &["builtins.exec"];

/// Track intra-file taint from Nix function formals to `builtins.exec` sinks.
pub fn track_taint_nix(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_nix_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    find_nix_exec_flows(source, &params)
}

/// Collect Nix function parameter names from set-pattern formals `{ a, b }:` or
/// simple binding `arg:`.
pub fn collect_nix_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_nix_parameter_names(root, source, &mut params, 0);
    if params.is_empty() {
        // Textual fallback: parse `{ param1, param2 }:` header
        if let Ok(text) = std::str::from_utf8(source) {
            params = collect_nix_formals_from_text(text);
        }
    }
    params
}

fn collect_nix_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // Nix set-pattern formals: `formals` node contains `formal` children
    // Each `formal` has an `identifier` as first named child
    if node.kind() == "formals" {
        let mut cur = node.walk();
        for child in node.named_children(&mut cur) {
            if child.kind() == "formal" {
                let name = child
                    .named_child(0)
                    .and_then(|c| c.utf8_text(source).ok())
                    .map(str::to_string);
                if let Some(n) = name {
                    if !n.is_empty() && n != "..." && !params.contains(&n) {
                        params.push(n);
                    }
                }
            }
        }
        return;
    }
    // Simple identifier binding before `:` in a function node
    if node.kind() == "function_expression" {
        // The first child before the colon is the binding
        if let Some(first) = node.named_child(0) {
            if first.kind() == "identifier" {
                let name = first
                    .utf8_text(source)
                    .ok()
                    .map(str::to_string)
                    .unwrap_or_default();
                if !name.is_empty() && !params.contains(&name) {
                    params.push(name);
                }
            }
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_nix_parameter_names(child, source, params, depth + 1);
    }
}

fn collect_nix_formals_from_text(text: &str) -> Vec<String> {
    // Parse `{ param1, param2 ? default, ... }:` at file start
    let Some(open) = text.find('{') else {
        return Vec::new();
    };
    let Some(close) = text[open..].find('}') else {
        return Vec::new();
    };
    let formals_text = &text[open + 1..open + close];
    formals_text
        .split(',')
        .filter_map(|segment| {
            let name = segment
                .split('?') // strip default value
                .next()?
                .trim();
            if name.is_empty() || name == "..." {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
}

fn find_nix_exec_flows(source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    for line in text.lines() {
        let is_exec_line = NIX_DANGEROUS_CALLS.iter().any(|sink| line.contains(sink));
        if !is_exec_line {
            continue;
        }
        for param in params {
            // param appears as a standalone identifier in the exec argument list
            if line.contains(param.as_str()) {
                flows.push(TaintFlow {
                    taint_source: param.clone(),
                    sink_byte: 0,
                    sink_end_byte: 0,
                });
                break;
            }
        }
    }
    flows
}

fn collect_nix_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_nix_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_nix_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    if node.kind() == "function_expression" {
        // Derive a symbol name: use the attribute path if this function is an
        // attribute value (e.g., `myPkg = { cmd }: builtins.exec [ cmd ]`).
        let symbol_name = node
            .parent()
            .filter(|p| p.kind() == "binding")
            .and_then(|p| {
                p.child_by_field_name("attrpath")
                    .or_else(|| find_first_named_child_by_kinds(p, &["attrpath"]))
            })
            .and_then(|ap| ap.utf8_text(source).ok())
            .map(str::to_string)
            .unwrap_or_else(|| "nixExpr".to_string());

        let params = collect_nix_params(node, source);
        let flows = find_nix_exec_flows(source, &params);
        let tainted_params: Vec<TaintedParam> = flows
            .into_iter()
            .enumerate()
            .map(|(index, flow)| TaintedParam {
                param_index: index as u32,
                param_name: flow.taint_source,
                kind: TaintKind::UserInput,
            })
            .filter(|tp| params.contains(&tp.param_name))
            .collect();
        if !tainted_params.is_empty() {
            records.push(TaintExportRecord {
                symbol_name,
                file_path: file_path.replace('\\', "/"),
                tainted_params,
                sink_kinds: vec![TaintKind::Unknown],
                propagates_to_return: false,
            });
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_nix_exports(child, source, file_path, records, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// HCL / Terraform implementation
// ---------------------------------------------------------------------------

/// HCL block types and attribute names that indicate OS command execution.
/// Format: (block_type, provisioner_label, attribute_name)
const HCL_DANGEROUS_BLOCKS: &[(&str, &str)] =
    &[("provisioner", "local-exec"), ("data", "external")];

/// Track intra-file taint from Terraform/HCL variable interpolations to
/// `local-exec` and `external` data-source sinks.
pub fn track_taint_hcl(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let _ = root; // primary detection is textual for HCL template interpolations
    find_hcl_dangerous_flows(source)
}

fn find_hcl_dangerous_flows(source: &[u8]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    let mut in_dangerous_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        // Detect entry into a dangerous block
        for (block_type, label) in HCL_DANGEROUS_BLOCKS {
            if trimmed.starts_with(block_type) && trimmed.contains(label) {
                in_dangerous_block = true;
            }
        }
        // Reset on block close
        if trimmed == "}" {
            in_dangerous_block = false;
        }
        if !in_dangerous_block {
            continue;
        }
        // Look for template interpolation ${var.X} or ${local.X} in command/program attributes
        if trimmed.starts_with("command") || trimmed.starts_with("program") {
            flows.extend(extract_hcl_var_flows(trimmed));
        }
    }
    flows
}

fn extract_hcl_var_flows(line: &str) -> Vec<TaintFlow> {
    let mut flows = Vec::new();
    let mut remaining = line;
    while let Some(start) = remaining.find("${") {
        let after_brace = &remaining[start + 2..];
        let Some(end) = after_brace.find('}') else {
            break;
        };
        let expr = after_brace[..end].trim();
        // Accept var.X and local.X as tainted references
        let param_name = if expr.starts_with("var.") || expr.starts_with("local.") {
            expr.to_string()
        } else {
            remaining = &remaining[start + 2..];
            continue;
        };
        flows.push(TaintFlow {
            taint_source: param_name,
            sink_byte: 0,
            sink_end_byte: 0,
        });
        remaining = &after_brace[end..];
    }
    flows
}

/// Extract the outer resource/data block label for HCL export record symbol names.
/// Matches: `resource "type" "name" {` → `"type.name"`
fn extract_hcl_block_label(source: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(source) else {
        return "hclBlock".to_string();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        // Match outer enclosing blocks: resource "type" "name" { or data "type" "name" {
        if trimmed.starts_with("resource ") || trimmed.starts_with("data ") {
            let parts: Vec<&str> = trimmed.split('"').collect();
            if parts.len() >= 4 {
                return format!("{}.{}", parts[1], parts[3]);
            }
        }
    }
    "hclBlock".to_string()
}

fn collect_hcl_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let flows = find_hcl_dangerous_flows(source);
    if flows.is_empty() {
        return Vec::new();
    }
    let symbol_name = extract_hcl_block_label(source);
    let tainted_params: Vec<TaintedParam> = flows
        .into_iter()
        .enumerate()
        .map(|(index, flow)| TaintedParam {
            param_index: index as u32,
            param_name: flow.taint_source,
            kind: TaintKind::UserInput,
        })
        .collect();
    let _ = root;
    vec![TaintExportRecord {
        symbol_name,
        file_path: file_path.replace('\\', "/"),
        tainted_params,
        sink_kinds: vec![TaintKind::Unknown],
        propagates_to_return: false,
    }]
}

// ---------------------------------------------------------------------------
// Lua implementation
// ---------------------------------------------------------------------------

/// Lua OS execution functions — first argument is the shell command string.
const LUA_DANGEROUS_CALLS: &[&str] = &["os.execute", "io.popen"];

/// Track intra-file taint from Lua function parameters to OS execution sinks.
///
/// Sinks: `os.execute(param)`, `io.popen(param)` — present in Neovim plugin
/// scripts and embedded-system Lua runtimes.
pub fn track_taint_lua(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_lua_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    find_lua_dangerous_flows(source, &params)
}

/// Collect Lua function parameter names from the parsed AST.
pub fn collect_lua_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_lua_parameter_names(root, source, &mut params, 0);
    if params.is_empty() {
        // Textual fallback: `function name(param1, param2)`
        if let Ok(text) = std::str::from_utf8(source) {
            params = collect_lua_params_from_text(text);
        }
    }
    params
}

fn collect_lua_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // tree-sitter-lua: `parameters` node contains `identifier` children
    if node.kind() == "parameters" {
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
        collect_lua_parameter_names(child, source, params, depth + 1);
    }
}

fn collect_lua_params_from_text(text: &str) -> Vec<String> {
    // Match `function name(...)` or `local function name(...)`
    let Some(fn_idx) = text.find("function") else {
        return Vec::new();
    };
    let sig = &text[fn_idx..];
    let Some(open) = sig.find('(') else {
        return Vec::new();
    };
    let Some(close) = sig[open + 1..].find(')') else {
        return Vec::new();
    };
    sig[open + 1..open + 1 + close]
        .split(',')
        .filter_map(|s| {
            let name = s.trim();
            if name.is_empty() || name == "..." {
                None
            } else {
                Some(name.to_string())
            }
        })
        .collect()
}

fn find_lua_dangerous_flows(source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let is_sink = LUA_DANGEROUS_CALLS.iter().any(|s| trimmed.contains(s));
        if !is_sink {
            continue;
        }
        for param in params {
            if trimmed.contains(param.as_str()) {
                flows.push(TaintFlow {
                    taint_source: param.clone(),
                    sink_byte: 0,
                    sink_end_byte: 0,
                });
                break;
            }
        }
    }
    flows
}

fn collect_lua_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    // Textual approach: tree-sitter-lua grammar version variance makes node-kind
    // checks fragile. Detect dangerous flows first; if found, emit an export record
    // with the function name extracted from the source text.
    let _ = root;
    let params = collect_lua_params_textual(source);
    let flows = find_lua_dangerous_flows(source, &params);
    if flows.is_empty() {
        return Vec::new();
    }
    let symbol_name = extract_lua_function_name(source);
    let tainted_params: Vec<TaintedParam> = flows
        .into_iter()
        .enumerate()
        .map(|(index, flow)| TaintedParam {
            param_index: index as u32,
            param_name: flow.taint_source,
            kind: TaintKind::UserInput,
        })
        .collect();
    vec![TaintExportRecord {
        symbol_name,
        file_path: file_path.replace('\\', "/"),
        tainted_params,
        sink_kinds: vec![TaintKind::Unknown],
        propagates_to_return: false,
    }]
}

/// Extract the first Lua function name from source text.
/// Matches `function name(` and `local function name(`.
fn extract_lua_function_name(source: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(source) else {
        return "luaFn".to_string();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        // `function name(` or `local function name(`
        let rest = if let Some(s) = trimmed.strip_prefix("local function ") {
            s
        } else if let Some(s) = trimmed.strip_prefix("function ") {
            s
        } else {
            continue;
        };
        if let Some(paren) = rest.find('(') {
            let name = rest[..paren].trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "luaFn".to_string()
}

fn collect_lua_params_textual(source: &[u8]) -> Vec<String> {
    if let Ok(text) = std::str::from_utf8(source) {
        collect_lua_params_from_text(text)
    } else {
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// GDScript implementation
// ---------------------------------------------------------------------------

/// GDScript OS execution functions — used in Godot editor extensions and game mods.
const GDSCRIPT_DANGEROUS_CALLS: &[&str] = &["OS.execute", "OS.shell_open"];

/// Track intra-file taint from GDScript function parameters to OS execution sinks.
///
/// Sinks: `OS.execute(param, ...)`, `OS.shell_open(param)` — Godot engine 4.x
/// API for spawning child processes.
pub fn track_taint_gdscript(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_gdscript_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    find_gdscript_dangerous_flows(source, &params)
}

/// Collect GDScript function parameter names from the parsed AST.
pub fn collect_gdscript_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_gdscript_parameter_names(root, source, &mut params, 0);
    if params.is_empty() {
        // Textual fallback: `func name(param: Type):`
        if let Ok(text) = std::str::from_utf8(source) {
            params = collect_signature_params_from_source(source, "func");
            let _ = text;
        }
    }
    params
}

fn collect_gdscript_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // tree-sitter-gdscript: `parameters` node wrapping individual `parameter` nodes
    if node.kind() == "parameters" {
        let mut cur = node.walk();
        for child in node.named_children(&mut cur) {
            // `parameter` node: first named child is the identifier
            let name = if child.kind() == "identifier" {
                child.utf8_text(source).ok().map(str::to_string)
            } else {
                child
                    .named_child(0)
                    .filter(|c| c.kind() == "identifier")
                    .and_then(|c| c.utf8_text(source).ok())
                    .map(str::to_string)
            };
            if let Some(n) = name {
                if !n.is_empty() {
                    params.push(n);
                }
            }
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_gdscript_parameter_names(child, source, params, depth + 1);
    }
}

fn find_gdscript_dangerous_flows(source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let is_sink = GDSCRIPT_DANGEROUS_CALLS.iter().any(|s| trimmed.contains(s));
        if !is_sink {
            continue;
        }
        for param in params {
            if trimmed.contains(param.as_str()) {
                flows.push(TaintFlow {
                    taint_source: param.clone(),
                    sink_byte: 0,
                    sink_end_byte: 0,
                });
                break;
            }
        }
    }
    flows
}

fn collect_gdscript_exports(
    root: Node<'_>,
    source: &[u8],
    file_path: &str,
) -> Vec<TaintExportRecord> {
    let mut records = Vec::new();
    walk_gdscript_exports(root, source, file_path, &mut records, 0);
    records
}

fn walk_gdscript_exports(
    node: Node<'_>,
    source: &[u8],
    file_path: &str,
    records: &mut Vec<TaintExportRecord>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // tree-sitter-gdscript: `function_definition` node
    if node.kind() == "function_definition" {
        let symbol_name = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::to_string)
            .unwrap_or_else(|| "gdFunc".to_string());
        let params = collect_gdscript_params(node, source);
        let flows = find_gdscript_dangerous_flows(source, &params);
        let tainted_params: Vec<TaintedParam> = flows
            .into_iter()
            .enumerate()
            .map(|(index, flow)| TaintedParam {
                param_index: index as u32,
                param_name: flow.taint_source,
                kind: TaintKind::UserInput,
            })
            .filter(|tp| params.contains(&tp.param_name))
            .collect();
        if !tainted_params.is_empty() {
            records.push(TaintExportRecord {
                symbol_name,
                file_path: file_path.replace('\\', "/"),
                tainted_params,
                sink_kinds: vec![TaintKind::Unknown],
                propagates_to_return: false,
            });
        }
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        walk_gdscript_exports(child, source, file_path, records, depth + 1);
    }
}

// ---------------------------------------------------------------------------
// Zig implementation
// ---------------------------------------------------------------------------

/// Zig stdlib functions that spawn child processes.
const ZIG_DANGEROUS_CALLS: &[&str] = &[
    "ChildProcess.exec",
    "ChildProcess.run",
    "std.process.exec",
    "spawnAndWait",
];

/// Track intra-file taint from Zig function parameters to child-process sinks.
///
/// Sinks: `std.ChildProcess.exec(.{ .argv = &[_][]const u8{param} })`,
/// `std.process.exec` — systems-level command execution in Zig tooling.
pub fn track_taint_zig(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_zig_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    find_zig_dangerous_flows(source, &params)
}

/// Collect Zig function parameter names from the parsed AST.
pub fn collect_zig_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let mut params = Vec::new();
    collect_zig_parameter_names(root, source, &mut params, 0);
    if params.is_empty() {
        // Textual fallback: `fn name(param: Type)`
        params = collect_signature_params_from_source(source, "fn");
    }
    params
}

fn collect_zig_parameter_names(
    node: Node<'_>,
    source: &[u8],
    params: &mut Vec<String>,
    depth: u32,
) {
    if depth > 100 {
        return;
    }
    // tree-sitter-zig: `param_decl` nodes hold individual parameter names
    if node.kind() == "param_decl" {
        // Try named field first; otherwise scan named children for identifier.
        let mut name_opt = node
            .child_by_field_name("name")
            .and_then(|n| n.utf8_text(source).ok())
            .map(str::to_string);
        if name_opt.is_none() {
            let mut cur = node.walk();
            for child in node.named_children(&mut cur) {
                if child.kind() == "identifier" {
                    if let Ok(n) = child.utf8_text(source) {
                        name_opt = Some(n.to_string());
                        break;
                    }
                }
            }
        }
        if let Some(n) = name_opt {
            if !n.is_empty() && n != "comptime" {
                params.push(n);
            }
        }
        return;
    }
    let mut cur = node.walk();
    for child in node.children(&mut cur) {
        collect_zig_parameter_names(child, source, params, depth + 1);
    }
}

fn find_zig_dangerous_flows(source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let is_sink = ZIG_DANGEROUS_CALLS.iter().any(|s| trimmed.contains(s));
        if !is_sink {
            continue;
        }
        for param in params {
            if trimmed.contains(param.as_str()) {
                flows.push(TaintFlow {
                    taint_source: param.clone(),
                    sink_byte: 0,
                    sink_end_byte: 0,
                });
                break;
            }
        }
    }
    flows
}

fn collect_zig_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    // Textual approach: tree-sitter-zig grammar version variance makes node-kind
    // checks fragile. Detect dangerous flows first; if found, emit an export record
    // with the function name extracted textually from `pub fn name(` / `fn name(`.
    let _ = root;
    let params = collect_zig_params_textual(source);
    let flows = find_zig_dangerous_flows(source, &params);
    if flows.is_empty() {
        return Vec::new();
    }
    let symbol_name = extract_zig_function_name(source);
    let tainted_params: Vec<TaintedParam> = flows
        .into_iter()
        .enumerate()
        .map(|(index, flow)| TaintedParam {
            param_index: index as u32,
            param_name: flow.taint_source,
            kind: TaintKind::UserInput,
        })
        .collect();
    vec![TaintExportRecord {
        symbol_name,
        file_path: file_path.replace('\\', "/"),
        tainted_params,
        sink_kinds: vec![TaintKind::Unknown],
        propagates_to_return: false,
    }]
}

/// Extract the first Zig function name from source text.
/// Matches `pub fn name(` and `fn name(`.
fn extract_zig_function_name(source: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(source) else {
        return "zigFn".to_string();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        let rest = if let Some(s) = trimmed.strip_prefix("pub fn ") {
            s
        } else if let Some(s) = trimmed.strip_prefix("fn ") {
            s
        } else {
            continue;
        };
        if let Some(paren) = rest.find('(') {
            let name = rest[..paren].trim();
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    "zigFn".to_string()
}

fn collect_zig_params_textual(source: &[u8]) -> Vec<String> {
    collect_signature_params_from_source(source, "fn")
}

// ---------------------------------------------------------------------------
// Objective-C / Objective-C++ implementation
// ---------------------------------------------------------------------------

/// Objective-C method/function names whose arguments are treated as OS execution sinks.
const OBJC_DANGEROUS_CALLS: &[&str] = &[
    "NSTask",
    "system(",
    "popen(",
    "performSelector:",
    "LaunchPath",
    "launch",
];

/// Track intra-file taint from Objective-C method parameters to OS execution sinks.
///
/// Sinks: `NSTask`, `system()`, `popen()`, `performSelector:`, `setLaunchPath:`.
pub fn track_taint_objc(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let params = collect_objc_params(root, source);
    if params.is_empty() {
        return Vec::new();
    }
    find_objc_dangerous_flows(source, &params)
}

/// Collect Objective-C method/function parameter names.
///
/// Handles ObjC keyword-message selectors `- (RetType)selector:(Type *)paramName …`
/// and falls back to C-style signature scanning for plain C functions in `.m` files.
pub fn collect_objc_params(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let _ = root;
    collect_objc_params_textual(source)
}

fn collect_objc_params_textual(source: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut params = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        // ObjC method declaration: `- (RetType)selector:(Type *)paramName …`
        if (trimmed.starts_with("- (") || trimmed.starts_with("+ (")) && trimmed.contains(":(") {
            let mut rest = trimmed;
            while let Some(colon_pos) = rest.find(":(") {
                let after_colon = &rest[colon_pos + 1..];
                if let Some(close_paren) = after_colon.find(')') {
                    let after_type = &after_colon[close_paren + 1..];
                    // Skip pointer stars and whitespace between `)` and param name
                    let after_type = after_type.trim_start_matches('*').trim_start();
                    let param_name: String = after_type
                        .chars()
                        .take_while(|c| c.is_alphanumeric() || *c == '_')
                        .collect();
                    if !param_name.is_empty() {
                        params.push(param_name);
                    }
                }
                rest = &rest[colon_pos + 1..];
            }
        }
    }
    // Fallback: C-style function signatures inside .m/.mm files
    if params.is_empty() {
        params = collect_signature_params_from_source(source, "void");
    }
    params
}

fn find_objc_dangerous_flows(source: &[u8], params: &[String]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    let mut byte_offset: usize = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        let is_sink = OBJC_DANGEROUS_CALLS.iter().any(|s| trimmed.contains(s));
        if is_sink {
            for param in params {
                // Exclude string literal occurrences: `"param"` or `@"param"`
                if trimmed.contains(param.as_str())
                    && !trimmed.contains(&format!("\"{param}\""))
                    && !trimmed.contains(&format!("@\"{param}\""))
                {
                    flows.push(TaintFlow {
                        taint_source: param.clone(),
                        sink_byte: byte_offset,
                        sink_end_byte: byte_offset + line.len(),
                    });
                }
            }
        }
        byte_offset += line.len() + 1;
    }
    flows
}

fn collect_objc_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let _ = root;
    let params = collect_objc_params_textual(source);
    let flows = find_objc_dangerous_flows(source, &params);
    if flows.is_empty() {
        return Vec::new();
    }
    let symbol_name = extract_objc_method_name(source);
    let tainted_params: Vec<TaintedParam> = flows
        .into_iter()
        .enumerate()
        .filter(|(_, f)| params.contains(&f.taint_source))
        .map(|(index, flow)| TaintedParam {
            param_index: index as u32,
            param_name: flow.taint_source,
            kind: TaintKind::UserInput,
        })
        .collect();
    if tainted_params.is_empty() {
        return Vec::new();
    }
    vec![TaintExportRecord {
        symbol_name,
        file_path: file_path.replace('\\', "/"),
        tainted_params,
        sink_kinds: vec![TaintKind::Unknown],
        propagates_to_return: false,
    }]
}

/// Extract the first ObjC method selector name (stripped of trailing `:`) from source.
fn extract_objc_method_name(source: &[u8]) -> String {
    let Ok(text) = std::str::from_utf8(source) else {
        return "objcMethod".to_string();
    };
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("- (") || trimmed.starts_with("+ (") {
            if let Some(close_paren) = trimmed.find(')') {
                let after = &trimmed[close_paren + 1..].trim_start();
                let name: String = after
                    .chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == ':')
                    .collect();
                if !name.is_empty() {
                    return name.trim_end_matches(':').to_string();
                }
            }
        }
    }
    "objcMethod".to_string()
}

// ---------------------------------------------------------------------------
// GLSL implementation
// ---------------------------------------------------------------------------

/// GLSL output variables and sampling calls treated as security-sensitive sinks.
///
/// A GPU timing side-channel or shader-logic injection occurs when attacker-controlled
/// uniform/varying data reaches `discard`, `gl_FragDepth`, `gl_Position`, or a
/// texture sampling call without bounds checking.
const GLSL_DANGEROUS_SINKS: &[&str] = &[
    "discard",
    "gl_FragDepth",
    "gl_FragColor",
    "gl_Position",
    "texelFetch(",
    "texture2D(",
    "texture(",
];

/// Track intra-file taint from GLSL `uniform` / `varying` / `in` inputs to GPU sinks.
///
/// Sinks: `discard`, `gl_FragDepth`, `gl_FragColor`, `gl_Position`,
/// `texelFetch`, `texture2D`, `texture`.
pub fn track_taint_glsl(source: &[u8], root: Node<'_>) -> Vec<TaintFlow> {
    let inputs = collect_glsl_inputs(root, source);
    if inputs.is_empty() {
        return Vec::new();
    }
    find_glsl_dangerous_flows(source, &inputs)
}

/// Collect GLSL `uniform`, `varying`, and `in` variable names as taint sources.
pub fn collect_glsl_inputs(root: Node<'_>, source: &[u8]) -> Vec<String> {
    let _ = root;
    collect_glsl_inputs_textual(source)
}

fn collect_glsl_inputs_textual(source: &[u8]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut inputs = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        let is_input = trimmed.starts_with("uniform ")
            || trimmed.starts_with("varying ")
            || trimmed.starts_with("in ");
        if !is_input {
            continue;
        }
        // Variable name is the last whitespace-separated token before `;`
        let decl = trimmed.trim_end_matches(';').trim();
        let name_token = decl.split_whitespace().last().unwrap_or("");
        // Strip array suffix: `texCoords[4]` → `texCoords`
        let name: String = name_token
            .chars()
            .take_while(|c| c.is_alphanumeric() || *c == '_')
            .collect();
        if !name.is_empty() && name != "uniform" && name != "varying" && name != "in" {
            inputs.push(name);
        }
    }
    inputs
}

fn find_glsl_dangerous_flows(source: &[u8], inputs: &[String]) -> Vec<TaintFlow> {
    let Ok(text) = std::str::from_utf8(source) else {
        return Vec::new();
    };
    let mut flows = Vec::new();
    let mut byte_offset: usize = 0;
    for line in text.lines() {
        let trimmed = line.trim();
        let is_sink = GLSL_DANGEROUS_SINKS.iter().any(|s| trimmed.contains(s));
        if is_sink {
            for input in inputs {
                if trimmed.contains(input.as_str()) {
                    flows.push(TaintFlow {
                        taint_source: input.clone(),
                        sink_byte: byte_offset,
                        sink_end_byte: byte_offset + line.len(),
                    });
                }
            }
        }
        byte_offset += line.len() + 1;
    }
    flows
}

fn collect_glsl_exports(root: Node<'_>, source: &[u8], file_path: &str) -> Vec<TaintExportRecord> {
    let _ = root;
    let inputs = collect_glsl_inputs_textual(source);
    let flows = find_glsl_dangerous_flows(source, &inputs);
    if flows.is_empty() {
        return Vec::new();
    }
    let tainted_params: Vec<TaintedParam> = flows
        .into_iter()
        .enumerate()
        .filter(|(_, f)| inputs.contains(&f.taint_source))
        .map(|(index, flow)| TaintedParam {
            param_index: index as u32,
            param_name: flow.taint_source,
            kind: TaintKind::UserInput,
        })
        .collect();
    if tainted_params.is_empty() {
        return Vec::new();
    }
    // GLSL files represent shader programs rather than named functions;
    // use the file stem as the symbol identifier.
    let symbol_name = std::path::Path::new(file_path)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("glsl_shader")
        .to_string();
    vec![TaintExportRecord {
        symbol_name,
        file_path: file_path.replace('\\', "/"),
        tainted_params,
        sink_kinds: vec![TaintKind::Unknown],
        propagates_to_return: false,
    }]
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

    fn parse_python(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .expect("Python grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Python source must parse")
    }

    fn parse_typescript(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
            .expect("TypeScript grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("TypeScript source must parse")
    }

    fn parse_java(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .expect("Java grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Java source must parse")
    }

    fn parse_csharp(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_c_sharp::LANGUAGE.into())
            .expect("C# grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("C# source must parse")
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

    #[test]
    fn python_export_record_emits_for_public_function_boundary() {
        let src = r#"def build_query(user):
    dangerous_sink(user)
"#;
        let tree = parse_python(src);
        let records =
            export_cross_file_records("py", "src/db.py", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].symbol_name, "build_query");
        assert_eq!(records[0].tainted_params[0].param_name, "user");
        assert!(!records[0].sink_kinds.is_empty());
    }

    #[test]
    fn typescript_export_record_emits_for_exported_function() {
        let src = r#"export function buildQuery(user: string) {
  dangerousSink(user);
}"#;
        let tree = parse_typescript(src);
        let records =
            export_cross_file_records("ts", "src/db.ts", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].symbol_name, "buildQuery");
        assert_eq!(records[0].tainted_params[0].param_name, "user");
    }

    #[test]
    fn java_export_record_emits_for_public_method() {
        let src = r#"class Queries {
  public String buildQuery(String user) {
    return dangerousSink(user);
  }
}"#;
        let tree = parse_java(src);
        let records =
            export_cross_file_records("java", "src/Queries.java", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].symbol_name, "buildQuery");
        assert!(records[0].propagates_to_return);
    }

    #[test]
    fn go_export_record_emits_for_exported_function() {
        let src = r#"package main
func BuildQuery(user string) string {
    return dangerousSink(user)
}
"#;
        let tree = parse_go(src);
        let records = export_cross_file_records("go", "db.go", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].symbol_name, "BuildQuery");
    }

    #[test]
    fn csharp_export_record_emits_for_public_method() {
        let src = r#"class Queries {
    public string BuildQuery(string user) {
        return DangerousSink(user);
    }
}"#;
        let tree = parse_csharp(src);
        let records =
            export_cross_file_records("cs", "Queries.cs", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].symbol_name, "BuildQuery");
        assert_eq!(records[0].tainted_params[0].param_name, "user");
    }

    // -----------------------------------------------------------------------
    // C/C++ taint tests
    // -----------------------------------------------------------------------

    fn parse_cpp(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_cpp::LANGUAGE.into())
            .expect("C++ grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("C++ source must parse")
    }

    fn parse_rust_src(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_rust::LANGUAGE.into())
            .expect("Rust grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Rust source must parse")
    }

    fn parse_kotlin(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_kotlin_ng::LANGUAGE.into())
            .expect("Kotlin grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Kotlin source must parse")
    }

    fn parse_swift(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_swift::LANGUAGE.into())
            .expect("Swift grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Swift source must parse")
    }

    fn parse_scala(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_scala::LANGUAGE.into())
            .expect("Scala grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Scala source must parse")
    }

    /// True positive: C++ parameter flows into `system()` call.
    #[test]
    fn cpp_taint_confirmed_param_in_system_call() {
        let src = r#"
#include <cstdlib>
void run_command(char* user_cmd) {
    system(user_cmd);
}
"#;
        let tree = parse_cpp(src);
        let params = collect_cpp_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_cpp_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(!params.is_empty(), "C++ params must be collected");
        assert!(
            !flows.is_empty(),
            "C++ system() with param must confirm taint"
        );
        assert_eq!(flows[0].taint_source, "user_cmd");
    }

    /// True negative: C++ system() with literal string — no taint.
    #[test]
    fn cpp_taint_not_confirmed_literal_in_system_call() {
        let src = r#"
#include <cstdlib>
void run_safe() {
    system("ls -la");
}
"#;
        let tree = parse_cpp(src);
        let params = collect_cpp_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_cpp_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(
            flows.is_empty(),
            "C++ system() with literal must not confirm taint"
        );
    }

    /// True positive: C++ cross-file export record emits for non-static function.
    #[test]
    fn cpp_export_record_emits_for_non_static_function() {
        let src = r#"
void process_input(char* data) {
    system(data);
}
"#;
        let tree = parse_cpp(src);
        let records =
            export_cross_file_records("cpp", "src/handler.cpp", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1, "cpp export must emit one record");
        assert_eq!(records[0].symbol_name, "process_input");
        assert_eq!(records[0].tainted_params[0].param_name, "data");
    }

    // -----------------------------------------------------------------------
    // Rust taint tests
    // -----------------------------------------------------------------------

    /// True positive: Rust pub fn parameter flows into `Command::new(param)`.
    #[test]
    fn rust_taint_confirmed_param_in_command_new() {
        let src = r#"
use std::process::Command;
pub fn run_cmd(cmd: &str) {
    Command::new(cmd);
}
"#;
        let tree = parse_rust_src(src);
        let params = collect_rust_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_rust_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(!params.is_empty(), "Rust params must be collected");
        assert!(
            !flows.is_empty(),
            "Rust Command::new(param) must confirm taint"
        );
        assert_eq!(flows[0].taint_source, "cmd");
    }

    /// True negative: Rust Command::new with literal — no taint.
    #[test]
    fn rust_taint_not_confirmed_literal_in_command_new() {
        let src = r#"
use std::process::Command;
pub fn run_safe() {
    Command::new("ls");
}
"#;
        let tree = parse_rust_src(src);
        let params = collect_rust_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_rust_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(
            flows.is_empty(),
            "Rust Command::new with literal must not confirm taint"
        );
    }

    /// True positive: Rust cross-file export record emits for pub fn.
    #[test]
    fn rust_export_record_emits_for_pub_fn() {
        let src = r#"
use std::process::Command;
pub fn execute(cmd: &str) {
    Command::new(cmd);
}
"#;
        let tree = parse_rust_src(src);
        let records =
            export_cross_file_records("rs", "src/runner.rs", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1, "Rust export must emit one record");
        assert_eq!(records[0].symbol_name, "execute");
        assert_eq!(records[0].tainted_params[0].param_name, "cmd");
    }

    // -----------------------------------------------------------------------
    // Kotlin taint tests
    // -----------------------------------------------------------------------

    /// True positive: Kotlin parameter flows into Runtime.exec().
    #[test]
    fn kotlin_taint_confirmed_param_in_runtime_exec() {
        let src = r#"
fun runCommand(userCmd: String) {
    Runtime.getRuntime().exec(userCmd)
}
"#;
        let tree = parse_kotlin(src);
        let params = collect_kotlin_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_kotlin_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(!params.is_empty(), "Kotlin params must be collected");
        assert!(
            !flows.is_empty(),
            "Kotlin Runtime.exec(param) must confirm taint"
        );
        assert_eq!(flows[0].taint_source, "userCmd");
    }

    /// True negative: Kotlin exec() with literal — no taint.
    #[test]
    fn kotlin_taint_not_confirmed_literal_in_exec() {
        let src = r#"
fun runSafe() {
    Runtime.getRuntime().exec("ls")
}
"#;
        let tree = parse_kotlin(src);
        let params = collect_kotlin_params(tree.root_node(), src.as_bytes());
        let flows = find_tainted_kotlin_sinks(tree.root_node(), src.as_bytes(), &params);
        assert!(
            flows.is_empty(),
            "Kotlin exec() with literal must not confirm taint"
        );
    }

    #[test]
    fn swift_taint_confirmed_for_foundation_process() {
        let src = r#"
func runCommand(userCmd: String) {
    Foundation.Process(userCmd)
}
"#;
        let tree = parse_swift(src);
        let flows = track_taint_swift(src.as_bytes(), tree.root_node());
        assert_eq!(flows.len(), 1, "Swift Process(userCmd) must confirm taint");
        assert_eq!(flows[0].taint_source, "userCmd");
    }

    #[test]
    fn swift_taint_not_confirmed_for_literal_process() {
        let src = r#"
func runSafe() {
    Foundation.Process("ls")
}
"#;
        let tree = parse_swift(src);
        let flows = track_taint_swift(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "Swift literal process call must stay silent"
        );
    }

    #[test]
    fn swift_export_record_emits_for_exec_boundary() {
        let src = r#"
func runCommand(userCmd: String) {
    let proc = Process(userCmd)
    proc.launch()
}
"#;
        let tree = parse_swift(src);
        let records = export_cross_file_records(
            "swift",
            "Sources/Runner.swift",
            src.as_bytes(),
            tree.root_node(),
        );
        assert_eq!(records.len(), 1, "Swift export must emit one record");
        assert_eq!(records[0].symbol_name, "runCommand");
        assert_eq!(records[0].tainted_params[0].param_name, "userCmd");
    }

    #[test]
    fn scala_taint_confirmed_for_runtime_exec() {
        let src = r#"
def runCommand(userCmd: String): Unit = {
  Runtime.getRuntime().exec(userCmd)
}
"#;
        let tree = parse_scala(src);
        let flows = track_taint_scala(src.as_bytes(), tree.root_node());
        assert_eq!(
            flows.len(),
            1,
            "Scala Runtime.exec(userCmd) must confirm taint"
        );
        assert_eq!(flows[0].taint_source, "userCmd");
    }

    #[test]
    fn scala_taint_not_confirmed_for_literal_process() {
        let src = r#"
def runSafe(): Unit = {
  sys.process.Process("ls")
}
"#;
        let tree = parse_scala(src);
        let flows = track_taint_scala(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "Scala literal sys.process.Process call must stay silent"
        );
    }

    #[test]
    fn scala_export_record_emits_for_process_boundary() {
        let src = r#"
def runCommand(userCmd: String): Unit = {
  sys.process.Process(userCmd)
}
"#;
        let tree = parse_scala(src);
        let records = export_cross_file_records(
            "scala",
            "src/main/scala/Runner.scala",
            src.as_bytes(),
            tree.root_node(),
        );
        assert_eq!(records.len(), 1, "Scala export must emit one record");
        assert_eq!(records[0].symbol_name, "runCommand");
        assert_eq!(records[0].tainted_params[0].param_name, "userCmd");
    }

    fn parse_bash(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_bash::LANGUAGE.into())
            .expect("Bash grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Bash source must parse")
    }

    fn parse_nix(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_nix::LANGUAGE.into())
            .expect("Nix grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Nix source must parse")
    }

    fn parse_hcl(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_hcl::LANGUAGE.into())
            .expect("HCL grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("HCL source must parse")
    }

    // -----------------------------------------------------------------------
    // Bash taint tests
    // -----------------------------------------------------------------------

    #[test]
    fn bash_eval_positional_param_confirms_taint() {
        let src = r#"
run_cmd() {
    eval "$1"
}
"#;
        let tree = parse_bash(src);
        let flows = track_taint_bash(src.as_bytes(), tree.root_node());
        assert_eq!(flows.len(), 1, "eval $1 must confirm taint");
        assert_eq!(flows[0].taint_source, "$1");
    }

    #[test]
    fn bash_eval_literal_is_safe() {
        let src = r#"
run_safe() {
    eval "ls -la /tmp"
}
"#;
        let tree = parse_bash(src);
        let flows = track_taint_bash(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "eval with string literal must not emit taint flow"
        );
    }

    #[test]
    fn bash_eval_all_args_confirms_taint() {
        let src = r#"
run_all() {
    eval "$@"
}
"#;
        let tree = parse_bash(src);
        let flows = track_taint_bash(src.as_bytes(), tree.root_node());
        assert_eq!(flows.len(), 1, "eval $@ must confirm taint");
        assert_eq!(flows[0].taint_source, "$@");
    }

    #[test]
    fn bash_export_record_emits_for_eval_boundary() {
        let src = r#"
run_cmd() {
    eval "$1"
}
"#;
        let tree = parse_bash(src);
        let records =
            export_cross_file_records("bash", "scripts/run.sh", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1, "Bash eval $1 must emit one export record");
        assert_eq!(records[0].symbol_name, "run_cmd");
        assert_eq!(records[0].tainted_params[0].param_name, "$1");
    }

    // -----------------------------------------------------------------------
    // Nix taint tests
    // -----------------------------------------------------------------------

    #[test]
    fn nix_builtins_exec_with_param_confirms_taint() {
        let src = "{ cmd }: builtins.exec [ cmd ]";
        let tree = parse_nix(src);
        let flows = track_taint_nix(src.as_bytes(), tree.root_node());
        assert_eq!(
            flows.len(),
            1,
            "builtins.exec with param must confirm taint"
        );
        assert_eq!(flows[0].taint_source, "cmd");
    }

    #[test]
    fn nix_builtins_exec_with_literal_is_safe() {
        let src = r#"builtins.exec [ "ls" "-la" ]"#;
        let tree = parse_nix(src);
        let flows = track_taint_nix(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "builtins.exec with only string literals must stay silent"
        );
    }

    #[test]
    fn nix_export_record_emits_for_exec_boundary() {
        let src = "{ cmd }: builtins.exec [ cmd ]";
        let tree = parse_nix(src);
        let records =
            export_cross_file_records("nix", "pkgs/runner.nix", src.as_bytes(), tree.root_node());
        assert_eq!(
            records.len(),
            1,
            "Nix builtins.exec must emit one export record"
        );
        assert_eq!(records[0].tainted_params[0].param_name, "cmd");
    }

    // -----------------------------------------------------------------------
    // HCL / Terraform taint tests
    // -----------------------------------------------------------------------

    #[test]
    fn hcl_local_exec_with_var_confirms_taint() {
        let src = r#"
resource "null_resource" "deploy" {
  provisioner "local-exec" {
    command = "echo ${var.user_input}"
  }
}
"#;
        let tree = parse_hcl(src);
        let flows = track_taint_hcl(src.as_bytes(), tree.root_node());
        assert_eq!(
            flows.len(),
            1,
            "local-exec with ${{var.X}} must confirm taint"
        );
        assert_eq!(flows[0].taint_source, "var.user_input");
    }

    #[test]
    fn hcl_local_exec_with_literal_is_safe() {
        let src = r#"
resource "null_resource" "safe" {
  provisioner "local-exec" {
    command = "echo hello"
  }
}
"#;
        let tree = parse_hcl(src);
        let flows = track_taint_hcl(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "local-exec with literal command must stay silent"
        );
    }

    #[test]
    fn hcl_export_record_emits_for_local_exec_boundary() {
        let src = r#"
resource "null_resource" "deploy" {
  provisioner "local-exec" {
    command = "echo ${var.user_input}"
  }
}
"#;
        let tree = parse_hcl(src);
        let records =
            export_cross_file_records("tf", "infra/main.tf", src.as_bytes(), tree.root_node());
        assert_eq!(
            records.len(),
            1,
            "HCL local-exec with interpolation must emit one export record"
        );
        assert_eq!(records[0].symbol_name, "null_resource.deploy");
        assert_eq!(records[0].tainted_params[0].param_name, "var.user_input");
    }

    // -----------------------------------------------------------------------
    // Lua taint tests
    // -----------------------------------------------------------------------

    fn parse_lua(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_lua::LANGUAGE.into())
            .expect("Lua grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Lua source must parse")
    }

    /// True positive: Lua parameter flows into `os.execute`.
    #[test]
    fn lua_os_execute_with_param_confirms_taint() {
        let src = r#"
function run_cmd(user_cmd)
    os.execute(user_cmd)
end
"#;
        let tree = parse_lua(src);
        let flows = track_taint_lua(src.as_bytes(), tree.root_node());
        assert_eq!(flows.len(), 1, "os.execute with param must confirm taint");
        assert_eq!(flows[0].taint_source, "user_cmd");
    }

    /// True negative: Lua os.execute with literal — no taint.
    #[test]
    fn lua_os_execute_with_literal_is_safe() {
        let src = r#"
function run_safe()
    os.execute("ls -la /tmp")
end
"#;
        let tree = parse_lua(src);
        let flows = track_taint_lua(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "os.execute with string literal must not emit taint flow"
        );
    }

    /// Export record: Lua function with os.execute sink emits TaintExportRecord.
    #[test]
    fn lua_export_record_emits_for_os_execute_boundary() {
        let src = r#"
function run_cmd(user_cmd)
    os.execute(user_cmd)
end
"#;
        let tree = parse_lua(src);
        let records = export_cross_file_records(
            "lua",
            "scripts/runner.lua",
            src.as_bytes(),
            tree.root_node(),
        );
        assert_eq!(
            records.len(),
            1,
            "Lua os.execute must emit one export record"
        );
        assert_eq!(records[0].symbol_name, "run_cmd");
        assert_eq!(records[0].tainted_params[0].param_name, "user_cmd");
    }

    // -----------------------------------------------------------------------
    // GDScript taint tests
    // -----------------------------------------------------------------------

    fn parse_gdscript(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_gdscript::LANGUAGE.into())
            .expect("GDScript grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("GDScript source must parse")
    }

    /// True positive: GDScript parameter flows into `OS.execute`.
    #[test]
    fn gdscript_os_execute_with_param_confirms_taint() {
        let src = r#"
func run_cmd(user_cmd: String) -> void:
    OS.execute(user_cmd, [])
"#;
        let tree = parse_gdscript(src);
        let flows = track_taint_gdscript(src.as_bytes(), tree.root_node());
        assert_eq!(flows.len(), 1, "OS.execute with param must confirm taint");
        assert_eq!(flows[0].taint_source, "user_cmd");
    }

    /// True negative: GDScript OS.execute with literal — no taint.
    #[test]
    fn gdscript_os_execute_with_literal_is_safe() {
        let src = r#"
func run_safe() -> void:
    OS.execute("ls", [])
"#;
        let tree = parse_gdscript(src);
        let flows = track_taint_gdscript(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "OS.execute with literal must not emit taint flow"
        );
    }

    /// Export record: GDScript function with OS.execute sink emits TaintExportRecord.
    #[test]
    fn gdscript_export_record_emits_for_os_execute_boundary() {
        let src = r#"
func run_cmd(user_cmd: String) -> void:
    OS.execute(user_cmd, [])
"#;
        let tree = parse_gdscript(src);
        let records =
            export_cross_file_records("gd", "scripts/runner.gd", src.as_bytes(), tree.root_node());
        assert_eq!(
            records.len(),
            1,
            "GDScript OS.execute must emit one export record"
        );
        assert_eq!(records[0].tainted_params[0].param_name, "user_cmd");
    }

    // -----------------------------------------------------------------------
    // Zig taint tests
    // -----------------------------------------------------------------------

    fn parse_zig(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_zig::LANGUAGE.into())
            .expect("Zig grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("Zig source must parse")
    }

    /// True positive: Zig parameter flows into `ChildProcess.exec`.
    #[test]
    fn zig_child_process_exec_with_param_confirms_taint() {
        let src = r#"
pub fn run_cmd(user_cmd: []const u8) !void {
    _ = try ChildProcess.exec(.{ .argv = &[_][]const u8{user_cmd} });
}
"#;
        let tree = parse_zig(src);
        let flows = track_taint_zig(src.as_bytes(), tree.root_node());
        assert_eq!(
            flows.len(),
            1,
            "ChildProcess.exec with param must confirm taint"
        );
        assert_eq!(flows[0].taint_source, "user_cmd");
    }

    /// True negative: Zig ChildProcess.exec with literal — no taint.
    #[test]
    fn zig_child_process_exec_with_literal_is_safe() {
        let src = r#"
pub fn run_safe() !void {
    _ = try ChildProcess.exec(.{ .argv = &[_][]const u8{"ls"} });
}
"#;
        let tree = parse_zig(src);
        let flows = track_taint_zig(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "ChildProcess.exec with literal must not emit taint flow"
        );
    }

    // -----------------------------------------------------------------------
    // Objective-C taint tests
    // -----------------------------------------------------------------------

    fn parse_objc(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_objc::LANGUAGE.into())
            .expect("ObjC grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("ObjC source must parse")
    }

    /// True positive: ObjC method parameter flows into NSTask / setLaunchPath.
    #[test]
    fn objc_nstask_with_param_confirms_taint() {
        let src = r#"
- (void)runCommand:(NSString *)userCmd {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:userCmd];
    [task launch];
}
"#;
        let tree = parse_objc(src);
        let flows = track_taint_objc(src.as_bytes(), tree.root_node());
        assert!(!flows.is_empty(), "NSTask with param must confirm taint");
        assert_eq!(flows[0].taint_source, "userCmd");
    }

    /// True negative: ObjC NSTask with literal path — no taint.
    #[test]
    fn objc_nstask_with_literal_is_safe() {
        let src = r#"
- (void)runSafe {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:@"/bin/ls"];
    [task launch];
}
"#;
        let tree = parse_objc(src);
        let flows = track_taint_objc(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "NSTask with literal path must not emit taint flow"
        );
    }

    /// Export record: ObjC method with NSTask sink emits TaintExportRecord.
    #[test]
    fn objc_export_record_emits_for_nstask_boundary() {
        let src = r#"
- (void)runCommand:(NSString *)userCmd {
    NSTask *task = [[NSTask alloc] init];
    [task setLaunchPath:userCmd];
    [task launch];
}
"#;
        let tree = parse_objc(src);
        let records =
            export_cross_file_records("m", "Sources/Runner.m", src.as_bytes(), tree.root_node());
        assert_eq!(records.len(), 1, "ObjC NSTask must emit one export record");
        assert_eq!(records[0].symbol_name, "runCommand");
        assert_eq!(records[0].tainted_params[0].param_name, "userCmd");
    }

    // -----------------------------------------------------------------------
    // GLSL taint tests
    // -----------------------------------------------------------------------

    fn parse_glsl(source: &str) -> tree_sitter::Tree {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_glsl::LANGUAGE_GLSL.into())
            .expect("GLSL grammar must load");
        parser
            .parse(source.as_bytes(), None)
            .expect("GLSL source must parse")
    }

    /// True positive: GLSL varying uniform input flows into texture2D sink.
    #[test]
    fn glsl_varying_in_texture2d_confirms_taint() {
        let src = r#"
uniform sampler2D tex;
varying vec2 userCoord;

void main() {
    gl_FragColor = texture2D(tex, userCoord);
}
"#;
        let tree = parse_glsl(src);
        let flows = track_taint_glsl(src.as_bytes(), tree.root_node());
        assert!(!flows.is_empty(), "varying in texture2D must confirm taint");
        // Both `tex` (uniform) and `userCoord` (varying) are taint sources;
        // assert that `userCoord` appears somewhere in the flow list.
        assert!(
            flows.iter().any(|f| f.taint_source == "userCoord"),
            "userCoord must appear as a taint source"
        );
    }

    /// True negative: GLSL with no external inputs — no taint.
    #[test]
    fn glsl_no_external_inputs_is_safe() {
        let src = r#"
void main() {
    gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0);
}
"#;
        let tree = parse_glsl(src);
        let flows = track_taint_glsl(src.as_bytes(), tree.root_node());
        assert!(
            flows.is_empty(),
            "GLSL with no uniform/varying must not emit taint flow"
        );
    }

    /// Export record: GLSL varying flowing into texture2D emits TaintExportRecord.
    #[test]
    fn glsl_export_record_emits_for_shader_boundary() {
        let src = r#"
uniform sampler2D tex;
varying vec2 userCoord;

void main() {
    gl_FragColor = texture2D(tex, userCoord);
}
"#;
        let tree = parse_glsl(src);
        let records = export_cross_file_records(
            "frag",
            "shaders/main.frag",
            src.as_bytes(),
            tree.root_node(),
        );
        assert_eq!(
            records.len(),
            1,
            "GLSL varying in texture2D must emit one export record"
        );
        assert_eq!(records[0].symbol_name, "main");
        // Both `tex` (uniform) and `userCoord` (varying) appear as tainted params;
        // assert that `userCoord` is present somewhere in the list.
        assert!(
            records[0]
                .tainted_params
                .iter()
                .any(|p| p.param_name == "userCoord"),
            "userCoord must appear as a tainted param in the export record"
        );
    }

    /// Export record: Zig function with ChildProcess.exec sink emits TaintExportRecord.
    #[test]
    fn zig_export_record_emits_for_child_process_exec_boundary() {
        let src = r#"
pub fn run_cmd(user_cmd: []const u8) !void {
    _ = try ChildProcess.exec(.{ .argv = &[_][]const u8{user_cmd} });
}
"#;
        let tree = parse_zig(src);
        let records =
            export_cross_file_records("zig", "src/runner.zig", src.as_bytes(), tree.root_node());
        assert_eq!(
            records.len(),
            1,
            "Zig ChildProcess.exec must emit one export record"
        );
        assert_eq!(records[0].tainted_params[0].param_name, "user_cmd");
    }
}
