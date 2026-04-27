//! Race-condition and TOCTOU detection over sequential operation graphs.

use common::slop::StructuredFinding;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashSet;

/// Security finding emitted for confirmed check-then-act temporal races.
pub const TOCTOU_RULE_ID: &str = "security:toctou_race_condition";

/// Operation class tracked by the happens-before graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationKind {
    /// Filesystem state check such as `stat(path)` or `access(path, mode)`.
    FileCheck,
    /// Filesystem act operation such as `open(path, flags)`.
    FileAct,
    /// Database read check, usually `SELECT ... WHERE`.
    DbCheck,
    /// Database write act, usually `UPDATE` or `INSERT`.
    DbAct,
    /// Transaction boundary or lock that closes the temporal race.
    Guard,
}

/// Sequential operation node stored in [`HappensBeforeGraph`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Operation {
    /// Operation kind.
    pub kind: OperationKind,
    /// Canonical resource touched by the operation.
    pub resource: String,
    /// One-indexed source line.
    pub line: u32,
    /// Raw source line, trimmed.
    pub text: String,
}

/// Directed graph of sequentially ordered file and database operations.
#[derive(Debug, Clone, Default)]
pub struct HappensBeforeGraph {
    graph: DiGraph<Operation, ()>,
}

impl HappensBeforeGraph {
    /// Build a happens-before graph from source text.
    pub fn from_source(source: &[u8]) -> Self {
        let text = String::from_utf8_lossy(source);
        let mut graph = DiGraph::new();
        let mut previous: Option<NodeIndex> = None;
        for (idx, line) in text.lines().enumerate() {
            for operation in operations_from_line(line, idx as u32 + 1) {
                let node = graph.add_node(operation);
                if let Some(prev) = previous {
                    graph.add_edge(prev, node, ());
                }
                previous = Some(node);
            }
        }
        Self { graph }
    }

    /// Return the ordered operations.
    pub fn operations(&self) -> Vec<&Operation> {
        self.graph.node_weights().collect()
    }

    fn has_guard_between(&self, check_idx: usize, act_idx: usize, resource: &str) -> bool {
        self.graph
            .node_weights()
            .skip(check_idx + 1)
            .take(act_idx.saturating_sub(check_idx + 1))
            .any(|operation| {
                operation.kind == OperationKind::Guard
                    && (operation.resource == resource || operation.resource == "*")
            })
    }
}

/// Detect filesystem and database check-then-act races in a source file.
pub fn detect_race_conditions(ext: &str, source: &[u8], file_name: &str) -> Vec<StructuredFinding> {
    if !matches!(
        ext,
        "c" | "cc"
            | "cpp"
            | "cxx"
            | "h"
            | "hpp"
            | "py"
            | "rb"
            | "java"
            | "go"
            | "js"
            | "ts"
            | "tsx"
            | "jsx"
    ) {
        return Vec::new();
    }
    let hb = HappensBeforeGraph::from_source(source);
    let operations = hb.operations();
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (check_idx, check) in operations.iter().enumerate() {
        if !matches!(
            check.kind,
            OperationKind::FileCheck | OperationKind::DbCheck
        ) {
            continue;
        }
        for (act_idx, act) in operations.iter().enumerate().skip(check_idx + 1) {
            if !same_race_class(check.kind, act.kind) || check.resource != act.resource {
                continue;
            }
            if hb.has_guard_between(check_idx, act_idx, &check.resource) {
                break;
            }
            let key = (check.line, act.line, check.resource.clone());
            if seen.insert(key) {
                out.push(toctou_finding(file_name, check, act));
            }
            break;
        }
    }
    out
}

fn same_race_class(check: OperationKind, act: OperationKind) -> bool {
    matches!(
        (check, act),
        (OperationKind::FileCheck, OperationKind::FileAct)
            | (OperationKind::DbCheck, OperationKind::DbAct)
    )
}

fn toctou_finding(file_name: &str, check: &Operation, act: &Operation) -> StructuredFinding {
    let check_line = check.line;
    let act_line = act.line;
    let resource = &check.resource;
    StructuredFinding {
        id: TOCTOU_RULE_ID.to_string(),
        file: Some(file_name.to_string()),
        line: Some(check_line),
        fingerprint: blake3::hash(format!("{file_name}:{resource}:{check_line}:{act_line}").as_bytes())
            .to_hex()
            .to_string(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(format!(
            "Temporal race on `{resource}`: Check node line {check_line} precedes Act node line {act_line} without an intervening guard. Use `openat`/`fstatat` with `O_NOFOLLOW`, or hold a database transaction with `SELECT ... FOR UPDATE` across the act."
        )),
        docs_url: None,
        exploit_witness: None,
        upstream_validation_absent: false,
        ..Default::default()
    }
}

fn operations_from_line(line: &str, line_no: u32) -> Vec<Operation> {
    let mut operations = Vec::new();
    let trimmed = line.trim();
    let lower = trimmed.to_ascii_lowercase();
    if is_transaction_guard(&lower) {
        operations.push(Operation {
            kind: OperationKind::Guard,
            resource: "*".to_string(),
            line: line_no,
            text: trimmed.to_string(),
        });
    }
    if lower.contains("fstatat(") || lower.contains("o_nofollow") || lower.contains("for update") {
        operations.push(Operation {
            kind: OperationKind::Guard,
            resource: first_call_arg(trimmed, "fstatat")
                .or_else(|| first_sql_resource(&lower))
                .unwrap_or_else(|| "*".to_string()),
            line: line_no,
            text: trimmed.to_string(),
        });
    }
    if let Some(resource) =
        first_call_arg(trimmed, "stat").or_else(|| first_call_arg(trimmed, "access"))
    {
        operations.push(Operation {
            kind: OperationKind::FileCheck,
            resource,
            line: line_no,
            text: trimmed.to_string(),
        });
    }
    if let Some(resource) = first_call_arg(trimmed, "open") {
        if !lower.contains("o_nofollow") {
            operations.push(Operation {
                kind: OperationKind::FileAct,
                resource,
                line: line_no,
                text: trimmed.to_string(),
            });
        }
    }
    if lower.contains("select") && lower.contains(" where ") && !lower.contains("for update") {
        if let Some(resource) = first_sql_resource(&lower) {
            operations.push(Operation {
                kind: OperationKind::DbCheck,
                resource,
                line: line_no,
                text: trimmed.to_string(),
            });
        }
    }
    if lower.contains("update ") || lower.contains("insert into ") {
        if let Some(resource) = first_sql_write_resource(&lower) {
            operations.push(Operation {
                kind: OperationKind::DbAct,
                resource,
                line: line_no,
                text: trimmed.to_string(),
            });
        }
    }
    operations
}

fn is_transaction_guard(lower: &str) -> bool {
    lower.contains("begin")
        || lower.contains("transaction")
        || lower.contains("serializable")
        || lower.contains(".atomic(")
        || lower.contains("with transaction")
}

fn first_call_arg(line: &str, name: &str) -> Option<String> {
    for needle in [format!("{name}("), format!(".{name}(")] {
        let Some(start) = line.find(&needle) else {
            continue;
        };
        let args_start = start + needle.len();
        let args = &line[args_start..];
        let first = args.split([',', ')']).next()?.trim();
        let normalized = normalize_resource(first);
        if !normalized.is_empty() {
            return Some(normalized);
        }
    }
    None
}

fn normalize_resource(raw: &str) -> String {
    raw.trim()
        .trim_matches('&')
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .to_string()
}

fn first_sql_resource(lower: &str) -> Option<String> {
    lower
        .split(" from ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .map(clean_sql_resource)
        .filter(|resource| !resource.is_empty())
}

fn first_sql_write_resource(lower: &str) -> Option<String> {
    if let Some(tail) = lower.split("update ").nth(1) {
        return tail
            .split_whitespace()
            .next()
            .map(clean_sql_resource)
            .filter(|resource| !resource.is_empty());
    }
    lower
        .split("insert into ")
        .nth(1)
        .and_then(|tail| tail.split_whitespace().next())
        .map(clean_sql_resource)
        .filter(|resource| !resource.is_empty())
}

fn clean_sql_resource(raw: &str) -> String {
    raw.trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.')
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filesystem_stat_then_open_same_path_emits_toctou() {
        let source = br#"
int vulnerable(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        int fd = open(path, O_WRONLY);
        return fd;
    }
    return -1;
}
"#;
        let findings = detect_race_conditions("c", source, "src/fs.c");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, TOCTOU_RULE_ID);
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
        let remediation = findings[0]
            .remediation
            .as_deref()
            .expect("remediation must prove temporal gap");
        assert!(remediation.contains("Check node line 4"));
        assert!(remediation.contains("Act node line 5"));
    }

    #[test]
    fn filesystem_o_nofollow_open_suppresses_toctou() {
        let source = br#"
int safe(const char *path) {
    struct stat st;
    stat(path, &st);
    return open(path, O_RDONLY | O_NOFOLLOW);
}
"#;
        assert!(detect_race_conditions("c", source, "src/fs.c").is_empty());
    }

    #[test]
    fn database_select_then_update_same_resource_emits_toctou() {
        let source = br#"
def update_user(db, user_id):
    db.execute("SELECT id FROM users WHERE id = ?", [user_id])
    db.execute("UPDATE users SET role = 'admin' WHERE id = ?", [user_id])
"#;
        let findings = detect_race_conditions("py", source, "app/users.py");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, TOCTOU_RULE_ID);
    }

    #[test]
    fn database_select_for_update_suppresses_toctou() {
        let source = br#"
def update_user(db, user_id):
    db.execute("BEGIN TRANSACTION")
    db.execute("SELECT id FROM users WHERE id = ? FOR UPDATE", [user_id])
    db.execute("UPDATE users SET role = 'admin' WHERE id = ?", [user_id])
"#;
        assert!(detect_race_conditions("py", source, "app/users.py").is_empty());
    }
}
