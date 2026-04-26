//! Cross-file router topology graph for Express / Fastify (JS/TS) applications.
//!
//! Scans JS/TS source text for `router.use(path?, middlewares..., child_router?)`
//! call sites, builds [`RouterNode`] / [`RouterEdge`] records, and assembles a
//! `petgraph::DiGraph` that models the full cross-file mount hierarchy.
//!
//! The [`RouterTopology::inherited_middlewares`] query returns every auth guard
//! visible to a given `(file, symbol)` pair, including guards applied by ancestor
//! mounts, so the IFDS authz propagation layer can correctly downgrade IDOR
//! false positives on routes whose parent router registers the middleware via a
//! bare `router.use(authMiddleware)` call in a separate file or earlier in the
//! same file.

use std::collections::{HashMap, HashSet, VecDeque};

use petgraph::graph::{DiGraph, NodeIndex};
use petgraph::visit::EdgeRef;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A router or application symbol participating in the topology graph.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterNode {
    /// Relative file path where the symbol is defined or wired up.
    pub file: String,
    /// Variable name of the router / app, e.g. `"teamsRouter"` or `"app"`.
    pub symbol: String,
    /// Middleware names applied to ALL routes via bare `symbol.use(mw)` calls.
    pub router_level_middlewares: Vec<String>,
}

/// Edge data for a parent-mounts-child relationship in the topology.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterEdge {
    /// URL prefix under which the child router is mounted,
    /// e.g. `"/admin/teams"`.  `None` for bare `router.use(child)` calls.
    pub mount_path: Option<String>,
    /// Middleware names that appear between the optional path and the child
    /// router in the `.use(path?, mw+, child)` argument list.
    pub applied_middlewares: Vec<String>,
}

/// Assembled topology for a set of JS/TS source files.
pub struct RouterTopology {
    /// Directed graph where an edge from P → C means P mounts C.
    pub graph: DiGraph<RouterNode, RouterEdge>,
    /// O(1) lookup from `(file, symbol)` to graph node index.
    node_index: HashMap<(String, String), NodeIndex>,
}

impl RouterTopology {
    /// Return all middleware names visible to `(file, symbol)`.
    ///
    /// Includes:
    /// - Router-level middlewares registered on the node itself.
    /// - Middlewares carried by incoming edges from parent nodes.
    /// - Router-level middlewares registered on every ancestor.
    ///
    /// Returns an empty `Vec` when the pair is not registered in the topology.
    pub fn inherited_middlewares(&self, file: &str, symbol: &str) -> Vec<String> {
        let key = (file.to_string(), symbol.to_string());
        let Some(&start_idx) = self.node_index.get(&key) else {
            return Vec::new();
        };

        let mut result: Vec<String> = self.graph[start_idx].router_level_middlewares.clone();
        let mut visited: HashSet<NodeIndex> = HashSet::new();
        let mut queue: VecDeque<NodeIndex> = VecDeque::new();
        queue.push_back(start_idx);

        while let Some(idx) = queue.pop_front() {
            if !visited.insert(idx) {
                continue;
            }
            // Traverse incoming edges (parent → child) to climb the hierarchy.
            for edge_ref in self
                .graph
                .edges_directed(idx, petgraph::Direction::Incoming)
            {
                let edge = edge_ref.weight();
                result.extend_from_slice(&edge.applied_middlewares);
                let parent_idx = edge_ref.source();
                result.extend_from_slice(&self.graph[parent_idx].router_level_middlewares);
                queue.push_back(parent_idx);
            }
        }

        result.sort_unstable();
        result.dedup();
        result
    }

    /// Return all middleware names registered anywhere in `file`.
    ///
    /// Used when a finding carries only a file path and no controller symbol,
    /// to check whether any auth guard exists in the same translation unit.
    pub fn file_level_middlewares(&self, file: &str) -> Vec<String> {
        let mut result = Vec::new();

        // Router-level middlewares from all nodes belonging to this file.
        for (key, &idx) in &self.node_index {
            if key.0 == file {
                result.extend_from_slice(&self.graph[idx].router_level_middlewares);
            }
        }

        // Middlewares carried by edges whose source or target is in this file.
        for edge_ref in self.graph.edge_references() {
            let src = edge_ref.source();
            let dst = edge_ref.target();
            if self.graph[src].file == file || self.graph[dst].file == file {
                result.extend_from_slice(&edge_ref.weight().applied_middlewares);
            }
        }

        result.sort_unstable();
        result.dedup();
        result
    }
}

// ---------------------------------------------------------------------------
// Public builder
// ---------------------------------------------------------------------------

/// Staged edge record: `(parent_key, child_key, edge_data)`.
type PendingEdge = ((String, String), (String, String), RouterEdge);

/// Build a [`RouterTopology`] from a slice of `(file_path, source_bytes)` pairs.
///
/// Only files with a JS/TS extension (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`,
/// `.cjs`) are processed; all other entries are silently skipped.
pub fn build_router_topology(files: &[(&str, &[u8])]) -> RouterTopology {
    let mut graph: DiGraph<RouterNode, RouterEdge> = DiGraph::new();
    let mut node_index: HashMap<(String, String), NodeIndex> = HashMap::new();

    // Stage nodes and edges before inserting into petgraph to avoid borrow conflicts.
    let mut staged: HashMap<(String, String), RouterNode> = HashMap::new();
    let mut pending_edges: Vec<PendingEdge> = Vec::new();

    for (file, source) in files {
        let ext = file.rsplit('.').next().unwrap_or("");
        if !matches!(ext, "js" | "jsx" | "ts" | "tsx" | "mjs" | "cjs") {
            continue;
        }
        let text = match std::str::from_utf8(source) {
            Ok(s) => s,
            Err(_) => continue,
        };

        for call in extract_router_uses(text) {
            let parent_key = (file.to_string(), call.router_symbol.clone());
            let parent = staged
                .entry(parent_key.clone())
                .or_insert_with(|| RouterNode {
                    file: file.to_string(),
                    symbol: call.router_symbol.clone(),
                    router_level_middlewares: Vec::new(),
                });

            match call.child_router {
                Some(ref child_sym) => {
                    let child_key = (file.to_string(), child_sym.clone());
                    staged
                        .entry(child_key.clone())
                        .or_insert_with(|| RouterNode {
                            file: file.to_string(),
                            symbol: child_sym.clone(),
                            router_level_middlewares: Vec::new(),
                        });
                    pending_edges.push((
                        parent_key,
                        child_key,
                        RouterEdge {
                            mount_path: call.mount_path,
                            applied_middlewares: call.middlewares,
                        },
                    ));
                }
                None => {
                    // Bare middleware applied to all routes on this router.
                    for mw in &call.middlewares {
                        if !parent.router_level_middlewares.contains(mw) {
                            parent.router_level_middlewares.push(mw.clone());
                        }
                    }
                }
            }
        }
    }

    // Flush staged nodes into the graph.
    for (key, node) in staged {
        let idx = graph.add_node(node);
        node_index.insert(key, idx);
    }

    // Flush pending edges.
    for (parent_key, child_key, edge) in pending_edges {
        if let (Some(&parent_idx), Some(&child_idx)) =
            (node_index.get(&parent_key), node_index.get(&child_key))
        {
            graph.add_edge(parent_idx, child_idx, edge);
        }
    }

    RouterTopology { graph, node_index }
}

// ---------------------------------------------------------------------------
// Internal: `.use(...)` call-site extractor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RouterUseCall {
    router_symbol: String,
    mount_path: Option<String>,
    middlewares: Vec<String>,
    child_router: Option<String>,
}

/// Lightweight character-scan for `<symbol>.use(...)` call sites.
///
/// Avoids a tree-sitter dependency; handles single-line and multi-line calls up
/// to 2 048 bytes in the argument span.
fn extract_router_uses(text: &str) -> Vec<RouterUseCall> {
    let mut results = Vec::new();
    let bytes = text.as_bytes();
    let pat = b".use(";
    let mut pos = 0usize;

    while pos + pat.len() <= bytes.len() {
        if bytes[pos..pos + pat.len()] == *pat {
            let router_symbol = back_scan_identifier(bytes, pos);
            if !router_symbol.is_empty() {
                let args_start = pos + pat.len(); // char immediately after '('
                if let Some(args_text) = extract_args_text(text, args_start) {
                    let args = split_top_level_args(args_text);
                    if !args.is_empty() {
                        results.push(classify_use_args(&router_symbol, &args));
                    }
                }
            }
            pos += pat.len();
        } else {
            pos += 1;
        }
    }
    results
}

/// Scan backward from `pos` (position of the `.` in `.use(`) to extract the
/// identifier that precedes it (the router / app symbol name).
fn back_scan_identifier(bytes: &[u8], pos: usize) -> String {
    if pos == 0 {
        return String::new();
    }
    let mut start = pos;
    loop {
        if start == 0 {
            break;
        }
        let b = bytes[start - 1];
        if b.is_ascii_alphanumeric() || b == b'_' || b == b'$' {
            start -= 1;
        } else {
            break;
        }
    }
    if start == pos {
        return String::new();
    }
    String::from_utf8_lossy(&bytes[start..pos]).into_owned()
}

/// Extract the raw argument text from inside `(...)` starting at `start`
/// (the char immediately after the opening `(`).
///
/// Returns `None` when the span is malformed or exceeds 2 048 bytes.
fn extract_args_text(text: &str, start: usize) -> Option<&str> {
    let bytes = text.as_bytes();
    let mut depth = 1u32;
    let mut in_str: Option<u8> = None;
    let mut i = start;

    while i < bytes.len() && i.saturating_sub(start) < 2048 {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_str = None;
            }
        } else {
            match b {
                b'(' => depth += 1,
                b')' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(&text[start..i]);
                    }
                }
                b'"' | b'\'' | b'`' => in_str = Some(b),
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                    // Skip to end of line comment.
                    while i < bytes.len() && bytes[i] != b'\n' {
                        i += 1;
                    }
                    continue;
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Split raw argument text on top-level commas.
fn split_top_level_args(text: &str) -> Vec<&str> {
    let mut args = Vec::new();
    let bytes = text.as_bytes();
    let mut depth = 0i32;
    let mut in_str: Option<u8> = None;
    let mut start = 0usize;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = in_str {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                in_str = None;
            }
        } else {
            match b {
                b'(' | b'[' | b'{' => depth += 1,
                b')' | b']' | b'}' => depth -= 1,
                b'"' | b'\'' | b'`' => in_str = Some(b),
                b',' if depth == 0 => {
                    let arg = text[start..i].trim();
                    if !arg.is_empty() {
                        args.push(arg);
                    }
                    start = i + 1;
                }
                _ => {}
            }
        }
        i += 1;
    }
    let last = text[start..].trim();
    if !last.is_empty() {
        args.push(last);
    }
    args
}

fn is_string_literal(arg: &str) -> bool {
    let s = arg.trim();
    s.len() >= 2 && (s.starts_with('"') || s.starts_with('\'') || s.starts_with('`'))
}

fn strip_string_quotes(arg: &str) -> &str {
    let s = arg.trim();
    let s = s
        .strip_prefix('"')
        .or_else(|| s.strip_prefix('\''))
        .or_else(|| s.strip_prefix('`'))
        .unwrap_or(s);
    s.strip_suffix('"')
        .or_else(|| s.strip_suffix('\''))
        .or_else(|| s.strip_suffix('`'))
        .unwrap_or(s)
}

/// Heuristic: does this identifier name represent a sub-router being mounted?
///
/// True when the lowercase name contains `"router"` or equals `"app"`.
fn looks_like_router(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("router") || lower == "app"
}

/// Parse the argument list of a `.use(...)` call into a [`RouterUseCall`].
fn classify_use_args(router_symbol: &str, args: &[&str]) -> RouterUseCall {
    let mut mount_path: Option<String> = None;
    let mut middlewares: Vec<String> = Vec::new();
    let mut child_router: Option<String> = None;

    let mut iter = args.iter().peekable();

    // Consume leading string-literal path argument.
    if let Some(&&first) = iter.peek() {
        if is_string_literal(first) {
            mount_path = Some(strip_string_quotes(first).to_string());
            iter.next();
        }
    }

    let remaining: Vec<&str> = iter.copied().collect();
    for (i, arg) in remaining.iter().enumerate() {
        let trimmed = arg.trim();
        if trimmed.is_empty() || is_string_literal(trimmed) {
            continue;
        }
        // Strip TS type assertions such as `myRouter as Router`.
        let name = trimmed
            .split_ascii_whitespace()
            .next()
            .unwrap_or(trimmed)
            .trim_matches(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '$');
        if name.is_empty() {
            continue;
        }
        // Final argument that looks like a router symbol → child being mounted.
        if i == remaining.len() - 1 && looks_like_router(name) {
            child_router = Some(name.to_string());
        } else {
            middlewares.push(name.to_string());
        }
    }

    RouterUseCall {
        router_symbol: router_symbol.to_string(),
        mount_path,
        middlewares,
        child_router,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn build(files: &[(&str, &str)]) -> RouterTopology {
        let owned: Vec<(&str, Vec<u8>)> = files
            .iter()
            .map(|(f, s)| (*f, s.as_bytes().to_vec()))
            .collect();
        let pairs: Vec<(&str, &[u8])> = owned.iter().map(|(f, s)| (*f, s.as_slice())).collect();
        build_router_topology(&pairs)
    }

    #[test]
    fn router_level_middleware_detected() {
        let topology = build(&[(
            "src/routes/teams-router.ts",
            r#"
import { Router } from 'express';
import { jiraContextSymmetricJwtAuthenticationMiddleware } from '../middleware/jira';
export const teamsRouter = Router();
teamsRouter.use(jiraContextSymmetricJwtAuthenticationMiddleware);
teamsRouter.get('/', handler);
"#,
        )]);

        let mws = topology.file_level_middlewares("src/routes/teams-router.ts");
        assert!(
            mws.contains(&"jiraContextSymmetricJwtAuthenticationMiddleware".to_string()),
            "router-level middleware must be recorded; got: {mws:?}"
        );
    }

    #[test]
    fn subrouter_mount_builds_edge() {
        let topology = build(&[(
            "src/app.ts",
            r#"
app.use('/admin/teams', adminOnly, teamsRouter);
"#,
        )]);

        // Topology should contain both `app` and `teamsRouter` as nodes.
        let mws = topology.inherited_middlewares("src/app.ts", "teamsRouter");
        // teamsRouter is the child; it does not inherit app's own middlewares
        // unless app registered them via a separate .use() call.
        // But the edge carries `adminOnly`.
        assert!(
            mws.contains(&"adminOnly".to_string()),
            "child router must inherit edge middleware `adminOnly`; got: {mws:?}"
        );
    }

    #[test]
    fn inherited_middlewares_propagates_from_parent() {
        // Two-file scenario: parent mounts child under /api.
        // Parent has a router-level auth guard.
        let topology = build(&[
            (
                "src/app.ts",
                r#"
import { apiRouter } from './api-router';
app.use(requireAuth);
app.use('/api', apiRouter);
"#,
            ),
            (
                "src/api-router.ts",
                r#"
export const apiRouter = Router();
apiRouter.get('/:id', handler);
"#,
            ),
        ]);

        // apiRouter is a child of app; app has router-level `requireAuth`.
        let mws = topology.inherited_middlewares("src/app.ts", "apiRouter");
        assert!(
            mws.contains(&"requireAuth".to_string()),
            "child must inherit parent's router-level middleware; got: {mws:?}"
        );
    }

    #[test]
    fn path_only_use_call_ignored() {
        // `app.use('/health', healthHandler)` — `healthHandler` is not a router.
        let topology = build(&[("src/app.ts", r#"app.use('/health', healthHandler);"#)]);
        // healthHandler should be recorded as a middleware on app, not as a child router.
        let mws = topology.file_level_middlewares("src/app.ts");
        assert!(
            mws.contains(&"healthHandler".to_string()),
            "non-router arg after path must be a middleware; got: {mws:?}"
        );
    }

    #[test]
    fn figma_for_jira_teams_router_pattern() {
        // Exact pattern from the `figma-for-jira` IDOR false positive.
        let source = r#"
import { HttpStatusCode } from 'axios';
import type { NextFunction, Request } from 'express';
import { Router } from 'express';
import { connectFigmaTeamUseCase, disconnectFigmaTeamUseCase, listFigmaTeamsUseCase } from '../../../../usecases';
import { jiraContextSymmetricJwtAuthenticationMiddleware } from '../../../middleware/jira';

export const teamsRouter = Router();

teamsRouter.use(jiraContextSymmetricJwtAuthenticationMiddleware);

teamsRouter.get('/', (req, res, next) => {
    listFigmaTeamsUseCase.execute(connectInstallation).then(r => res.send(r)).catch(next);
});

teamsRouter.post('/:teamId/connect', (req, res, next) => {
    connectFigmaTeamUseCase.execute(req.params.teamId, atlassianUserId, connectInstallation)
        .then(s => res.send(s)).catch(next);
});
"#;
        let topology = build(&[("src/web/routes/admin/teams/teams-router.ts", source)]);
        let mws = topology.file_level_middlewares("src/web/routes/admin/teams/teams-router.ts");
        assert!(
            mws.contains(&"jiraContextSymmetricJwtAuthenticationMiddleware".to_string()),
            "Jira JWT middleware must be captured for figma-for-jira route; got: {mws:?}"
        );
    }
}
