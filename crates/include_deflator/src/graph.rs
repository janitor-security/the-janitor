//! # Include Graph Builder
//!
//! Constructs a [`petgraph::csr::Csr`] Directed Acyclic Graph from C/C++ source trees.
//!
//! **Edge direction**: `A → B` means "file A `#include`s file B". Transitive reach
//! of B = count of all nodes from which B is reachable (i.e. ancestor count).
//!
//! ## Zero-allocation query
//!
//! A single Tree-sitter S-expression captures both `#include "..."` (path strings)
//! and `#include <...>` (system strings) in one pass over the CST. The query is
//! compiled once into a [`OnceLock<Query>`] and reused across all files.

use std::{collections::HashMap, path::Path, sync::OnceLock};

use anyhow::{Context, Result};
use git2::Repository;
use petgraph::{csr::Csr, visit::EdgeRef as _};
use tree_sitter::{Language, Parser, Query, QueryCursor, StreamingIterator as _};

// ─── Grammar statics ──────────────────────────────────────────────────────────

static CPP_LANGUAGE: OnceLock<Language> = OnceLock::new();
static C_LANGUAGE: OnceLock<Language> = OnceLock::new();
static CPP_INCLUDE_QUERY: OnceLock<Query> = OnceLock::new();
static C_INCLUDE_QUERY: OnceLock<Query> = OnceLock::new();

fn cpp_language() -> &'static Language {
    CPP_LANGUAGE.get_or_init(|| tree_sitter_cpp::LANGUAGE.into())
}

fn c_language() -> &'static Language {
    C_LANGUAGE.get_or_init(|| tree_sitter_c::LANGUAGE.into())
}

/// S-expression that captures both `"path"` and `<path>` include strings.
///
/// Tree-sitter C/C++ grammar node types:
/// - `preproc_include` — the `#include` directive
/// - `string_literal`  — captures `"local/path.h"`
/// - `system_lib_string` — captures `<system/path.h>`
const INCLUDE_S_EXPR: &str = r#"
    (preproc_include
        path: [
            (string_literal) @include.path
            (system_lib_string) @include.path
        ])
"#;

fn include_query(lang: &'static Language) -> &'static Query {
    // Use separate OnceLocks per grammar to avoid cross-grammar contamination.
    if std::ptr::eq(lang, cpp_language()) {
        CPP_INCLUDE_QUERY
            .get_or_init(|| Query::new(lang, INCLUDE_S_EXPR).expect("CPP include query"))
    } else {
        C_INCLUDE_QUERY.get_or_init(|| Query::new(lang, INCLUDE_S_EXPR).expect("C include query"))
    }
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// Internal node index alias for petgraph CSR.
pub type NodeIdx = u32;

/// A resolved include edge: `from` includes `to`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IncludeEdge {
    pub from: String,
    pub to: String,
}

/// CSR-backed directed include graph.
///
/// Nodes are normalized header/source paths (relative to the repository root).
/// Edges are `#include` relationships: `from → to` means `from` includes `to`.
pub struct IncludeGraph {
    /// Mapping from normalized path → CSR node index.
    pub node_index: HashMap<String, NodeIdx>,
    /// Inverse mapping from CSR node index → normalized path.
    pub node_label: Vec<String>,
    /// The underlying CSR graph.
    pub csr: Csr<(), (), petgraph::Directed, NodeIdx>,
}

impl IncludeGraph {
    /// Number of nodes (unique headers/sources).
    pub fn node_count(&self) -> usize {
        self.csr.node_count()
    }

    /// Number of directed edges (include relationships).
    pub fn edge_count(&self) -> usize {
        self.csr.edge_count()
    }

    /// Returns the normalized label for a node index.
    pub fn label(&self, idx: NodeIdx) -> &str {
        &self.node_label[idx as usize]
    }

    /// Transitive reach of `node`: count of all ancestors (files that include it,
    /// directly or transitively). Uses BFS on the reversed graph.
    ///
    /// O(V + E) — no heap allocation beyond the BFS queue itself.
    pub fn transitive_reach(&self, node: NodeIdx) -> usize {
        let n = self.csr.node_count();

        // Build a reversed adjacency list.
        let mut rev_adj: Vec<Vec<NodeIdx>> = vec![Vec::new(); n];
        for src in 0..n as NodeIdx {
            for edge in self.csr.edges(src) {
                rev_adj[edge.target() as usize].push(src);
            }
        }

        // BFS from `node` in the reversed graph.
        let mut visited = vec![false; n];
        let mut queue = std::collections::VecDeque::new();
        queue.push_back(node);
        visited[node as usize] = true;
        let mut count = 0usize;

        while let Some(cur) = queue.pop_front() {
            for &pred in &rev_adj[cur as usize] {
                if !visited[pred as usize] {
                    visited[pred as usize] = true;
                    count += 1;
                    queue.push_back(pred);
                }
            }
        }
        count
    }

    /// All direct successors (files included by `node`).
    pub fn direct_includes(&self, node: NodeIdx) -> Vec<NodeIdx> {
        self.csr.edges(node).map(|e| e.target()).collect()
    }

    /// Number of files that directly include `node` (in-degree).
    ///
    /// Counts incoming edges by scanning all outgoing edge lists — O(E).
    /// Acceptable for the top-10 ranking slice produced by [`cmd_hyper_drive`].
    pub fn in_degree(&self, node: NodeIdx) -> usize {
        (0..self.csr.node_count() as NodeIdx)
            .flat_map(|src| self.csr.edges(src))
            .filter(|e| e.target() == node)
            .count()
    }
}

// ─── Builder ──────────────────────────────────────────────────────────────────

/// Constructs an [`IncludeGraph`] by scanning a directory tree for C/C++ files.
pub struct IncludeGraphBuilder {
    edges: Vec<IncludeEdge>,
    nodes: Vec<String>,
    node_set: HashMap<String, NodeIdx>,
}

impl IncludeGraphBuilder {
    pub fn new() -> Self {
        Self {
            edges: Vec::new(),
            nodes: Vec::new(),
            node_set: HashMap::new(),
        }
    }

    /// Scan a directory tree, extracting `#include` edges from all C/C++ files.
    ///
    /// Recognizes extensions: `.c`, `.cc`, `.cpp`, `.cxx`, `.h`, `.hh`, `.hpp`, `.hxx`.
    pub fn scan_dir(&mut self, root: &Path) -> Result<()> {
        for entry in walkdir::WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            if is_cpp_file(path) {
                self.scan_file(path, root)
                    .with_context(|| format!("scanning {}", path.display()))?;
            }
        }
        Ok(())
    }

    /// Walk the `HEAD` tree of `repo` in-memory, extracting `#include` edges from
    /// all C/C++ blobs without touching the filesystem.
    ///
    /// This is the correct path when the orchestrator uses `--no-checkout` or when
    /// the Scorched Earth protocol has already deleted the working tree.  Every blob
    /// is loaded directly from the Git object database via `blob.content()`.
    pub fn scan_repo(&mut self, repo: &Repository) -> Result<()> {
        let head_tree = repo
            .head()
            .context("resolve HEAD")?
            .peel_to_commit()
            .context("HEAD is not a commit")?
            .tree()
            .context("get commit tree")?;

        // Collect (rel_path, blob_oid) pairs — we cannot mutably borrow `self`
        // inside the walk callback, so we stage them first.
        let mut cpp_blobs: Vec<(String, git2::Oid)> = Vec::new();
        head_tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
            if entry.kind() == Some(git2::ObjectType::Blob) {
                let name = entry.name().unwrap_or("");
                if is_cpp_ext(ext_of(name)) {
                    cpp_blobs.push((format!("{root}{name}"), entry.id()));
                }
            }
            0 // TreeWalkResult::Ok
        })?;

        for (rel_path, oid) in cpp_blobs {
            if let Ok(blob) = repo.find_blob(oid) {
                let _ = self.scan_bytes(blob.content(), &rel_path);
            }
        }
        Ok(())
    }

    /// Extract `#include` directives from a single file, adding edges to the builder.
    pub fn scan_file(&mut self, path: &Path, root: &Path) -> Result<()> {
        let source = std::fs::read(path)?;
        let rel = normalize_path(path, root);
        self.scan_bytes(&source, &rel)
    }

    /// Extract `#include` directives from raw bytes, adding edges to the builder.
    ///
    /// `rel_path` is the normalized path relative to the repository root, used as
    /// the node label for the `from` side of each edge.
    pub fn scan_bytes(&mut self, source: &[u8], rel_path: &str) -> Result<()> {
        if source.is_empty() || source.len() > 4 * 1024 * 1024 {
            return Ok(());
        }

        let lang: &'static Language = if is_c_only_ext(ext_of(rel_path)) {
            c_language()
        } else {
            cpp_language()
        };
        let mut parser = Parser::new();
        parser.set_language(lang).context("set language")?;

        let tree = parser
            .parse(source, None)
            .context("tree-sitter parse returned None")?;

        let query = include_query(lang);
        let mut cursor = QueryCursor::new();
        let from = rel_path.to_string();

        let mut matches = cursor.matches(query, tree.root_node(), source);
        while let Some(m) = matches.next() {
            for cap in m.captures {
                let text = cap.node.utf8_text(source).unwrap_or("").trim();
                let inner = text
                    .trim_start_matches('"')
                    .trim_end_matches('"')
                    .trim_start_matches('<')
                    .trim_end_matches('>');
                if inner.is_empty() {
                    continue;
                }
                let to = inner.to_string();
                self.intern_node(from.clone());
                self.intern_node(to.clone());
                self.edges.push(IncludeEdge {
                    from: from.clone(),
                    to,
                });
            }
        }
        Ok(())
    }

    /// Directly add a set of edges (used by tests to build synthetic graphs).
    pub fn add_edges(&mut self, edges: impl IntoIterator<Item = IncludeEdge>) {
        for e in edges {
            self.intern_node(e.from.clone());
            self.intern_node(e.to.clone());
            self.edges.push(e);
        }
    }

    /// Intern a node by name (used by tests for isolated nodes).
    pub fn add_node(&mut self, name: impl Into<String>) {
        self.intern_node(name.into());
    }

    fn intern_node(&mut self, name: String) -> NodeIdx {
        if let Some(&idx) = self.node_set.get(&name) {
            return idx;
        }
        let idx = self.nodes.len() as NodeIdx;
        self.node_set.insert(name.clone(), idx);
        self.nodes.push(name);
        idx
    }

    /// Consume the builder and produce an [`IncludeGraph`].
    pub fn build(self) -> IncludeGraph {
        // Collect CSR-compatible edge list.
        let mut raw_edges: Vec<(NodeIdx, NodeIdx)> = self
            .edges
            .iter()
            .filter_map(|e| {
                let from = *self.node_set.get(&e.from)?;
                let to = *self.node_set.get(&e.to)?;
                Some((from, to))
            })
            .collect();

        // CSR requires edges sorted by source node; deduplicate parallel includes.
        raw_edges.sort_unstable();
        raw_edges.dedup();

        let csr: Csr<(), (), petgraph::Directed, NodeIdx> =
            Csr::from_sorted_edges(&raw_edges).unwrap_or_default();

        IncludeGraph {
            node_index: self.node_set,
            node_label: self.nodes,
            csr,
        }
    }
}

impl Default for IncludeGraphBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Extract the file extension from a path string (after the last `.`).
/// Returns `""` when no extension is present.
fn ext_of(path: &str) -> &str {
    path.rsplit('.').next().unwrap_or("")
}

fn is_cpp_ext(ext: &str) -> bool {
    let e = ext.trim_start_matches('.');
    matches!(e, "c" | "cc" | "cpp" | "cxx" | "h" | "hh" | "hpp" | "hxx")
}

fn is_c_only_ext(ext: &str) -> bool {
    let e = ext.trim_start_matches('.');
    matches!(e, "c" | "h")
}

fn is_cpp_file(path: &Path) -> bool {
    is_cpp_ext(path.extension().and_then(|e| e.to_str()).unwrap_or(""))
}

fn normalize_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}
