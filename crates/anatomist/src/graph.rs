//! # Reference Graph Builder
//!
//! Two-pass pipeline:
//! 1. **Index Pass**: Walk all `.py` files, extract entities, build `SymbolRegistry`, add nodes to graph.
//! 2. **Link Pass**: Re-parse each file for imports + call sites, add symbol-to-symbol edges.

use crate::imports::{extract_imports, resolve_import};
use crate::{AnatomistError, Entity, ParserHost};
use common::registry::{symbol_hash, SymbolEntry, SymbolRegistry};
use memmap2::Mmap;
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tree_sitter::{Node, Parser, Query, QueryCursor, StreamingIterator};
use walkdir::WalkDir;

/// Statistics about the reference graph.
#[derive(Debug, Clone, Copy, Default)]
pub struct GraphStats {
    pub symbol_count: usize,
    pub edge_count: usize,
    pub file_count: usize,
    pub parse_errors: usize,
}

/// Cross-file reference graph with symbol registry.
pub struct ReferenceGraph {
    pub registry: SymbolRegistry,
    pub graph: DiGraph<u64, ()>,
    pub file_symbols: HashMap<String, Vec<u64>>,
    /// All entities extracted across the project (populated in Pass 1).
    pub entities: Vec<Entity>,
    pub stats: GraphStats,
}

static CALL_QUERY: OnceLock<Query> = OnceLock::new();

/// A call expression extracted from Python source.
struct CallSite {
    /// The called name ("func" or "method" in `obj.method()`).
    name: String,
    /// Start byte of the captured identifier node.
    byte_offset: u32,
}

/// Extracts all call sites from a parsed Python source tree.
fn extract_calls(source: &[u8], root: Node) -> Vec<CallSite> {
    let query = CALL_QUERY.get_or_init(|| {
        Query::new(
            &tree_sitter_python::LANGUAGE.into(),
            r#"
            (call
              function: (identifier) @direct_call)

            (call
              function: (attribute
                attribute: (identifier) @attr_call))
            "#,
        )
        .expect("Invalid call query")
    });

    let mut cursor = QueryCursor::new();
    let mut matches = cursor.matches(query, root, source);
    let mut calls = Vec::new();

    while let Some(m) = matches.next() {
        for capture in m.captures {
            let node = capture.node;
            let text = match node.utf8_text(source) {
                Ok(t) => t.to_string(),
                Err(_) => continue,
            };
            calls.push(CallSite {
                name: text,
                byte_offset: node.start_byte() as u32,
            });
        }
    }

    calls
}

/// Finds the innermost entity containing `byte_offset`.
///
/// `entries` is `(symbol_id, start_byte, end_byte)` for all entities in the source file.
/// Returns the entry with the smallest span enclosing the offset.
/// With a `__MODULE__` sentinel entry covering the whole file, this always returns `Some`.
fn find_containing_entity(byte_offset: u32, entries: &[(u64, u32, u32)]) -> Option<u64> {
    entries
        .iter()
        .filter(|(_, start, end)| *start <= byte_offset && byte_offset < *end)
        .min_by_key(|(_, start, end)| end - start)
        .map(|(id, _, _)| *id)
}

/// Builds a reference graph from a Python project directory.
///
/// # Algorithm
/// 1. Walk directory for `.py` files (skips `__pycache__`, `.git`, etc.)
/// 2. **Pass 1**: Extract entities from each file, populate registry, add graph nodes.
///    Also inserts a `__MODULE__` sentinel node per file for module-level call attribution.
/// 3. **Pass 2**: Re-parse for imports + call sites, resolve paths, add symbol-to-symbol edges.
///
/// # Memory
/// - Registry stores all symbols (~80 bytes per symbol)
/// - Graph stores node indices (8 bytes per node) + edges (~16 bytes per edge)
/// - Per-file `Vec<Entity>` is dropped after indexing
pub fn build_reference_graph(
    project_root: &Path,
    host: &mut ParserHost,
) -> Result<ReferenceGraph, AnatomistError> {
    let root = dunce::canonicalize(project_root)?;
    let py_files = walk_py_files(&root)?;

    let mut registry = SymbolRegistry::new();
    let mut graph = DiGraph::new();
    let mut file_symbols: HashMap<String, Vec<u64>> = HashMap::new();
    let mut id_to_node: HashMap<u64, NodeIndex> = HashMap::new();
    let mut all_entities: Vec<Entity> = Vec::new();
    let mut stats = GraphStats {
        file_count: py_files.len(),
        ..Default::default()
    };

    // PASS 1: Index symbols
    for path in &py_files {
        match host.dissect(path) {
            Ok(entities) => {
                // Compute canonical file key for __MODULE__ sentinel
                let canonical = dunce::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
                let file_key = normalize_path(&canonical);
                let file_size = std::fs::metadata(path)
                    .map(|m| m.len().min(u32::MAX as u64) as u32)
                    .unwrap_or(0);

                // Insert __MODULE__ virtual entry covering the entire file.
                // Module-level calls (outside any func/class) are attributed to this symbol.
                let module_sym_id = format!("{}::__MODULE__", file_key);
                let module_hash = symbol_hash(&module_sym_id);
                registry.insert(SymbolEntry {
                    id: module_hash,
                    name: "__MODULE__".to_string(),
                    qualified_name: "__MODULE__".to_string(),
                    file_path: file_key.clone(),
                    entity_type: 0,
                    start_line: 1,
                    end_line: 0,
                    start_byte: 0,
                    end_byte: file_size,
                    structural_hash: 0,
                    protected_by: None,
                });
                let module_node = graph.add_node(module_hash);
                id_to_node.insert(module_hash, module_node);
                file_symbols.entry(file_key).or_default().push(module_hash);

                for entity in entities {
                    let symbol_id = entity.symbol_id();
                    let hash = symbol_hash(&symbol_id);

                    let entry = SymbolEntry {
                        id: hash,
                        name: entity.name.clone(),
                        qualified_name: entity.qualified_name.clone(),
                        file_path: entity.file_path.clone(),
                        entity_type: entity.entity_type as u8,
                        start_line: entity.start_line,
                        end_line: entity.end_line,
                        start_byte: entity.start_byte,
                        end_byte: entity.end_byte,
                        structural_hash: entity.structural_hash.unwrap_or(0),
                        protected_by: entity.protected_by,
                    };
                    registry.insert(entry);

                    let node_idx = graph.add_node(hash);
                    id_to_node.insert(hash, node_idx);

                    file_symbols
                        .entry(entity.file_path.clone())
                        .or_default()
                        .push(hash);

                    all_entities.push(entity);
                    stats.symbol_count += 1;
                }
            }
            Err(_) => {
                stats.parse_errors += 1;
            }
        }
    }

    // Build lookup: file_path -> [(name, id)]
    let mut file_to_names: HashMap<String, Vec<(String, u64)>> = HashMap::new();
    for entry in &registry.entries {
        file_to_names
            .entry(entry.file_path.clone())
            .or_default()
            .push((entry.name.clone(), entry.id));
    }

    // PASS 2: Link imports via call sites (symbol-to-symbol edges)
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_python::LANGUAGE.into())
        .map_err(|e| AnatomistError::ParseFailure(format!("Language load failed: {:?}", e)))?;

    for source_path in &py_files {
        let file = match File::open(source_path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => continue,
        };
        let source = &mmap[..];

        let tree = match parser.parse(source, None) {
            Some(t) => t,
            None => continue,
        };

        let imports = match extract_imports(source, tree.root_node()) {
            Ok(imp) => imp,
            Err(_) => continue,
        };

        let source_canonical = match dunce::canonicalize(source_path) {
            Ok(p) => p,
            Err(_) => continue,
        };
        let source_file_key = normalize_path(&source_canonical);

        // Build import_targets: name -> [target_symbol_id]
        let mut import_targets: HashMap<String, Vec<u64>> = HashMap::new();
        for import in &imports {
            let target_path = match resolve_import(&source_canonical, &import.raw_path, &root) {
                Some(p) => p,
                None => continue,
            };
            let target_file_key = normalize_path(&target_path);
            let target_names = match file_to_names.get(&target_file_key) {
                Some(names) => names,
                None => continue,
            };
            for (name, id) in target_names {
                if import.names.is_empty() || import.names.contains(name) {
                    import_targets.entry(name.clone()).or_default().push(*id);
                }
            }
        }

        if import_targets.is_empty() {
            continue;
        }

        // Build source_entries: (symbol_id, start_byte, end_byte) for containment lookup
        let source_entries: Vec<(u64, u32, u32)> = registry
            .entries
            .iter()
            .filter(|e| e.file_path == source_file_key)
            .map(|e| (e.id, e.start_byte, e.end_byte))
            .collect();

        // Extract call sites and emit directed edges
        let calls = extract_calls(source, tree.root_node());
        for call in calls {
            let target_ids = match import_targets.get(&call.name) {
                Some(ids) => ids,
                None => continue,
            };
            let caller_id = match find_containing_entity(call.byte_offset, &source_entries) {
                Some(id) => id,
                None => continue,
            };
            let src_node = match id_to_node.get(&caller_id) {
                Some(&n) => n,
                None => continue,
            };
            for &target_id in target_ids {
                if let Some(&tgt_node) = id_to_node.get(&target_id) {
                    graph.add_edge(src_node, tgt_node, ());
                    stats.edge_count += 1;
                }
            }
        }
    }

    Ok(ReferenceGraph {
        registry,
        graph,
        file_symbols,
        entities: all_entities,
        stats,
    })
}

/// Walks a directory for `.py` files, skipping excluded directories.
fn walk_py_files(root: &Path) -> Result<Vec<PathBuf>, AnatomistError> {
    let mut files = Vec::new();

    for entry in WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| !is_excluded(e.path()))
    {
        let entry = entry.map_err(|e| AnatomistError::IoError(e.into()))?;
        let path = entry.path();
        if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("py") {
            files.push(path.to_path_buf());
        }
    }

    Ok(files)
}

/// Returns `true` if the path should be excluded from walking.
fn is_excluded(path: &Path) -> bool {
    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
        matches!(
            name,
            "__pycache__"
                | ".git"
                | ".janitor"
                | "venv"
                | ".venv"
                | "target"
                | "node_modules"
                | ".pytest_cache"
        )
    } else {
        false
    }
}

/// Normalizes a path for use as a HashMap key.
///
/// Converts to UTF-8 string with forward slashes, stripping UNC prefix on Windows.
fn normalize_path(path: &Path) -> String {
    dunce::simplified(path).to_string_lossy().replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_empty_directory() {
        let tmp = std::env::temp_dir().join("test_graph_empty");
        fs::create_dir_all(&tmp).ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 0);
        assert_eq!(graph.stats.symbol_count, 0);

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_single_file() {
        let tmp = std::env::temp_dir().join("test_graph_single");
        fs::create_dir_all(&tmp).ok();
        let test_py = tmp.join("test.py");
        fs::write(&test_py, "def foo():\n    pass\n").ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 1);
        assert!(graph.stats.symbol_count >= 1);

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_two_file_import_edge() {
        let tmp = std::env::temp_dir().join("test_graph_import");
        fs::create_dir_all(&tmp).ok();

        let mod_a = tmp.join("mod_a.py");
        fs::write(&mod_a, "def helper():\n    pass\n").ok();

        // main() calls helper() — must produce edge main → helper
        let mod_b = tmp.join("mod_b.py");
        fs::write(
            &mod_b,
            "from mod_a import helper\n\ndef main():\n    helper()\n",
        )
        .ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 2);
        assert_eq!(
            graph.stats.edge_count, 1,
            "expected exactly 1 edge: main → helper"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_relative_import_edge() {
        let tmp = std::env::temp_dir().join("test_graph_relative");
        fs::create_dir_all(tmp.join("pkg")).ok();

        let utils = tmp.join("pkg/utils.py");
        fs::write(&utils, "def util():\n    pass\n").ok();

        // run() calls util() — must produce edge run → util
        let main = tmp.join("pkg/main.py");
        fs::write(&main, "from .utils import util\n\ndef run():\n    util()\n").ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 2);
        assert_eq!(
            graph.stats.edge_count, 1,
            "expected exactly 1 edge: run → util"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_attribute_call_edge() {
        let tmp = std::env::temp_dir().join("test_graph_attr_call");
        fs::create_dir_all(&tmp).ok();

        // utils.py defines process()
        let utils = tmp.join("utils.py");
        fs::write(&utils, "def process():\n    pass\n").ok();

        // main.py: bare import, run() calls utils.process()
        let main = tmp.join("main.py");
        fs::write(&main, "import utils\n\ndef run():\n    utils.process()\n").ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 2);
        assert_eq!(
            graph.stats.edge_count, 1,
            "expected exactly 1 edge: run → process"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_no_edge_without_call() {
        let tmp = std::env::temp_dir().join("test_graph_no_call");
        fs::create_dir_all(&tmp).ok();

        let utils = tmp.join("utils.py");
        fs::write(&utils, "def func():\n    pass\n").ok();

        // main.py imports but never calls func()
        let main = tmp.join("main.py");
        fs::write(&main, "from utils import func\n\ndef run():\n    pass\n").ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 2);
        assert_eq!(
            graph.stats.edge_count, 0,
            "expected 0 edges: import without call"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_skips_pycache() {
        let tmp = std::env::temp_dir().join("test_graph_skip");
        fs::create_dir_all(tmp.join("__pycache__")).ok();
        let cached = tmp.join("__pycache__/test.pyc");
        fs::write(&cached, b"").ok();

        let test_py = tmp.join("test.py");
        fs::write(&test_py, "def foo():\n    pass\n").ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 1); // Only test.py, not .pyc

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_handles_parse_error_gracefully() {
        let tmp = std::env::temp_dir().join("test_graph_error");
        fs::create_dir_all(&tmp).ok();

        let bad_py = tmp.join("bad.py");
        fs::write(&bad_py, "def foo(\n").ok(); // Syntax error

        let good_py = tmp.join("good.py");
        fs::write(&good_py, "def bar():\n    pass\n").ok();

        let mut host = ParserHost::new().unwrap();
        let result = build_reference_graph(&tmp, &mut host);

        assert!(result.is_ok());
        let graph = result.unwrap();
        assert_eq!(graph.stats.file_count, 2);
        // Parse errors are tracked, but don't fail the whole operation
        assert!(graph.stats.symbol_count >= 1); // At least 'bar' from good.py

        fs::remove_dir_all(tmp).ok();
    }
}
