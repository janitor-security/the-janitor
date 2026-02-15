//! 6-stage dead symbol detection pipeline ("The Funnel of Truth").
//!
//! Stages:
//! - **Stage 0** — Directory filter: skip files in protected directories.
//! - **Stage 1** — Reference graph: symbols with incoming edges survive.
//! - **Stage 2+4** — Wisdom + PackageExport: single mmap pass per file via [`wisdom`].
//! - **Stage 3** — Library mode: protect public symbols when `--library` is set.
//! - **Stage 5** — Grep shield: Aho-Corasick scan of non-`.py` files via [`scan`].
//!
//! Only symbols that pass through all five stages without acquiring a `protected_by`
//! reason are reported as dead.

use crate::graph::build_reference_graph;
use crate::parser::ParserHost;
use crate::{scan, wisdom, Entity, Protection};
use common::registry::symbol_hash;
use petgraph::Direction;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Results of a full pipeline run.
#[derive(Debug, Default)]
pub struct ScanResult {
    /// Symbols with no protection and no references — candidates for deletion.
    pub dead: Vec<Entity>,
    /// Symbols that survived at least one stage (with `protected_by` set).
    pub protected: Vec<Entity>,
    /// Total entities examined.
    pub total: usize,
    /// Per-stage survivor counts: `stage_counts[n]` = entities protected at stage n.
    /// Index 0 = directory, 1 = reference, 2 = wisdom/pkg-export, 3 = library, 5 = grep.
    pub stage_counts: [usize; 6],
}

/// Directory name segments that indicate protected/test/example code (Stage 0).
const PROTECTED_DIRS: &[&str] = &[
    "tests",
    "test",
    "examples",
    "example",
    "docs_src",
    "docs",
    "sandbox",
    "bin",
    "scripts",
    "tutorial",
    "benchmarks",
    "fixtures",
    "migrations",
];

/// Runs the full 6-stage dead symbol detection pipeline against a project directory.
///
/// # Arguments
/// - `project_root`: Root directory of the Python project.
/// - `host`: Configured `ParserHost` (with heuristics registered).
/// - `library_mode`: When `true`, Stage 3 protects all public symbols.
///
/// # Returns
/// A [`ScanResult`] containing the dead and protected entity lists.
///
/// # Errors
/// Propagates I/O and parse errors from the reference graph build step.
pub fn run(
    project_root: &Path,
    host: &mut ParserHost,
    library_mode: bool,
) -> anyhow::Result<ScanResult> {
    let root = dunce::canonicalize(project_root)?;

    // Build cross-file reference graph (Pass 1: index, Pass 2: link edges).
    let ref_graph = build_reference_graph(&root, host)?;

    let mut result = ScanResult {
        total: ref_graph.entities.len(),
        ..Default::default()
    };

    // Stage 1 prep: collect symbol hashes with at least one incoming edge.
    let referenced_ids: HashSet<u64> = ref_graph
        .graph
        .node_indices()
        .filter(|&n| {
            ref_graph
                .graph
                .edges_directed(n, Direction::Incoming)
                .count()
                > 0
        })
        .filter_map(|n| ref_graph.graph.node_weight(n))
        .copied()
        .collect();

    // Group entities by file for the wisdom pass (Stage 2+4).
    let mut file_groups: HashMap<String, Vec<Entity>> = HashMap::new();
    for entity in ref_graph.entities {
        file_groups
            .entry(entity.file_path.clone())
            .or_default()
            .push(entity);
    }

    // Per-file stage loop (Stages 0 → 1 → 2+4 → 3).
    let mut candidates: Vec<Entity> = Vec::new();

    for (file_path, entities) in file_groups {
        // Stage 0: Directory filter.
        if is_protected_path(&file_path) {
            for mut e in entities {
                e.protected_by = Some(Protection::Directory);
                result.stage_counts[0] += 1;
                result.protected.push(e);
            }
            continue;
        }

        // Stage 1: Reference check (cross-file edges in the graph).
        let mut still_dead: Vec<Entity> = Vec::new();
        for mut entity in entities {
            if entity.protected_by.is_some() {
                // Protected by parser heuristic (e.g., PytestFixture).
                result.protected.push(entity);
                continue;
            }

            let sym_id = entity.symbol_id();
            let hash = symbol_hash(&sym_id);
            if referenced_ids.contains(&hash) {
                entity.protected_by = Some(Protection::Referenced);
                result.stage_counts[1] += 1;
                result.protected.push(entity);
            } else {
                still_dead.push(entity);
            }
        }

        if still_dead.is_empty() {
            continue;
        }

        // Stage 2+4: Wisdom + PackageExport (single mmap pass per file).
        match std::fs::read(&file_path) {
            Ok(source) => {
                wisdom::classify(&mut still_dead, &source, &file_path);
            }
            Err(_) => {
                // Cannot read file — leave entities in still_dead for later stages.
            }
        }

        for mut entity in still_dead {
            if entity.protected_by.is_some() {
                result.stage_counts[2] += 1;
                result.protected.push(entity);
            } else if library_mode && entity.parent_class.is_none() && !entity.is_private() {
                // Stage 3: Library mode — protect all public top-level symbols.
                entity.protected_by = Some(Protection::LibraryMode);
                result.stage_counts[3] += 1;
                result.protected.push(entity);
            } else {
                candidates.push(entity);
            }
        }
    }

    if candidates.is_empty() {
        result.dead = candidates;
        return Ok(result);
    }

    // Stage 5: Grep Shield — only for symbols still dead after stages 0-4.
    let dead_names: Vec<String> = candidates.iter().map(|e| e.name.clone()).collect();
    let grep_found = scan::grep_shield(&dead_names, &root)?;

    for mut entity in candidates {
        if grep_found.contains(&entity.name) {
            entity.protected_by = Some(Protection::GrepShield);
            result.stage_counts[5] += 1;
            result.protected.push(entity);
        } else {
            result.dead.push(entity);
        }
    }

    Ok(result)
}

/// Returns `true` if any path segment matches a protected directory name.
fn is_protected_path(file_path: &str) -> bool {
    file_path
        .split('/')
        .any(|seg| PROTECTED_DIRS.contains(&seg))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_host() -> ParserHost {
        let mut host = ParserHost::new().unwrap();
        host.register_heuristic(Box::new(crate::heuristics::pytest::PytestFixtureHeuristic));
        host
    }

    #[test]
    fn test_empty_project() {
        let tmp = std::env::temp_dir().join("test_pipeline_empty");
        fs::create_dir_all(&tmp).ok();

        let mut host = make_host();
        let result = run(&tmp, &mut host, false).unwrap();
        assert_eq!(result.total, 0);
        assert!(result.dead.is_empty());

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_referenced_symbol_survives() {
        let tmp = std::env::temp_dir().join("test_pipeline_ref");
        fs::create_dir_all(&tmp).ok();

        fs::write(tmp.join("utils.py"), b"def helper():\n    pass\n").ok();
        fs::write(
            tmp.join("main.py"),
            b"from utils import helper\ndef run():\n    helper()\n",
        )
        .ok();

        let mut host = make_host();
        let result = run(&tmp, &mut host, false).unwrap();

        // `helper` is called by `run`, so it is referenced — not dead.
        assert!(!result.dead.iter().any(|e| e.name == "helper"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_unreferenced_symbol_is_dead() {
        let tmp = std::env::temp_dir().join("test_pipeline_dead");
        fs::create_dir_all(&tmp).ok();

        fs::write(tmp.join("utils.py"), b"def dead_code():\n    pass\n").ok();
        fs::write(tmp.join("main.py"), b"# nothing uses utils\n").ok();

        let mut host = make_host();
        let result = run(&tmp, &mut host, false).unwrap();

        assert!(result.dead.iter().any(|e| e.name == "dead_code"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_dunder_protected() {
        let tmp = std::env::temp_dir().join("test_pipeline_dunder");
        fs::create_dir_all(&tmp).ok();

        fs::write(
            tmp.join("model.py"),
            b"class Foo:\n    def __init__(self):\n        pass\n",
        )
        .ok();

        let mut host = make_host();
        let result = run(&tmp, &mut host, false).unwrap();

        assert!(!result.dead.iter().any(|e| e.name == "__init__"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_library_mode_protects_public() {
        let tmp = std::env::temp_dir().join("test_pipeline_lib");
        fs::create_dir_all(&tmp).ok();

        fs::write(
            tmp.join("api.py"),
            b"def public_fn():\n    pass\ndef _private():\n    pass\n",
        )
        .ok();

        let mut host = make_host();
        let result = run(&tmp, &mut host, true).unwrap();

        assert!(!result.dead.iter().any(|e| e.name == "public_fn"));
        // _private is still a candidate (private even in library mode)
        // it may or may not be dead depending on other stages
        let _ = result; // just check it compiles and runs
        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_protected_dir_skipped() {
        let tmp = std::env::temp_dir().join("test_pipeline_dir");
        fs::create_dir_all(tmp.join("tests")).ok();

        fs::write(
            tmp.join("tests/test_foo.py"),
            b"def test_something():\n    pass\n",
        )
        .ok();

        let mut host = make_host();
        let result = run(&tmp, &mut host, false).unwrap();

        // All symbols in tests/ should be Directory-protected, not dead.
        assert!(result.dead.is_empty());

        fs::remove_dir_all(tmp).ok();
    }
}
