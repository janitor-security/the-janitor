//! Stage 5: Grep Shield — multi-file Aho-Corasick scan for dead symbol names.
//!
//! Scans non-Python files (HTML, JS, JSON, YAML, TOML, Markdown, etc.) for
//! any of the given symbol names. Only symbols still dead after stages 0-4
//! are passed to this stage, so the automaton is typically small.
//!
//! **Memory model**: one mmap per file, zero heap allocation per match.
//! **Time complexity**: O(patterns·len + file_sizes) — single pass per file.

use aho_corasick::{AhoCorasick, MatchKind};
use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use walkdir::WalkDir;

/// File extensions to scan for string references to Python symbols.
///
/// Excludes `.py` files — those are already covered by the reference graph.
const GREP_EXTENSIONS: &[&str] = &[
    // Web
    "html", "htm", "css", "scss", "js", "jsx", "ts", "tsx", "vue", "svelte", // Config
    "xml", "yaml", "yml", "toml", "json", "ini", "cfg", "env", "conf", // Templates
    "jinja", "j2", "mako", // Docs / Scripts
    "md", "rst", "txt", "sh", "bash",
];

/// Scans non-Python project files for occurrences of the given symbol names.
///
/// Builds a single Aho-Corasick automaton from `dead_names` and runs it over
/// every matching file in the project tree via `mmap`. Returns the subset of
/// names that were found.
///
/// Returns an empty set immediately if `dead_names` is empty (no automaton built).
///
/// # Errors
/// Returns an `anyhow::Error` only if automaton construction fails (malformed patterns).
/// Individual file I/O errors are silently skipped.
pub fn grep_shield(dead_names: &[&str], project_root: &Path) -> anyhow::Result<HashSet<String>> {
    if dead_names.is_empty() {
        return Ok(HashSet::new());
    }

    // Build automaton once — O(sum of name lengths).
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(dead_names)
        .map_err(|e| anyhow::anyhow!("AhoCorasick build failed: {}", e))?;

    let mut found: HashSet<String> = HashSet::new();

    for entry in WalkDir::new(project_root)
        .into_iter()
        .filter_entry(|e| !is_scan_excluded(e.path()))
        .flatten()
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let ext = path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if !GREP_EXTENSIONS.contains(&ext) {
            continue;
        }

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        // SAFETY: mmap is read-only; the file handle outlives the mmap.
        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => continue,
        };

        for mat in ac.find_iter(&*mmap) {
            found.insert(dead_names[mat.pattern().as_usize()].to_string());
        }

        // Early exit: all symbols accounted for.
        if found.len() == dead_names.len() {
            break;
        }
    }

    Ok(found)
}

/// Returns `true` if the path should be excluded from grep scanning.
///
/// Used by both the grep shield (`scan.rs`) and the bridge extractor (`bridge.rs`).
pub(crate) fn is_scan_excluded(path: &Path) -> bool {
    path.file_name()
        .and_then(|s| s.to_str())
        .map(|name| {
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
                    | "site"
                    | "dist"
                    | "build"
            )
        })
        .unwrap_or(false)
}

/// Cross-file Rust reference shield (Stage 5.5).
///
/// Supplements the regular grep shield for Rust symbols. The main `grep_shield`
/// does not scan `.rs` files because doing so would trivially find every symbol
/// in its own definition, falsely protecting all Rust code from dead-code analysis.
///
/// This function is **file-path-aware**: for each candidate defined in file F,
/// only occurrences found in files *other than* F count as live cross-file
/// references. Occurrences inside the definition file are skipped.
///
/// Catches all forms of Rust cross-file usage in one linear scan:
/// - Function calls: `simulate_merge(repo, base, head)`
/// - Qualified path calls: `shadow_git::simulate_merge(...)`
/// - Struct instantiations: `MergeSnapshot { ... }`, `MergeSnapshot::new()`
/// - `use` imports: `use crate::shadow_git::simulate_merge;`
/// - Type annotations: `fn foo(s: MergeSnapshot) -> ...`
///
/// # Arguments
/// - `candidates`: `(name, definition_file_path)` pairs — Rust symbols not yet
///   protected by the regular grep shield. Paths must be the same canonicalised
///   form used in `entity.file_path` (i.e. from `dunce::canonicalize`).
/// - `project_root`: Canonicalised project root.
///
/// # Errors
/// Returns an error only if automaton construction fails (malformed names).
/// Individual file I/O errors are silently skipped.
pub fn rust_cross_file_shield(
    candidates: &[(&str, &str)],
    project_root: &Path,
) -> anyhow::Result<HashSet<String>> {
    if candidates.is_empty() {
        return Ok(HashSet::new());
    }

    let names: Vec<&str> = candidates.iter().map(|(n, _)| *n).collect();
    let mut found: HashSet<String> = HashSet::new();

    // Phase 0: Heuristic protection for Rust test and benchmark functions.
    //
    // Functions annotated with `#[test]` or `#[bench]` are invoked by the Cargo
    // test/bench harness via attribute discovery — they have no static callers in
    // source and are never truly dead code. The conventional `test_` / `bench_`
    // prefix covers virtually all real-world Rust test suites.
    for name in &names {
        if name.starts_with("test_") || name.starts_with("bench_") {
            found.insert(name.to_string());
        }
    }

    if found.len() == candidates.len() {
        return Ok(found);
    }

    // Phase 1: Cross-file scan.
    //
    // Walk every `.rs` file in the project. For each Aho-Corasick match, skip
    // occurrences inside the symbol's own definition file — those are self-
    // references (the definition line itself) that prove nothing about reachability.
    let ac = AhoCorasick::builder()
        .match_kind(MatchKind::LeftmostFirst)
        .build(&names)
        .map_err(|e| anyhow::anyhow!("rust AC build: {}", e))?;

    for entry in WalkDir::new(project_root)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_scan_excluded(e.path()))
        .flatten()
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if path.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }

        let path_str = path.to_string_lossy();

        let file = match File::open(path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        // SAFETY: mmap is read-only; the file handle outlives the mmap.
        let mmap = match unsafe { Mmap::map(&file) } {
            Ok(m) => m,
            Err(_) => continue,
        };

        for mat in ac.find_iter(&*mmap) {
            let pat_idx = mat.pattern().as_usize();
            // Skip occurrences inside the definition file itself.
            if path_str.as_ref() == candidates[pat_idx].1 {
                continue;
            }
            found.insert(names[pat_idx].to_string());
        }

        // Early exit: all candidates are accounted for.
        if found.len() == candidates.len() {
            return Ok(found);
        }
    }

    // Phase 2: Within-file occurrence count.
    //
    // For symbols still not found cross-file, scan their definition file and
    // count total occurrences. If a name appears > 1 time (definition line +
    // at least one internal call site), the symbol is referenced within its own
    // compilation unit and must not be reported as dead.
    //
    // This catches intra-file helper functions, private methods, and OnceLock
    // initialisation functions that are only ever called from within the same
    // file and therefore invisible to both the Python reference graph and the
    // cross-file scan above.
    let unfound: Vec<(usize, &str, &str)> = candidates
        .iter()
        .enumerate()
        .filter(|(_, (n, _))| !found.contains(*n))
        .map(|(i, (n, f))| (i, *n, *f))
        .collect();

    if !unfound.is_empty() {
        // Group candidates by definition file to read each file only once.
        let mut by_file: std::collections::HashMap<&str, Vec<(usize, &str)>> =
            std::collections::HashMap::new();
        for (idx, name, def_file) in &unfound {
            by_file.entry(def_file).or_default().push((*idx, name));
        }

        for (def_file, syms) in &by_file {
            let sym_names: Vec<&str> = syms.iter().map(|(_, n)| *n).collect();
            let Ok(ac2) = AhoCorasick::builder()
                .match_kind(MatchKind::LeftmostFirst)
                .build(&sym_names)
            else {
                continue;
            };

            let Ok(f) = File::open(def_file) else {
                continue;
            };
            let Ok(mmap) = (unsafe { Mmap::map(&f) }) else {
                continue;
            };

            // Count total occurrences of each symbol in its definition file.
            let mut counts = vec![0usize; sym_names.len()];
            for mat in ac2.find_iter(&*mmap) {
                counts[mat.pattern().as_usize()] += 1;
            }

            // count > 1 means there is at least one call site beyond the definition.
            for (local_idx, (_, name)) in syms.iter().enumerate() {
                if counts[local_idx] > 1 {
                    found.insert(name.to_string());
                }
            }
        }
    }

    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_empty_names_returns_empty() {
        let tmp = std::env::temp_dir().join("test_grep_empty");
        fs::create_dir_all(&tmp).ok();
        let result = grep_shield(&[], &tmp).unwrap();
        assert!(result.is_empty());
        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_symbol_found_in_md() {
        let tmp = std::env::temp_dir().join("test_grep_md");
        fs::create_dir_all(&tmp).ok();

        fs::write(tmp.join("README.md"), b"Call `my_function` to get started.").ok();

        let found = grep_shield(&["my_function"], &tmp).unwrap();
        assert!(found.contains("my_function"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_symbol_not_found() {
        let tmp = std::env::temp_dir().join("test_grep_not_found");
        fs::create_dir_all(&tmp).ok();

        fs::write(tmp.join("config.yaml"), b"key: value\nother: data").ok();

        let found = grep_shield(&["nonexistent_fn"], &tmp).unwrap();
        assert!(found.is_empty());

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_rust_cross_file_shield_finds_cross_file_usage() {
        let tmp = std::env::temp_dir().join("test_rust_cross_def");
        let sub = tmp.join("sub");
        fs::create_dir_all(&sub).ok();

        // Definition file — contains the symbol name only as a definition.
        let def_path = sub.join("shadow_git.rs");
        fs::write(&def_path, b"pub fn simulate_merge() -> bool { true }\n").ok();

        // Caller file — references the symbol from outside.
        fs::write(
            tmp.join("slop_filter.rs"),
            b"use crate::shadow_git::simulate_merge;\nfn bounce() { simulate_merge(); }\n",
        )
        .ok();

        let def_str = def_path.to_string_lossy().to_string();
        let candidates = [("simulate_merge", def_str.as_str())];
        let found = rust_cross_file_shield(&candidates, &tmp).unwrap();
        assert!(
            found.contains("simulate_merge"),
            "should find cross-file usage in slop_filter.rs"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_rust_cross_file_shield_within_file_usage() {
        let tmp = std::env::temp_dir().join("test_rust_cross_intra");
        fs::create_dir_all(&tmp).ok();

        // Single file: symbol defined AND called multiple times within it.
        let def_path = tmp.join("parser.rs");
        fs::write(
            &def_path,
            b"fn get_rust_query() -> &'static str { \"q\" }\n\
              fn parse_a() { let _ = get_rust_query(); }\n\
              fn parse_b() { let _ = get_rust_query(); }\n",
        )
        .ok();

        let def_str = def_path.to_string_lossy().to_string();
        let candidates = [("get_rust_query", def_str.as_str())];
        let found = rust_cross_file_shield(&candidates, &tmp).unwrap();
        assert!(
            found.contains("get_rust_query"),
            "within-file usage (count > 1) must protect intra-file helpers"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_rust_cross_file_shield_test_prefix_protected() {
        let tmp = std::env::temp_dir().join("test_rust_cross_testfn");
        fs::create_dir_all(&tmp).ok();

        let def_path = tmp.join("lib.rs");
        fs::write(&def_path, b"#[test]\nfn test_hash_determinism() {}\n").ok();

        let def_str = def_path.to_string_lossy().to_string();
        let candidates = [("test_hash_determinism", def_str.as_str())];
        let found = rust_cross_file_shield(&candidates, &tmp).unwrap();
        assert!(
            found.contains("test_hash_determinism"),
            "test_ prefix must be protected without any file scanning"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_rust_cross_file_shield_ignores_self_reference() {
        let tmp = std::env::temp_dir().join("test_rust_cross_self");
        fs::create_dir_all(&tmp).ok();

        // Only the definition file exists — no other .rs files reference it.
        let def_path = tmp.join("only_def.rs");
        fs::write(&def_path, b"pub fn truly_dead() {}\n").ok();

        let def_str = def_path.to_string_lossy().to_string();
        let candidates = [("truly_dead", def_str.as_str())];
        let found = rust_cross_file_shield(&candidates, &tmp).unwrap();
        assert!(
            !found.contains("truly_dead"),
            "self-reference must not protect a truly dead symbol"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_symbol_found_in_json() {
        let tmp = std::env::temp_dir().join("test_grep_json");
        fs::create_dir_all(&tmp).ok();

        fs::write(
            tmp.join("config.json"),
            b"{\"handler\": \"process_request\", \"timeout\": 30}",
        )
        .ok();

        let found = grep_shield(&["process_request", "unused_fn"], &tmp).unwrap();
        assert!(found.contains("process_request"));
        assert!(!found.contains("unused_fn"));

        fs::remove_dir_all(tmp).ok();
    }
}
