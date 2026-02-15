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
    "html", "htm", "js", "ts", "jsx", "tsx", "json", "yaml", "yml", "toml", "ini", "cfg", "md",
    "rst", "txt", "sh", "bash", "xml", "css", "scss", "env", "conf",
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
pub fn grep_shield(dead_names: &[String], project_root: &Path) -> anyhow::Result<HashSet<String>> {
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
            found.insert(dead_names[mat.pattern().as_usize()].clone());
        }

        // Early exit: all symbols accounted for.
        if found.len() == dead_names.len() {
            break;
        }
    }

    Ok(found)
}

/// Returns `true` if the path should be excluded from grep scanning.
fn is_scan_excluded(path: &Path) -> bool {
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
            )
        })
        .unwrap_or(false)
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

        let names = vec!["my_function".to_string()];
        let found = grep_shield(&names, &tmp).unwrap();
        assert!(found.contains("my_function"));

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_symbol_not_found() {
        let tmp = std::env::temp_dir().join("test_grep_not_found");
        fs::create_dir_all(&tmp).ok();

        fs::write(tmp.join("config.yaml"), b"key: value\nother: data").ok();

        let names = vec!["nonexistent_fn".to_string()];
        let found = grep_shield(&names, &tmp).unwrap();
        assert!(found.is_empty());

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

        let names = vec!["process_request".to_string(), "unused_fn".to_string()];
        let found = grep_shield(&names, &tmp).unwrap();
        assert!(found.contains("process_request"));
        assert!(!found.contains("unused_fn"));

        fs::remove_dir_all(tmp).ok();
    }
}
