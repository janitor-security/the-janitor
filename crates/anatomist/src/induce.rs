//! Induction Bridge — learns entity-extraction metadata for unknown file extensions
//! from the Governor API at `https://api.thejanitor.app/v1/induce`.
//!
//! ## Protocol
//! 1. When `dissect()` encounters an extension not in the built-in 14-language list,
//!    it calls [`induce`] with the first [`SNIPPET_MAX_BYTES`] of the file.
//! 2. The server returns an [`InducedEntry`] — a Tree-sitter query string paired with
//!    a `language_hint` indicating which embedded grammar to run it against.
//! 3. The result is cached in `.janitor/learned_wisdom.rkyv` (JSON-serialised map,
//!    keyed by file extension).
//! 4. On any network or parse failure the bridge logs a warning via `eprintln!` and
//!    returns `None` — the caller must skip the file gracefully. No panics.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// API endpoint for the Induction Bridge.
const INDUCE_URL: &str = "https://api.thejanitor.app/v1/induce";

/// Maximum source snippet size (bytes) sent to the API (first 4 KiB).
const SNIPPET_MAX_BYTES: usize = 4096;

/// A learned grammar entry: Tree-sitter query + language hint, cached by extension.
///
/// Returned by the Governor API for file extensions not in the built-in language list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InducedEntry {
    /// Tree-sitter S-expression query for extracting entities from this language.
    pub query: String,
    /// Built-in grammar name to parse with (`"python"`, `"rust"`, `"cpp"`, etc.).
    ///
    /// Defaults to `"python"` when the server omits the field.
    pub language_hint: String,
}

/// Attempts to learn entity-extraction metadata for `ext` from the Governor API.
///
/// Posts the first [`SNIPPET_MAX_BYTES`] of `source` to `/v1/induce`.
/// On success, returns the [`InducedEntry`] for this extension.
/// On any failure, prints a warning to stderr and returns `None`.
pub fn induce(source: &[u8], ext: &str) -> Option<InducedEntry> {
    let snippet_len = source.len().min(SNIPPET_MAX_BYTES);
    let snippet = String::from_utf8_lossy(&source[..snippet_len]);

    let payload = serde_json::json!({
        "extension": ext,
        "snippet": snippet.as_ref(),
    });

    let response = ureq::post(INDUCE_URL)
        .set("Content-Type", "application/json")
        .send_json(&payload)
        .map_err(|e| {
            eprintln!("induce: POST to {INDUCE_URL} failed for .{ext}: {e}");
        })
        .ok()?;

    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| {
            eprintln!("induce: response parse error for .{ext}: {e}");
        })
        .ok()?;

    let query = body["query"].as_str().map(str::to_owned)?;
    let language_hint = body
        .get("language_hint")
        .and_then(|v| v.as_str())
        .unwrap_or("python")
        .to_owned();

    Some(InducedEntry {
        query,
        language_hint,
    })
}

/// Walks ancestor directories from `file_path` upward to locate `.janitor/`.
///
/// Returns the first `.janitor/` directory found, or `None` if the search
/// reaches the filesystem root without finding one.
pub fn find_janitor_dir(file_path: &Path) -> Option<PathBuf> {
    let mut dir = file_path.parent()?;
    loop {
        let candidate = dir.join(".janitor");
        if candidate.is_dir() {
            return Some(candidate);
        }
        dir = dir.parent()?;
    }
}

/// Loads the learned wisdom cache from `<janitor_dir>/learned_wisdom.rkyv`.
///
/// Returns an empty map when the file is missing or cannot be parsed.
pub fn load_cache(janitor_dir: &Path) -> HashMap<String, InducedEntry> {
    let path = janitor_dir.join("learned_wisdom.rkyv");
    std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Persists `cache` to `<janitor_dir>/learned_wisdom.rkyv`.
///
/// Creates `janitor_dir` if it does not exist. Silently ignores I/O errors
/// (cache persistence is best-effort).
pub fn save_cache(janitor_dir: &Path, cache: &HashMap<String, InducedEntry>) {
    let path = janitor_dir.join("learned_wisdom.rkyv");
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_vec(cache) {
        let _ = std::fs::write(&path, json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_find_janitor_dir_returns_none_when_absent() {
        let tmp = std::env::temp_dir().join(format!("induce_no_janitor_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        let file = tmp.join("example.mojo");
        std::fs::write(&file, b"fn main() {}").ok();
        // No .janitor/ exists in ancestors → must return None.
        assert!(find_janitor_dir(&file).is_none());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_find_janitor_dir_finds_ancestor() {
        let tmp =
            std::env::temp_dir().join(format!("induce_janitor_present_{}", std::process::id()));
        let src_dir = tmp.join("src");
        let janitor_dir = tmp.join(".janitor");
        std::fs::create_dir_all(&src_dir).ok();
        std::fs::create_dir_all(&janitor_dir).ok();
        let file = src_dir.join("example.mojo");
        std::fs::write(&file, b"fn main() {}").ok();

        let found = find_janitor_dir(&file);
        assert_eq!(found.as_deref(), Some(janitor_dir.as_path()));
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_cache_roundtrip() {
        let tmp = std::env::temp_dir().join(format!("induce_cache_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();

        let mut cache = HashMap::new();
        cache.insert(
            "mojo".to_string(),
            InducedEntry {
                query: "(function_definition name: (identifier) @fn.name) @fn.def".into(),
                language_hint: "python".into(),
            },
        );

        save_cache(&tmp, &cache);
        let loaded = load_cache(&tmp);
        assert_eq!(loaded.len(), 1);
        let entry = loaded.get("mojo").expect("mojo entry must be present");
        assert_eq!(entry.language_hint, "python");
        assert!(!entry.query.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_load_cache_missing_file_returns_empty() {
        let tmp = std::env::temp_dir().join(format!("induce_missing_cache_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).ok();
        let cache = load_cache(&tmp);
        assert!(cache.is_empty());
        std::fs::remove_dir_all(&tmp).ok();
    }
}
