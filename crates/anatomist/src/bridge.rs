//! JS-to-Python Bridge: REST API path extraction from JavaScript/TypeScript files.
//!
//! Extracts quoted string literals that start with `/` from `.js`, `.jsx`, `.ts`,
//! and `.tsx` files. The resulting path set is used by the pipeline's bridge shield:
//! if a Python entity's decorator text references one of these paths, the entity is
//! presumed to serve that endpoint and is therefore protected.
//!
//! **Memory model**: one mmap per file, zero heap allocation per match.

use crate::scan::is_scan_excluded;
use memmap2::Mmap;
use std::collections::HashSet;
use std::fs::File;
use std::path::Path;
use walkdir::WalkDir;

/// Extracts REST API path strings from JavaScript and TypeScript files.
///
/// Scans for single- or double-quoted string literals that start with `/` in all
/// `.js`, `.jsx`, `.ts`, and `.tsx` files under `project_root`. Returns the set of
/// path strings found (e.g. `"/users"`, `"/api/v1/items"`).
///
/// These paths are used by the bridge shield in the pipeline: if a Python entity's
/// decorator text references one of these paths, it is presumed to serve that endpoint
/// and is therefore protected.
///
/// # Errors
/// Individual file I/O errors are silently skipped.
pub fn bridge_extract(project_root: &Path) -> anyhow::Result<HashSet<String>> {
    let mut api_paths: HashSet<String> = HashSet::new();

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
        if !matches!(ext, "js" | "jsx" | "ts" | "tsx") {
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
        let src = &*mmap;

        // Scan for quoted strings starting with '/'
        let mut i = 0usize;
        while i < src.len() {
            let q = src[i];
            if q == b'"' || q == b'\'' {
                i += 1;
                if i < src.len() && src[i] == b'/' {
                    let start = i;
                    // Scan to closing quote (no multiline or escape sequences needed here)
                    while i < src.len() && src[i] != q && src[i] != b'\n' {
                        i += 1;
                    }
                    if i < src.len() && src[i] == q {
                        if let Ok(s) = std::str::from_utf8(&src[start..i]) {
                            let s = s.trim();
                            // Only keep non-trivial paths with valid ASCII-printable chars
                            if s.len() > 1
                                && s.bytes()
                                    .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\'')
                            {
                                api_paths.insert(s.to_string());
                            }
                        }
                    }
                    i = i.saturating_add(1); // skip closing quote
                }
            } else {
                i += 1;
            }
        }
    }

    Ok(api_paths)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_bridge_extract_finds_api_paths() {
        let tmp = std::env::temp_dir().join("test_bridge_api");
        fs::create_dir_all(&tmp).ok();

        fs::write(
            tmp.join("api.js"),
            b"fetch(\"/users\");\nfetch(\"/items/123\");\nconst x = \"not-a-path\";",
        )
        .ok();

        let paths = bridge_extract(&tmp).unwrap();
        assert!(paths.contains("/users"), "should find /users");
        assert!(paths.contains("/items/123"), "should find /items/123");
        assert!(
            !paths.contains("not-a-path"),
            "should not find non-path string"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_bridge_extract_empty_dir() {
        let tmp = std::env::temp_dir().join("test_bridge_empty");
        fs::create_dir_all(&tmp).ok();
        let paths = bridge_extract(&tmp).unwrap();
        assert!(paths.is_empty());
        fs::remove_dir_all(tmp).ok();
    }
}
