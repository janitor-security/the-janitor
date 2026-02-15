//! Path normalization utilities for cross-platform file handling.

use std::path::Path;

use crate::AnatomistError;

/// Normalizes a file path to a canonical UTF-8 string with forward slashes.
///
/// # Process
/// 1. Canonicalizes the path using `dunce::canonicalize` (removes `\\?\` prefix on Windows)
/// 2. Converts to UTF-8 string
/// 3. Replaces backslashes with forward slashes for consistent representation
///
/// # Errors
/// - Returns `AnatomistError::IoError` if canonicalization fails (file not found, permissions, etc.)
/// - Returns `AnatomistError::ParseFailure` if the path contains non-UTF-8 characters
///
/// # Example
/// ```no_run
/// use std::path::Path;
/// use anatomist::path_util::normalize_path;
///
/// let normalized = normalize_path(Path::new("./src/main.rs")).unwrap();
/// // On Windows: "C:/Users/name/project/src/main.rs"
/// // On Unix: "/home/name/project/src/main.rs"
/// ```
pub fn normalize_path(path: &Path) -> Result<String, AnatomistError> {
    let canonical = dunce::canonicalize(path)?;
    let s = canonical.to_str().ok_or_else(|| {
        AnatomistError::ParseFailure(format!("Non-UTF-8 path: {}", canonical.display()))
    })?;
    Ok(s.replace('\\', "/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_path_cargo_manifest() {
        // Normalize Cargo.toml which always exists in the workspace
        let cargo_manifest = std::env::var("CARGO_MANIFEST_DIR")
            .map(|dir| Path::new(&dir).join("Cargo.toml"))
            .unwrap();

        let result = normalize_path(&cargo_manifest);
        assert!(result.is_ok());
        let normalized = result.unwrap();

        // Should contain forward slashes
        assert!(normalized.contains('/'));
        // Should end with Cargo.toml
        assert!(normalized.ends_with("Cargo.toml"));
        // Should not contain backslashes
        assert!(!normalized.contains('\\'));
    }

    #[test]
    fn test_normalize_nonexistent_path() {
        let result = normalize_path(Path::new("/this/does/not/exist/nowhere.py"));
        assert!(result.is_err());
    }
}
