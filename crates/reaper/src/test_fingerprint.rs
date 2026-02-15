//! Pytest test-node fingerprinting.
//!
//! Runs `pytest --collect-only -q` and parses the emitted test node IDs
//! (e.g. `tests/test_api.py::test_create_user`). Returns all leaf segment
//! names (the function portion after the last `::`) so callers can check
//! whether a symbol name appears in the test surface.

use crate::ReaperError;
use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

/// Collects pytest test node IDs from the project at `project_root`.
///
/// Runs `pytest --collect-only -q --no-header` in `project_root`.
/// Each collected test ID (`path::class::func` or `path::func`) contributes:
/// - The **full node ID** (for substring matching).
/// - The **leaf function name** (last `::` segment).
///
/// Returns an empty set if pytest is not installed, the project has no tests,
/// or the collection step itself fails — the caller should treat this as
/// "no additional fingerprint protection" rather than an error.
///
/// # Errors
/// Returns `ReaperError::IoError` only if `Command::spawn` itself fails
/// (i.e., `pytest` binary is not in `PATH`), which the caller may ignore.
pub fn collect_test_ids(project_root: &Path) -> Result<HashSet<String>, ReaperError> {
    let output = Command::new("pytest")
        .args(["--collect-only", "-q", "--no-header"])
        .current_dir(project_root)
        .output()?;

    parse_collected_ids(&output.stdout)
}

/// Parses the stdout of `pytest --collect-only -q` into a set of names.
fn parse_collected_ids(stdout: &[u8]) -> Result<HashSet<String>, ReaperError> {
    let text = String::from_utf8_lossy(stdout);
    let mut ids = HashSet::new();

    for line in text.lines() {
        let line = line.trim();
        // Node IDs contain "::" — skip summary lines and blank lines.
        if !line.contains("::") {
            continue;
        }
        // Skip lines that look like pytest summary output ("= X passed =").
        if line.starts_with('=') {
            continue;
        }

        // Insert the full node ID for substring matching.
        ids.insert(line.to_string());

        // Also insert each "::" segment so individual function names match.
        for segment in line.split("::") {
            let seg = segment.trim();
            if !seg.is_empty() && !seg.ends_with(".py") {
                ids.insert(seg.to_string());
            }
        }
    }

    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_ids() {
        let stdout = b"tests/test_api.py::test_create_user\ntests/test_api.py::test_delete_user\n";
        let ids = parse_collected_ids(stdout).unwrap();

        assert!(ids.contains("test_create_user"));
        assert!(ids.contains("test_delete_user"));
        assert!(ids.contains("tests/test_api.py::test_create_user"));
    }

    #[test]
    fn test_parse_class_method_ids() {
        let stdout = b"tests/test_model.py::TestUser::test_save\n";
        let ids = parse_collected_ids(stdout).unwrap();

        assert!(ids.contains("TestUser"));
        assert!(ids.contains("test_save"));
    }

    #[test]
    fn test_parse_empty_stdout() {
        let ids = parse_collected_ids(b"").unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn test_parse_skips_summary_lines() {
        let stdout = b"tests/test_foo.py::test_bar\n= 1 test collected =\n";
        let ids = parse_collected_ids(stdout).unwrap();
        assert!(ids.contains("test_bar"));
        assert!(!ids.iter().any(|s| s.starts_with('=')));
    }
}
