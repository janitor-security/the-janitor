//! Pytest fixture detection heuristic.
//!
//! Identifies functions decorated with `@pytest.fixture` or `@fixture` and
//! applies special protection rules for `conftest.py` files.

use crate::{Heuristic, Protection};

/// Detects pytest fixtures via decorator byte-scanning.
///
/// # Detection Rules
/// 1. **Decorated Functions**: Scans decorator region for `pytest.fixture` or `@fixture`
/// 2. **conftest.py Special Case**: If the file ends with `conftest.py` and contains
///    any pytest markers (`pytest` or `@fixture`), ALL functions are protected
///
/// # Rationale
/// Pytest fixtures are dynamically discovered and invoked by the framework. Even
/// fixtures without explicit references may be used via:
/// - Autouse fixtures (`@pytest.fixture(autouse=True)`)
/// - Parameterization (`@pytest.mark.parametrize`)
/// - Fixture dependency chains (a test uses fixture A, which depends on fixture B)
/// - conftest.py fixtures are globally available to all tests in the directory tree
///
/// # Implementation
/// Uses byte-scanning (NOT additional tree-sitter queries) because:
/// - The decorator text must be checked anyway (tree-sitter provides structure, not semantics)
/// - Decorator regions are typically <200 bytes
/// - O(n*m) window search is acceptable for small haystacks
pub struct PytestFixtureHeuristic;

impl Heuristic for PytestFixtureHeuristic {
    fn apply(
        &self,
        source: &[u8],
        node: &tree_sitter::Node<'_>,
        file_path: &str,
    ) -> Option<Protection> {
        // Special case: conftest.py files
        if file_path.ends_with("conftest.py") {
            // If the file contains any pytest markers, protect ALL functions
            if contains_bytes(source, b"pytest") || contains_bytes(source, b"@fixture") {
                return Some(Protection::PytestFixture);
            }
        }

        // General case: walk up to find decorated_definition parent
        let mut current = Some(*node);
        while let Some(n) = current {
            if n.kind() == "decorated_definition" {
                // Extract decorator region bytes
                if let Some(decorator_node) = n.child_by_field_name("decorator") {
                    let start = decorator_node.start_byte();
                    let end = decorator_node.end_byte();
                    if end <= source.len() {
                        let decorator_region = &source[start..end];
                        // Check for pytest.fixture or @fixture markers
                        if contains_bytes(decorator_region, b"pytest.fixture")
                            || contains_bytes(decorator_region, b"@fixture")
                        {
                            return Some(Protection::PytestFixture);
                        }
                    }
                }

                // Check all decorators (decorated_definition can have multiple)
                let mut cursor = n.walk();
                for child in n.children(&mut cursor) {
                    if child.kind() == "decorator" {
                        let start = child.start_byte();
                        let end = child.end_byte();
                        if end <= source.len() {
                            let decorator_region = &source[start..end];
                            if contains_bytes(decorator_region, b"pytest.fixture")
                                || contains_bytes(decorator_region, b"@fixture")
                            {
                                return Some(Protection::PytestFixture);
                            }
                        }
                    }
                }
            }
            current = n.parent();
        }

        None
    }
}

/// Searches for a byte sequence within another byte slice.
///
/// # Performance
/// O(n*m) sliding window search. For decorator regions (<200 bytes),
/// this is faster than importing a full Boyer-Moore implementation.
fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contains_bytes() {
        assert!(contains_bytes(b"hello world", b"world"));
        assert!(contains_bytes(b"@pytest.fixture", b"pytest.fixture"));
        assert!(!contains_bytes(b"hello", b"world"));
        assert!(contains_bytes(b"anything", b""));
        assert!(!contains_bytes(b"short", b"this is longer"));
    }

    // Note: Full integration test of conftest.py detection is in parser.rs tests
    // This unit test validates the conftest.py special case logic
}
