//! Heuristic detection system for entity protection classification.
//!
//! This module defines the `Heuristic` trait and provides implementations
//! for detecting protected entities based on various patterns and conventions.

pub mod pytest;

use crate::Protection;

/// A heuristic for detecting if an entity should be protected from removal.
///
/// Heuristics analyze source code nodes to determine if they match specific
/// patterns that indicate the entity serves a critical role (e.g., test fixtures,
/// framework hooks, plugin entry points).
///
/// # Implementation Notes
/// - Heuristics are applied during parsing, not as a separate analysis pass
/// - The first heuristic to return `Some(Protection)` wins
/// - Implementations should be fast — they run for every entity in every file
/// - Use byte-scanning where possible to avoid additional tree-sitter queries
pub trait Heuristic {
    /// Analyzes a tree-sitter node to determine if it should be protected.
    ///
    /// # Parameters
    /// - `source`: The complete file source code as bytes
    /// - `node`: The tree-sitter node representing the entity
    /// - `file_path`: Normalized file path (forward slashes, UTF-8)
    ///
    /// # Returns
    /// - `Some(Protection::...)` if the node matches this heuristic's pattern
    /// - `None` if the heuristic doesn't apply
    ///
    /// # Example
    /// ```no_run
    /// use anatomist::{Heuristic, Protection};
    /// use tree_sitter::Node;
    ///
    /// struct MyHeuristic;
    ///
    /// impl Heuristic for MyHeuristic {
    ///     fn apply(&self, source: &[u8], node: &Node, file_path: &str) -> Option<Protection> {
    ///         // Check if the node matches a specific pattern
    ///         if file_path.ends_with("conftest.py") {
    ///             return Some(Protection::PytestFixture);
    ///         }
    ///         None
    ///     }
    /// }
    /// ```
    fn apply(
        &self,
        source: &[u8],
        node: &tree_sitter::Node<'_>,
        file_path: &str,
    ) -> Option<Protection>;
}
