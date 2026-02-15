//! # The Forge: Structural Identity Engine
//!
//! Computes a deterministic structural hash of Python AST nodes using
//! **alpha-normalization** — identifier names, string contents, and comments
//! are erased so that two functions with identical logic but different naming
//! produce the same `u64` hash.
//!
//! ## Alpha-Normalization Rule
//! The following node kinds are **skipped** (not hashed):
//! - `identifier`           — variable/function/parameter names
//! - `string` / `string_content` / `string_start` / `string_end` — literal text
//! - `comment`              — source comments
//!
//! Everything else (operator tokens, control-flow keywords, block structure,
//! `kind_id` sequence) **is** hashed, preserving the structural skeleton.
//!
//! ## Example
//! ```ignore
//! // def add(a, b): return a + b
//! // def sum(x, y): return x + y
//! // → same structural hash
//! ```

use tree_sitter::Node;

/// Node kinds that carry only naming information and must be erased
/// during alpha-normalization.
const SKIP_KINDS: &[&str] = &[
    "identifier",
    "string",
    "string_content",
    "string_start",
    "string_end",
    "escape_sequence",
    "comment",
    "type_comment",
];

/// Computes a deterministic structural hash for the given AST node.
///
/// The hash encodes the **shape** of the syntax tree — the sequence of
/// `node.kind_id()` values in a depth-first pre-order walk — with all
/// identifier names, string contents, and comments stripped out.
///
/// Truncates the 256-bit BLAKE3 digest to a `u64` (first 8 bytes, LE).
///
/// # Arguments
/// - `node`:   The tree-sitter node to hash (typically a function body `block`).
/// - `source`: The raw source bytes of the file (used for completeness; the
///   alpha-normalization step means we never read identifier text).
///
/// # Returns
/// A `u64` structural fingerprint.  Two nodes with the same control-flow
/// shape and operator structure will produce identical values regardless of
/// variable naming.
pub fn compute_structural_hash(node: Node<'_>, source: &[u8]) -> u64 {
    let mut hasher = blake3::Hasher::new();
    hash_node_recursive(&mut hasher, node, source);
    let digest = hasher.finalize();
    u64::from_le_bytes(digest.as_bytes()[..8].try_into().expect("blake3 ≥ 8 bytes"))
}

/// Represents a group of symbols sharing the same structural hash.
#[derive(Debug, Clone)]
pub struct DuplicateGroup {
    /// The shared structural fingerprint.
    pub hash: u64,
    /// Symbol entries: (file_path, qualified_name, start_byte, end_byte).
    pub members: Vec<(String, String, u32, u32)>,
}

impl DuplicateGroup {
    /// Returns the number of duplicate members in this group.
    pub fn len(&self) -> usize {
        self.members.len()
    }

    /// Returns `true` if this group has no members (should never happen in practice).
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Internal recursive walker
// ---------------------------------------------------------------------------

/// Returns `true` if `node` (or any of its descendants) will contribute to the hash.
///
/// A node contributes when it is NOT in `SKIP_KINDS` AND either:
/// - it is a leaf node, OR
/// - at least one of its children contributes.
///
/// This pre-check lets us skip container nodes whose entire subtree is
/// alpha-normalized away — most importantly `expression_statement` nodes
/// that wrap docstring literals at the top of a function body.
fn has_structural_content(node: Node<'_>) -> bool {
    if SKIP_KINDS.contains(&node.kind()) {
        return false;
    }
    if node.child_count() == 0 {
        return true; // Non-skipped leaf — contributes its kind_id.
    }
    let mut cursor = node.walk();
    let result = node
        .children(&mut cursor)
        .any(|child| has_structural_content(child));
    result
}

fn hash_node_recursive(hasher: &mut blake3::Hasher, node: Node<'_>, _source: &[u8]) {
    // Skip nodes that are either alpha-normalized away or have no structural
    // descendants (e.g., a docstring `expression_statement`).
    if !has_structural_content(node) {
        return;
    }

    // Hash the structural kind_id (u16 → 2 bytes).
    hasher.update(&node.kind_id().to_le_bytes());

    // Recurse into children (depth-first pre-order).
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        hash_node_recursive(hasher, child, _source);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

    fn parse_and_get_body(src: &str) -> (tree_sitter::Tree, Vec<u8>) {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let bytes = src.as_bytes().to_vec();
        let tree = parser.parse(&bytes, None).unwrap();
        (tree, bytes)
    }

    fn body_hash(src: &str) -> u64 {
        let (tree, bytes) = parse_and_get_body(src);
        // Find the first function_definition and hash its body block.
        let query = Query::new(
            &tree_sitter_python::LANGUAGE.into(),
            "(function_definition body: (block) @body)",
        )
        .unwrap();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes.as_slice());
        if let Some(m) = matches.next() {
            let body = m.captures[0].node;
            return compute_structural_hash(body, &bytes);
        }
        0
    }

    #[test]
    fn test_same_logic_different_names() {
        let h1 = body_hash("def add(a, b):\n    return a + b\n");
        let h2 = body_hash("def sum(x, y):\n    return x + y\n");
        assert_eq!(h1, h2, "Identical logic must produce identical hashes");
    }

    #[test]
    fn test_different_operator_differs() {
        let h1 = body_hash("def add(a, b):\n    return a + b\n");
        let h2 = body_hash("def sub(a, b):\n    return a - b\n");
        assert_ne!(h1, h2, "Different operators must produce different hashes");
    }

    #[test]
    fn test_different_structure_differs() {
        let h1 = body_hash("def f(x):\n    return x\n");
        let h2 = body_hash("def g(x):\n    if x:\n        return x\n    return None\n");
        assert_ne!(h1, h2, "Different control flow must differ");
    }

    #[test]
    fn test_docstring_ignored() {
        let h1 = body_hash("def add(a, b):\n    return a + b\n");
        let h2 = body_hash("def add(a, b):\n    \"\"\"Add two numbers.\"\"\"\n    return a + b\n");
        assert_eq!(h1, h2, "Docstring should not affect structural hash");
    }

    #[test]
    fn test_determinism() {
        let h1 = body_hash("def foo(x):\n    return x * 2\n");
        let h2 = body_hash("def foo(x):\n    return x * 2\n");
        assert_eq!(h1, h2);
    }
}
