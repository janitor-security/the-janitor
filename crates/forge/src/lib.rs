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

pub mod adapter_kotlin;
pub mod adapter_scala;
pub mod adapter_swift;
pub mod agentic_graph;
pub mod agentic_tool_audit;
pub mod agnostic_shield;
pub mod ast_adapter;
pub mod authz;
pub mod authz_propagation;
pub mod binary_recovery;
pub mod brain;
pub mod callgraph;
pub mod campaign;
pub mod config_taint;
pub mod cst_diff;
pub mod dedup;
pub mod deobfuscate;
pub mod exploitability;
pub mod federated_memory;
pub mod financial_pii;
pub mod fold;
pub mod frontend_state;
pub mod gadgets;
pub mod git_sig;
pub mod governance;
pub mod hashing;
pub mod idor;
pub mod ifds;
pub mod intent_divergence;
pub mod invisible_payload;
pub mod kani_bridge;
pub mod labyrinth;
pub mod legacy_c_mining;
pub mod library_identity;
pub mod memory_bomb;
pub mod memory_proof;
pub mod mesh_taint;
pub mod metadata;
pub mod migration_guard;
pub mod negtaint;
pub mod oauth_account_fusion;
pub mod oauth_scope;
pub mod pr_collider;
pub mod rag_source_registry;
pub mod rcal;
pub mod rebac_coherence;
pub mod rebac_registry;
pub mod router_topology;
pub mod rust_build_worm;
pub mod sanitizer;
pub mod sanitizer_sym;
pub mod schema_graph;
pub mod shadow_git;
pub mod slop_filter;
pub mod slop_hunter;
pub mod solidity_taint;
pub mod symbex;
pub mod taint_catalog;
pub mod taint_propagate;
pub mod toctou;
pub mod wasm_host;

use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Performance Heuristic: SIMD / math-path dedup skip
// ---------------------------------------------------------------------------

/// C++ compile-time and inlining keywords that flag a function for dedup skip.
///
/// - `constexpr`: body must remain individually visible for constant folding.
/// - `inline`: explicit inlining hint; merging strips it and forces a call indirection,
///   regressing throughput on hot paths.
const CPP_COMPILE_TIME_PATTERNS: &[&[u8]] = &[b"constexpr", b"inline"];

/// SIMD intrinsic byte patterns that indicate a function should not be deduplicated.
///
/// Merging SIMD-intrinsic functions breaks inlining and AVX/NEON optimisation
/// opportunities — the compiler must see the full body to auto-vectorise.
const SIMD_PATTERNS: &[&[u8]] = &[
    b"_mm_",
    b"_mm256_",
    b"_mm512_",
    b"__m128",
    b"__m256",
    b"__m512",
    b"simd_",
    b"__builtin_ia32",
    b"__builtin_neon",
    b"vcvt",
    b"vdup",
];

/// Returns `true` when structural deduplication must be **skipped** for this entity.
///
/// Two independent guards are applied:
///
/// 1. **Path guard** — the file path contains a `/math/` or `/physics/` component.
///    Math-heavy files contain hand-tuned SIMD or fused operations whose ordering
///    matters for numerical precision and hardware throughput.
///
/// 2. **Intrinsic guard** — the entity's source bytes contain a known SIMD intrinsic
///    prefix (Intel SSE/AVX/AVX-512 or GCC built-ins).  Merging such functions strips
///    the inlining hint the compiler depends on to emit vectorised machine code.
///
/// # Arguments
/// - `file_path`:     Normalized (UTF-8, forward-slash) path of the source file.
/// - `entity_source`: Raw source bytes of the function/method body to inspect.
pub fn should_skip_dedup(file_path: &str, entity_source: &[u8]) -> bool {
    // Guard 1: single path-segment guard — math/physics hot paths + Godot typedefs dir.
    if file_path
        .split('/')
        .any(|seg| matches!(seg, "math" | "physics" | "typedefs"))
    {
        return true;
    }
    // Guard 1b: Godot core sub-module pair guard — two consecutive segments where the
    // first is "core" and the second is a known highly-optimised module directory.
    // Protects core/math (also caught above), core/templates (template metaprogramming),
    // and core/variant (Variant type with platform-specific hot paths).
    {
        let mut prev: Option<&str> = None;
        for seg in file_path.split('/') {
            if prev == Some("core") && matches!(seg, "math" | "templates" | "variant") {
                return true;
            }
            prev = Some(seg);
        }
    }
    // Guard 2: SIMD intrinsic patterns in the entity body.
    for pattern in SIMD_PATTERNS {
        if entity_source.windows(pattern.len()).any(|w| w == *pattern) {
            return true;
        }
    }
    // Guard 3: C++ compile-time / inline-hint keywords in the entity body.
    // `constexpr` functions are evaluated at compile time — constant folding requires the
    // compiler to see the full body. `inline` carries an explicit inlining hint; merging
    // identical inline bodies into one forces a call indirection on every call site.
    for pattern in CPP_COMPILE_TIME_PATTERNS {
        if entity_source.windows(pattern.len()).any(|w| w == *pattern) {
            return true;
        }
    }
    false
}

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
    let d = digest.as_bytes();
    u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
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

    // --- Guard 3: constexpr / inline tests ---

    #[test]
    fn test_constexpr_body_skips_dedup() {
        let src = b"constexpr int factorial(int n) { return n <= 1 ? 1 : n * factorial(n - 1); }";
        assert!(
            should_skip_dedup("src/math_utils.cpp", src),
            "constexpr body must be skipped from dedup"
        );
    }

    #[test]
    fn test_inline_body_skips_dedup() {
        let src = b"inline void swap(int& a, int& b) { int t = a; a = b; b = t; }";
        assert!(
            should_skip_dedup("src/utils.cpp", src),
            "inline body must be skipped from dedup"
        );
    }

    #[test]
    fn test_plain_cpp_body_not_skipped_by_guard3() {
        let src = b"int add(int a, int b) { return a + b; }";
        assert!(
            !should_skip_dedup("src/arithmetic.cpp", src),
            "plain C++ body with no special keywords must not be skipped"
        );
    }
}
