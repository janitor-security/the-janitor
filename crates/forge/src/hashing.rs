//! Fuzzy structural hashing for AST nodes via SimHash (Locality-Sensitive Hashing).
//!
//! Augments the exact BLAKE3 structural hash with a 64-bit SimHash fingerprint
//! that is robust to minor structural mutations: added logging, trivial refactors,
//! variable renaming within non-normalized nodes, or reordered simple statements.
//!
//! ## Similarity Thresholds
//!
//! | Hamming distance | Similarity  | Classification  | Action                   |
//! |-----------------|-------------|-----------------|--------------------------|
//! | ≤ 3             | > 0.95      | [`Refactor`]    | Ignore — noise           |
//! | 4 – 9           | 0.85 – 0.95 | [`Zombie`]      | Penalise as near-clone   |
//! | ≥ 10            | ≤ 0.85      | [`NewCode`]     | Ignore — genuinely new   |
//!
//! ## Algorithm
//! 1. Walk the AST depth-first, collecting `(kind_id u16, depth u32)` feature pairs.
//! 2. Alpha-normalisation: `identifier`, `string`, and `comment` nodes are skipped
//!    (identical skip list to [`compute_structural_hash`][crate::compute_structural_hash]).
//! 3. Each feature pair is hashed to a `u64` via BLAKE3 (reuses the existing dep).
//! 4. For each of the 64 bit positions, the feature hash drives a vote counter:
//!    `+1` if that bit is `1`, `−1` if it is `0`.
//! 5. The final fingerprint sets bit `i` to `1` iff `counter[i] > 0`.
//!
//! Two ASTs with the same structural skeleton produce identical fingerprints.
//! Structurally similar (but not identical) ASTs produce fingerprints with small
//! Hamming distances, enabling fuzzy near-clone detection.

use tree_sitter::Node;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Classification of structural similarity between two AST fingerprints.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Similarity {
    /// Hamming distance ≤ 3 (similarity > 0.95).
    ///
    /// Near-identical structure — treat as a refactor/rename, not a clone.
    /// The alpha-normalization already strips identifiers, so this category
    /// captures "one-line changes" like an added `pass` or a single operator swap.
    Refactor,
    /// Hamming distance 4–9 (0.85 < similarity ≤ 0.95).
    ///
    /// Suspiciously similar structure — penalise as a near-zombie reintroduction.
    /// Typically indicates a function body copied with minor structural modifications
    /// (added error-handling block, inserted logging call, etc.).
    Zombie,
    /// Hamming distance ≥ 10 (similarity ≤ 0.85).
    ///
    /// Structurally distinct — treat as genuinely new code.
    NewCode,
}

/// Trait for types that compute a SimHash fingerprint from an AST node.
pub trait FuzzyHash {
    /// Compute a 64-bit SimHash fingerprint for the given AST `node`.
    fn fuzzy_hash(node: Node<'_>, source: &[u8]) -> u64;

    /// Compute the Hamming-distance similarity between two fingerprints.
    ///
    /// Returns a value in `[0.0, 1.0]`: `1.0` = identical fingerprints.
    fn similarity(a: u64, b: u64) -> f64 {
        compute_similarity(a, b)
    }

    /// Classify the similarity between two fingerprints into a [`Similarity`] band.
    fn classify(a: u64, b: u64) -> Similarity {
        classify_similarity(compute_similarity(a, b))
    }
}

/// Default SimHash implementation: walks the AST, hashes `(kind_id, depth)` features.
pub struct AstSimHasher;

impl FuzzyHash for AstSimHasher {
    fn fuzzy_hash(node: Node<'_>, source: &[u8]) -> u64 {
        compute_simhash(node, source)
    }
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Compute the Hamming-distance similarity between two SimHash fingerprints.
///
/// Returns a value in `[0.0, 1.0]`.
pub fn compute_similarity(a: u64, b: u64) -> f64 {
    let differing_bits = (a ^ b).count_ones();
    1.0 - (differing_bits as f64 / 64.0)
}

/// Classify a raw similarity score into a [`Similarity`] band.
///
/// Thresholds:
/// - `> 0.95` → [`Similarity::Refactor`]
/// - `> 0.85` → [`Similarity::Zombie`]
/// - `≤ 0.85` → [`Similarity::NewCode`]
pub fn classify_similarity(similarity: f64) -> Similarity {
    if similarity > 0.95 {
        Similarity::Refactor
    } else if similarity > 0.85 {
        Similarity::Zombie
    } else {
        Similarity::NewCode
    }
}

/// Compute a 64-bit SimHash fingerprint for the given AST node.
///
/// Alpha-normalisation applies: `identifier`, `string`, and `comment` nodes
/// are skipped to ensure that variable renaming does not shift the fingerprint.
/// The same skip list is used in [`compute_structural_hash`][crate::compute_structural_hash].
/// Minimum descendant AST node count below which a function is considered
/// trivial (getter, delegate, one-liner adapter) and excluded from clone
/// detection.  Trivial nodes receive a per-position unique hash so they never
/// match each other — no heap allocation required.
const TRIVIAL_NODE_THRESHOLD: usize = 7;

pub fn compute_simhash(node: Node<'_>, source: &[u8]) -> u64 {
    // Bypass clone detection for trivial nodes (getters, delegates, one-liners).
    // Return a per-position unique hash so these never match each other.
    if node.descendant_count() < TRIVIAL_NODE_THRESHOLD {
        return (node.start_byte() as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    }
    let mut counters = [0i32; 64];
    collect_features(node, source, 0, &mut counters);
    let mut fingerprint = 0u64;
    for (i, &count) in counters.iter().enumerate() {
        if count > 0 {
            fingerprint |= 1u64 << i;
        }
    }
    fingerprint
}

// ---------------------------------------------------------------------------
// Internal constants & helpers
// ---------------------------------------------------------------------------

/// Node kinds excluded from SimHash fingerprinting.
///
/// Must stay in sync with `SKIP_KINDS` in `lib.rs`.
///
/// ## Version-bump bypass
///
/// Numeric and string literal nodes are excluded so that automated dependency
/// bumps — which change only version number literals (`"1.2.3"` → `"1.2.4"`,
/// `0x1A` → `0x1B`) — do not shift the structural fingerprint.  Two function
/// bodies that differ **only** in literal values produce identical SimHash
/// fingerprints and are correctly classified as [`Similarity::Refactor`]
/// rather than [`Similarity::Zombie`], preventing the ×5 near-clone penalty
/// from firing on ecosystem automation PRs (`r-ryantm`, Dependabot, Renovate).
///
/// Literal kind names are grammar-specific; we cover all supported grammars:
///
/// | Grammar | Integer kind | Float kind |
/// |---------|-------------|------------|
/// | Python  | `integer`   | `float`    |
/// | Rust    | `integer_literal` | `float_literal` |
/// | Go      | `int_literal` | `float_literal`, `imaginary_literal` |
/// | JS/TS   | `number`    | —          |
/// | C/C++   | `number_literal` | —     |
/// | Java    | `decimal_integer_literal` | `decimal_floating_point_literal` |
const SIM_SKIP_KINDS: &[&str] = &[
    // Naming nodes (original set)
    "identifier",
    "string",
    "string_content",
    "string_start",
    "string_end",
    "escape_sequence",
    "comment",
    "type_comment",
    // Numeric literal nodes — version-bump bypass
    "integer",
    "float",
    "integer_literal",
    "float_literal",
    "int_literal",
    "imaginary_literal",
    "number",
    "number_literal",
    "decimal_integer_literal",
    "decimal_floating_point_literal",
    "hex_literal",
    "octal_literal",
    "binary_literal",
];

/// Recursively collect SimHash features from the AST.
///
/// Each non-skipped node contributes a feature `(kind_id, depth)` hashed via BLAKE3.
/// The BLAKE3 feature hash drives 64 vote counters (+1 for set bits, −1 for clear bits).
fn collect_features(node: Node<'_>, _source: &[u8], depth: u32, counters: &mut [i32; 64]) {
    if SIM_SKIP_KINDS.contains(&node.kind()) {
        return;
    }

    // Feature: hash (kind_id u16 LE || depth u32 LE) → BLAKE3 → u64.
    let feature_hash = {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&node.kind_id().to_le_bytes());
        hasher.update(&depth.to_le_bytes());
        let digest = hasher.finalize();
        let d = digest.as_bytes();
        u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
    };

    // Drive vote counters.
    for i in 0..64u32 {
        if (feature_hash >> i) & 1 == 1 {
            counters[i as usize] += 1;
        } else {
            counters[i as usize] -= 1;
        }
    }

    // Recurse into children.
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        collect_features(child, _source, depth + 1, counters);
    }
}

// ---------------------------------------------------------------------------
// Entropy gate — structural token counting
// ---------------------------------------------------------------------------

/// Minimum number of structural (non-cosmetic) AST tokens required for a
/// patch to form a unique cryptographic signature.
///
/// Patches below this threshold — pure markdown edits, translation files,
/// whitespace-only diffs — contain no discriminating structural information
/// and produce the degenerate `0x0000_0000_0000_0000` SimHash fingerprint.
/// They must bypass the swarm clustering index to prevent null-vector
/// collisions between structurally unrelated PRs.
pub const MIN_STRUCTURAL_TOKENS: usize = 5;

/// Count the number of structural (non-cosmetic) AST tokens in `node`'s subtree.
///
/// Structural tokens are nodes whose kind is **not** in [`SIM_SKIP_KINDS`]
/// (identifiers, string literals, comments, and numeric literals are excluded).
/// The count is used as a pre-flight entropy gate before swarm clustering.
pub fn count_structural_tokens(node: Node<'_>) -> usize {
    let mut count = 0usize;
    count_structural_inner(node, &mut count);
    count
}

fn count_structural_inner(node: Node<'_>, count: &mut usize) {
    if SIM_SKIP_KINDS.contains(&node.kind()) {
        return;
    }
    *count += 1;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        count_structural_inner(child, count);
    }
}

/// Compute a 64-bit SimHash fingerprint, returning `None` if the node
/// contains fewer than [`MIN_STRUCTURAL_TOKENS`] structural tokens.
///
/// A `None` result means the patch lacks sufficient AST entropy to form a
/// unique cryptographic signature.  Callers must not insert the patch into
/// the swarm clustering [`LshIndex`][crate::pr_collider::LshIndex] when
/// this returns `None`.
pub fn compute_simhash_checked(node: Node<'_>, source: &[u8]) -> Option<u64> {
    if count_structural_tokens(node) < MIN_STRUCTURAL_TOKENS {
        return None;
    }
    Some(compute_simhash(node, source))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tree_sitter::{Parser, Query, QueryCursor, StreamingIterator};

    fn simhash_of(src: &str) -> u64 {
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let bytes = src.as_bytes();
        let tree = parser.parse(bytes, None).unwrap();
        let query = Query::new(
            &tree_sitter_python::LANGUAGE.into(),
            "(function_definition body: (block) @body)",
        )
        .unwrap();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        if let Some(m) = matches.next() {
            return compute_simhash(m.captures[0].node, bytes);
        }
        0
    }

    #[test]
    fn test_identical_functions_same_simhash() {
        // Alpha-normalized identical structure → identical SimHash.
        let h1 = simhash_of("def add(a, b):\n    return a + b\n");
        let h2 = simhash_of("def sum(x, y):\n    return x + y\n");
        assert_eq!(
            h1, h2,
            "alpha-normalized identical structure must produce same SimHash"
        );
    }

    #[test]
    fn test_refactor_classification() {
        // Exactly identical bodies → similarity == 1.0 → Refactor.
        let h = simhash_of("def add(a, b):\n    return a + b\n");
        assert_eq!(
            classify_similarity(compute_similarity(h, h)),
            Similarity::Refactor,
            "identical fingerprint must classify as Refactor"
        );
    }

    #[test]
    fn test_different_structure_is_new_code() {
        let h1 = simhash_of("def trivial():\n    return 1\n");
        let h2 = simhash_of(
            "def complex(x):\n    if x > 0:\n        for i in range(x):\n            print(i)\n    return x\n",
        );
        assert_eq!(
            classify_similarity(compute_similarity(h1, h2)),
            Similarity::NewCode,
            "structurally very different functions must classify as NewCode"
        );
    }

    #[test]
    fn test_similarity_is_symmetric() {
        let h1 = simhash_of("def f(a):\n    return a * 2\n");
        let h2 = simhash_of("def g(x):\n    return x + x\n");
        let sim_ab = compute_similarity(h1, h2);
        let sim_ba = compute_similarity(h2, h1);
        assert_eq!(sim_ab, sim_ba, "similarity must be symmetric");
    }

    #[test]
    fn test_classify_similarity_thresholds() {
        // Construct explicit similarity values to test the threshold boundaries.
        assert_eq!(classify_similarity(0.96), Similarity::Refactor);
        assert_eq!(classify_similarity(0.95), Similarity::Zombie); // not strictly > 0.95
        assert_eq!(classify_similarity(0.90), Similarity::Zombie);
        assert_eq!(classify_similarity(0.86), Similarity::Zombie);
        assert_eq!(classify_similarity(0.85), Similarity::NewCode); // not strictly > 0.85
        assert_eq!(classify_similarity(0.50), Similarity::NewCode);
    }

    #[test]
    fn test_determinism() {
        let h1 = simhash_of("def foo(x):\n    return x * 2\n");
        let h2 = simhash_of("def foo(x):\n    return x * 2\n");
        assert_eq!(h1, h2, "SimHash must be deterministic");
    }

    #[test]
    fn test_count_structural_tokens_code_node() {
        // A real function body should have well above the threshold.
        let src = b"def add(a, b):\n    return a + b\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let count = count_structural_tokens(tree.root_node());
        assert!(
            count >= MIN_STRUCTURAL_TOKENS,
            "real code must have at least {MIN_STRUCTURAL_TOKENS} structural tokens, got {count}"
        );
    }

    #[test]
    fn test_count_structural_tokens_identifier_only() {
        // A bare name expression (`x`) should count as zero structural tokens
        // because "identifier" is in SIM_SKIP_KINDS.  The root `module` node
        // is structural (1), so the count is 1 — below the threshold.
        let src = b"x\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let count = count_structural_tokens(tree.root_node());
        // Root `module` + `expression_statement` are structural; `identifier` is not.
        assert!(
            count < MIN_STRUCTURAL_TOKENS,
            "identifier-only source must be below threshold, got {count}"
        );
    }

    #[test]
    fn test_compute_simhash_checked_returns_none_for_sparse_ast() {
        // A single bare identifier has fewer structural tokens than the gate.
        let src = b"x\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let result = compute_simhash_checked(tree.root_node(), src);
        assert!(
            result.is_none(),
            "sparse AST must return None from compute_simhash_checked"
        );
    }

    #[test]
    fn test_compute_simhash_checked_returns_some_for_code() {
        let src = b"def foo(x):\n    if x > 0:\n        return x * 2\n    return 0\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(src, None).unwrap();
        let result = compute_simhash_checked(tree.root_node(), src);
        assert!(
            result.is_some(),
            "real code must return Some from compute_simhash_checked"
        );
    }

    #[test]
    fn test_fuzzy_hash_trait() {
        let src = "def bar(a, b):\n    return a - b\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_python::LANGUAGE.into())
            .unwrap();
        let bytes = src.as_bytes();
        let tree = parser.parse(bytes, None).unwrap();
        let query = Query::new(
            &tree_sitter_python::LANGUAGE.into(),
            "(function_definition body: (block) @body)",
        )
        .unwrap();
        let mut cursor = QueryCursor::new();
        let mut matches = cursor.matches(&query, tree.root_node(), bytes);
        if let Some(m) = matches.next() {
            let node = m.captures[0].node;
            let h1 = AstSimHasher::fuzzy_hash(node, bytes);
            let h2 = compute_simhash(node, bytes);
            assert_eq!(h1, h2, "FuzzyHash trait must delegate to compute_simhash");
        } else {
            panic!("no function body found");
        }
    }
}
