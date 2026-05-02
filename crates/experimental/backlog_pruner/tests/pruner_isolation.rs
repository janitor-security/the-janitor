//! # Pruner Isolation Tests
//!
//! Verifies the three garbage-collection states in complete isolation.
//! Each test constructs a minimal synthetic scenario and asserts the detector
//! produces the expected verdict.  No external files or network calls.

use backlog_pruner::{
    ghost_collision::{is_ghost_collision, MasterEntry, MasterIndex},
    semantic_null::{is_semantic_null, structural_hash},
    unwired_island::{is_unwired_island, MasterCallGraph},
    GarbageCollectionManifest, PrunerFlag,
};
use fips204::ml_dsa_65;
use fips204::traits::{KeyGen, Verifier};
use tree_sitter::Parser;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn python_parser() -> Parser {
    let mut p = Parser::new();
    p.set_language(&tree_sitter_python::LANGUAGE.into())
        .expect("Python grammar must load");
    p
}

fn parse_python(parser: &mut Parser, source: &[u8]) -> tree_sitter::Tree {
    parser.parse(source, None).expect("parse must not fail")
}

// ---------------------------------------------------------------------------
// SEMANTIC_NULL — identical structural skeletons
// ---------------------------------------------------------------------------

/// Two Python functions differing only in identifier names produce the same
/// structural skeleton hash → SEMANTIC_NULL.
#[test]
fn semantic_null_detected_when_only_identifiers_differ() {
    // Both have the same skeleton: module → function_definition → return → binary_operator
    let base_src = b"def add(a, b):\n    return a + b\n";
    let pr_src = b"def multiply(x, y):\n    return x + y\n";

    let mut parser = python_parser();
    let base_tree = parse_python(&mut parser, base_src);
    let pr_tree = parse_python(&mut parser, pr_src);

    assert!(
        is_semantic_null(base_tree.root_node(), pr_tree.root_node()),
        "Functions differing only in identifiers must be SEMANTIC_NULL"
    );
}

/// Functions with different control flow are NOT semantic null.
#[test]
fn semantic_null_not_triggered_when_logic_changes() {
    let base_src = b"def check(x):\n    if x > 0:\n        return True\n    return False\n";
    let pr_src = b"def check(x):\n    while x > 0:\n        x -= 1\n    return x == 0\n";

    let mut parser = python_parser();
    let base_tree = parse_python(&mut parser, base_src);
    let pr_tree = parse_python(&mut parser, pr_src);

    assert!(
        !is_semantic_null(base_tree.root_node(), pr_tree.root_node()),
        "Functions with different control flow must NOT be SEMANTIC_NULL"
    );
}

/// The structural hash is stable (deterministic) for identical sources.
#[test]
fn structural_hash_is_deterministic() {
    let src = b"def foo():\n    pass\n";
    let mut parser = python_parser();
    let tree_a = parse_python(&mut parser, src);
    let tree_b = parse_python(&mut parser, src);
    assert_eq!(
        structural_hash(tree_a.root_node()),
        structural_hash(tree_b.root_node()),
        "structural_hash must be deterministic for identical sources"
    );
}

// ---------------------------------------------------------------------------
// GHOST_COLLISION — decayed architecture
// ---------------------------------------------------------------------------

/// All modified functions missing from master → GHOST_COLLISION.
#[test]
fn ghost_collision_detected_when_all_functions_missing() {
    let master = MasterIndex::new(vec![]);
    let fns = vec!["engine::render".to_string(), "engine::flush".to_string()];
    let hashes = vec![[0u8; 32]; 2];

    assert!(
        is_ghost_collision(&fns, &hashes, &master),
        "100% missing functions must trigger GHOST_COLLISION"
    );
}

/// All modified functions present with matching hashes → not a ghost collision.
#[test]
fn ghost_collision_not_triggered_when_all_present_and_matching() {
    let hash = [0xABu8; 32];
    let master = MasterIndex::new(vec![
        MasterEntry {
            qualified_name: "mod::foo".to_string(),
            structural_hash: hash,
        },
        MasterEntry {
            qualified_name: "mod::bar".to_string(),
            structural_hash: hash,
        },
    ]);
    let fns = vec!["mod::foo".to_string(), "mod::bar".to_string()];
    let pr_hashes = vec![hash, hash];

    assert!(
        !is_ghost_collision(&fns, &pr_hashes, &master),
        "Functions present with matching hashes must NOT trigger GHOST_COLLISION"
    );
}

/// Exactly 50% missing — threshold is strict > 50%, so must NOT trigger.
#[test]
fn ghost_collision_boundary_at_fifty_percent() {
    let hash = [0xCCu8; 32];
    let master = MasterIndex::new(vec![MasterEntry {
        qualified_name: "mod::foo".to_string(),
        structural_hash: hash,
    }]);
    let fns = vec!["mod::foo".to_string(), "mod::bar".to_string()];
    let pr_hashes = vec![hash, [0u8; 32]];

    assert!(
        !is_ghost_collision(&fns, &pr_hashes, &master),
        "Exactly 50% decay must NOT trigger GHOST_COLLISION (threshold is > 50%)"
    );
}

// ---------------------------------------------------------------------------
// UNWIRED_ISLAND — unreachable new functions
// ---------------------------------------------------------------------------

/// New function with no callers and no lifecycle name → UNWIRED_ISLAND.
#[test]
fn unwired_island_detected_for_orphan_function() {
    let graph = MasterCallGraph::new(&[]);
    let new_fns = vec!["utils::validate_input".to_string()];

    assert!(
        is_unwired_island(&new_fns, &graph),
        "New function with no callers must be UNWIRED_ISLAND"
    );
}

/// New function that IS called by master code → not an island.
#[test]
fn unwired_island_not_triggered_when_callers_exist() {
    let edges = vec![(
        "engine::dispatch".to_string(),
        "utils::validate_input".to_string(),
    )];
    let graph = MasterCallGraph::new(&edges);
    let new_fns = vec!["utils::validate_input".to_string()];

    assert!(
        !is_unwired_island(&new_fns, &graph),
        "New function with an existing caller must NOT be UNWIRED_ISLAND"
    );
}

/// Lifecycle-named function with no callers is exempt.
#[test]
fn unwired_island_exempts_lifecycle_hooks() {
    let graph = MasterCallGraph::new(&[]);
    let new_fns = vec!["node::_ready".to_string()];

    assert!(
        !is_unwired_island(&new_fns, &graph),
        "_ready is a lifecycle hook and must be exempt from UNWIRED_ISLAND"
    );
}

/// Empty new-function list → not an island.
#[test]
fn unwired_island_returns_false_for_empty_input() {
    let graph = MasterCallGraph::new(&[]);
    assert!(
        !is_unwired_island(&[], &graph),
        "Empty new-function list must not be flagged as UNWIRED_ISLAND"
    );
}

// ---------------------------------------------------------------------------
// GarbageCollectionManifest — ML-DSA-65 signing round-trip
// ---------------------------------------------------------------------------

/// The manifest can be signed and the signature verifies against the same payload.
#[test]
fn manifest_signature_round_trip() {
    let (pk, sk) = ml_dsa_65::KG::try_keygen().expect("key generation must succeed");

    let skeleton_hash = [0x42u8; 32];
    let manifest =
        GarbageCollectionManifest::sign(12345, PrunerFlag::SemanticNull, skeleton_hash, &sk)
            .expect("signing must succeed");

    // Reconstruct the canonical payload identically to how lib.rs built it.
    let flag_str = backlog_pruner::flag_label(&manifest.flag);
    let blake3_hex = backlog_pruner::hex_encode(&manifest.skeleton_hash);
    let payload = format!("{}:{}:{}", manifest.pr_number, flag_str, blake3_hex);

    assert!(
        pk.verify(payload.as_bytes(), &*manifest.signature, &[]),
        "ML-DSA-65 signature must verify against the reconstructed payload"
    );
}

/// Manifest carries the correct PR number and flag.
#[test]
fn manifest_carries_correct_metadata() {
    let (_pk, sk) = ml_dsa_65::KG::try_keygen().expect("key generation must succeed");
    let skeleton_hash = [0u8; 32];

    let manifest =
        GarbageCollectionManifest::sign(99, PrunerFlag::GhostCollision, skeleton_hash, &sk)
            .expect("signing must succeed");

    assert_eq!(manifest.pr_number, 99);
    assert_eq!(manifest.flag, PrunerFlag::GhostCollision);
    assert_eq!(manifest.skeleton_hash, [0u8; 32]);
}
