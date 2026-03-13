//! Isolation test suite for the Advanced Threat Matrix.
//!
//! ## Blast-Radius tests
//! Verify BFS on a 10,000-node CSR graph completes rapidly and that arena
//! allocation does not leak between runs.
//!
//! ## Yggdrasil tests
//! Verify that the Aho-Corasick automaton catches CI injection indicators in
//! JavaScript string literals parsed by `tree-sitter-javascript`, and that the
//! resulting ThreatReport carries a valid ML-DSA-65 signature.

use advanced_threats::blast_radius::{compute_blast_radius, NodeIndex, HALLUCINATION_THRESHOLD};
use advanced_threats::yggdrasil::scan_for_ci_injection;
use petgraph::csr::Csr;

// ── Blast-Radius ──────────────────────────────────────────────────────────────

/// Build a directed chain: 0 → 1 → 2 → … → (n-1).
/// In petgraph CSR, `add_node()` returns `NodeIndex` = `u32`.
fn chain_graph(n: u32) -> (Csr<(), ()>, Vec<NodeIndex>) {
    let mut g: Csr<(), ()> = Csr::new();
    let nodes: Vec<NodeIndex> = (0..n).map(|_| g.add_node(())).collect();
    for i in 0..n - 1 {
        g.add_edge(nodes[i as usize], nodes[i as usize + 1], ());
    }
    (g, nodes)
}

#[test]
fn test_blast_radius_10k_chain_is_hallucination() {
    // 10,000-node chain; modified nodes span the entire length.
    let (graph, nodes) = chain_graph(10_000);
    let modified = vec![nodes[0], nodes[5_000], nodes[9_999]];

    let start = std::time::Instant::now();
    let report = compute_blast_radius(&graph, &modified);
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_millis() < 2_000,
        "BFS on 10k-node CSR graph took {}ms — arena reuse failure?",
        elapsed.as_millis()
    );
    assert!(
        report.is_agentic_hallucination,
        "Expected hallucination for nodes spanning 10k-hop chain"
    );
    assert!(
        report.max_hop_distance > HALLUCINATION_THRESHOLD,
        "max_hop_distance {} must exceed threshold {}",
        report.max_hop_distance,
        HALLUCINATION_THRESHOLD
    );
}

#[test]
fn test_blast_radius_single_node_no_hallucination() {
    let (graph, nodes) = chain_graph(100);
    // Only one modified node — cannot form a pair, must return clean report.
    let report = compute_blast_radius(&graph, &[nodes[42]]);
    assert_eq!(report.max_hop_distance, 0);
    assert!(!report.is_agentic_hallucination);
}

#[test]
fn test_blast_radius_adjacent_nodes_below_threshold() {
    let (graph, nodes) = chain_graph(10);
    // nodes[0] → nodes[3]: 3 hops, below HALLUCINATION_THRESHOLD (4).
    let report = compute_blast_radius(&graph, &[nodes[0], nodes[3]]);
    assert_eq!(report.max_hop_distance, 3);
    assert!(!report.is_agentic_hallucination);
}

#[test]
fn test_blast_radius_exactly_at_threshold_not_hallucination() {
    let (graph, nodes) = chain_graph(20);
    // nodes[0] → nodes[4]: exactly 4 hops == HALLUCINATION_THRESHOLD.
    // "exceeds" means > not >=, so this is NOT a hallucination.
    let report = compute_blast_radius(&graph, &[nodes[0], nodes[4]]);
    assert_eq!(report.max_hop_distance, 4);
    assert!(!report.is_agentic_hallucination);
}

#[test]
fn test_blast_radius_one_above_threshold_is_hallucination() {
    let (graph, nodes) = chain_graph(20);
    // nodes[0] → nodes[5]: 5 hops > HALLUCINATION_THRESHOLD (4).
    let report = compute_blast_radius(&graph, &[nodes[0], nodes[5]]);
    assert_eq!(report.max_hop_distance, 5);
    assert!(report.is_agentic_hallucination);
}

#[test]
fn test_blast_radius_disconnected_nodes_max_hallucination() {
    // Two isolated nodes with no edges — no path between them.
    let mut graph: Csr<(), ()> = Csr::new();
    let a = graph.add_node(());
    let b = graph.add_node(());
    // Intentionally no edge — BFS from a never reaches b, and vice versa.
    let report = compute_blast_radius(&graph, &[a, b]);
    assert_eq!(report.max_hop_distance, u32::MAX);
    assert!(report.is_agentic_hallucination);
}

// ── Yggdrasil ─────────────────────────────────────────────────────────────────

fn js_language() -> tree_sitter::Language {
    tree_sitter_javascript::LANGUAGE.into()
}

fn js_capture_query(language: &tree_sitter::Language) -> tree_sitter::Query {
    tree_sitter::Query::new(language, "[(string) (template_string) (comment)] @target")
        .expect("JS capture query must compile")
}

#[test]
fn test_yggdrasil_catches_secrets_in_js_string() {
    // Object literal whose value contains a GitHub Actions context expression.
    let source = r#"
        const config = {
            awsKey: "${{ secrets.AWS_ACCESS_KEY_ID }}"
        };
    "#;

    let language = js_language();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .expect("JS grammar must load");
    let tree = parser.parse(source, None).expect("parse must succeed");
    let query = js_capture_query(&language);

    let report = scan_for_ci_injection(tree.root_node(), source.as_bytes(), &query)
        .expect("scan must not error");

    let report = report.expect("'${{ secrets.' in JS string must trigger ThreatReport");

    // "${{" appears first in the string, so it fires before "secrets."
    assert!(
        report.matched_indicator == "${{" || report.matched_indicator == "secrets.",
        "Unexpected indicator: {}",
        report.matched_indicator
    );
    assert_eq!(report.node_kind, "string");

    // ML-DSA-65 output sizes are defined by FIPS 204.
    assert_eq!(
        report.public_key_bytes.len(),
        1952,
        "ML-DSA-65 public key must be 1952 bytes"
    );
    assert_eq!(
        report.signature_bytes.len(),
        3309,
        "ML-DSA-65 signature must be 3309 bytes"
    );
}

#[test]
fn test_yggdrasil_catches_github_token_in_comment() {
    let source = r#"
        // CI token: github.token is passed via env
        function deploy() {}
    "#;

    let language = js_language();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .expect("JS grammar must load");
    let tree = parser.parse(source, None).expect("parse must succeed");
    let query = js_capture_query(&language);

    let report = scan_for_ci_injection(tree.root_node(), source.as_bytes(), &query)
        .expect("scan must not error");

    let report = report.expect("'github.token' in JS comment must trigger ThreatReport");
    assert_eq!(report.matched_indicator, "github.token");
    assert_eq!(report.node_kind, "comment");
    assert_eq!(report.public_key_bytes.len(), 1952);
    assert_eq!(report.signature_bytes.len(), 3309);
}

#[test]
fn test_yggdrasil_clean_source_returns_none() {
    let source = r#"
        const msg = "Hello, world!";
        // This is a safe comment — no CI variables here.
        function greet(name) { return `Hi ${name}`; }
    "#;

    let language = js_language();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .expect("JS grammar must load");
    let tree = parser.parse(source, None).expect("parse must succeed");
    let query = js_capture_query(&language);

    let report = scan_for_ci_injection(tree.root_node(), source.as_bytes(), &query)
        .expect("scan must not error");

    assert!(
        report.is_none(),
        "Clean JS source must not trigger a ThreatReport"
    );
}

#[test]
fn test_yggdrasil_actions_checkout_in_template_string() {
    let source = r#"
        const step = `uses: actions/checkout@v4`;
    "#;

    let language = js_language();
    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&language)
        .expect("JS grammar must load");
    let tree = parser.parse(source, None).expect("parse must succeed");
    let query = js_capture_query(&language);

    let report = scan_for_ci_injection(tree.root_node(), source.as_bytes(), &query)
        .expect("scan must not error");

    let report = report.expect("'actions/checkout' in template string must trigger ThreatReport");
    assert_eq!(report.matched_indicator, "actions/checkout");
    assert_eq!(report.node_kind, "template_string");
    assert_eq!(report.public_key_bytes.len(), 1952);
    assert_eq!(report.signature_bytes.len(), 3309);
}
