//! # Include Deflator — Integration Tests
//!
//! Tests the graph builder, transitive reach calculation, and delta engine against
//! the fixture directories in `tests/fixtures/`.
//!
//! ## Fixture layout
//!
//! ```
//! fixtures/
//!   base/   — tangled graph: math_utils.h pulls in error_macros.h;
//!             renderer.cpp and physics.cpp also include error_macros.h directly.
//!   pr/     — deflated graph: error_macros.h includes severed from math_utils.h
//!             and from both .cpp files.
//! ```
//!
//! ## Edge topology (base)
//!
//! ```text
//! renderer.cpp → math_utils.h → core.h
//! renderer.cpp → error_macros.h → core.h
//! physics.cpp  → math_utils.h
//! physics.cpp  → error_macros.h
//! math_utils.h → error_macros.h
//! ```
//!
//! ## Edge topology (pr)
//!
//! ```text
//! renderer.cpp → math_utils.h → core.h
//! physics.cpp  → math_utils.h
//! error_macros.h → core.h   (still exists, just not referenced by math/renderers)
//! ```

use std::path::PathBuf;
use std::time::Instant;

use include_deflator::{
    deflator::{DeltaEngine, BLOAT_LABEL, BLOAT_REACH_THRESHOLD, ENTANGLEMENT_LABEL},
    graph::{IncludeEdge, IncludeGraphBuilder},
};

fn fixture(sub: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(sub)
}

// ─── Graph construction ────────────────────────────────────────────────────────

#[test]
fn base_graph_extracts_expected_edges() {
    let mut builder = IncludeGraphBuilder::new();
    builder
        .scan_dir(&fixture("base"))
        .expect("scan base fixture");
    let graph = builder.build();

    // The base fixture has 5 source files (core.h, error_macros.h, math_utils.h,
    // renderer.cpp, physics.cpp).  Edges (unique, deduped):
    //   math_utils.h    → core.h
    //   math_utils.h    → error_macros.h
    //   error_macros.h  → core.h
    //   renderer.cpp    → math_utils.h
    //   renderer.cpp    → error_macros.h
    //   physics.cpp     → math_utils.h
    //   physics.cpp     → error_macros.h
    assert!(
        graph.node_count() >= 5,
        "expected ≥5 nodes, got {}",
        graph.node_count()
    );
    assert!(
        graph.edge_count() >= 7,
        "expected ≥7 edges, got {}",
        graph.edge_count()
    );
}

#[test]
fn pr_graph_has_fewer_edges_than_base() {
    let mut base_builder = IncludeGraphBuilder::new();
    base_builder.scan_dir(&fixture("base")).expect("scan base");
    let base = base_builder.build();

    let mut pr_builder = IncludeGraphBuilder::new();
    pr_builder.scan_dir(&fixture("pr")).expect("scan pr");
    let pr = pr_builder.build();

    assert!(
        pr.edge_count() < base.edge_count(),
        "PR graph must have fewer edges than base: pr={}, base={}",
        pr.edge_count(),
        base.edge_count()
    );
}

// ─── Transitive reach ─────────────────────────────────────────────────────────

#[test]
fn core_h_has_highest_reach_in_base() {
    let mut builder = IncludeGraphBuilder::new();
    builder.scan_dir(&fixture("base")).expect("scan base");
    let graph = builder.build();

    let core_idx = *graph
        .node_index
        .get("core.h")
        .expect("core.h must be in graph");

    let reach = graph.transitive_reach(core_idx);
    // core.h is included by: error_macros.h, math_utils.h, renderer.cpp, physics.cpp → reach ≥ 4
    assert!(
        reach >= 4,
        "core.h reach must be ≥4 (all other files pull it in), got {}",
        reach
    );
}

#[test]
fn source_cpp_files_have_zero_reach() {
    let mut builder = IncludeGraphBuilder::new();
    builder.scan_dir(&fixture("base")).expect("scan base");
    let graph = builder.build();

    for leaf in &["renderer.cpp", "physics.cpp"] {
        if let Some(&idx) = graph.node_index.get(*leaf) {
            let reach = graph.transitive_reach(idx);
            assert_eq!(
                reach, 0,
                "{leaf} is a leaf TU — nothing includes it, reach must be 0, got {reach}"
            );
        }
    }
}

// ─── Delta engine ─────────────────────────────────────────────────────────────

#[test]
fn delta_engine_reports_deflation_bonus() {
    let mut base_builder = IncludeGraphBuilder::new();
    base_builder.scan_dir(&fixture("base")).expect("scan base");
    let base = base_builder.build();

    let mut pr_builder = IncludeGraphBuilder::new();
    pr_builder.scan_dir(&fixture("pr")).expect("scan pr");
    let pr = pr_builder.build();

    let engine = DeltaEngine::new(&base, &pr);
    let (bonus, threats, _entanglements) = engine.analyse();

    let bonus = bonus.expect("PR removes include edges — DeflationBonus must be Some");
    assert!(
        bonus.edges_severed >= 3,
        "at least 3 edges severed (math→error, renderer→error, physics→error), got {}",
        bonus.edges_severed
    );
    assert!(
        bonus.total_reach_reduction > 0,
        "removing error_macros.h edges must reduce total reach"
    );
    assert!(
        threats.is_empty(),
        "no bloat added in this PR, threats must be empty"
    );
}

#[test]
fn delta_engine_reports_bloat_threat() {
    // Construct a synthetic scenario: a file with 150 ancestors (high reach)
    // suddenly includes a new heavy header. This crosses BLOAT_REACH_THRESHOLD (100).

    let mut base_builder = IncludeGraphBuilder::new();
    // Existing chain: heavy.h is included by 150 leaf files in base.
    // We build the base without the new problematic edge.
    base_builder.add_node("heavy.h");
    for i in 0..150u32 {
        base_builder.add_edges(std::iter::once(IncludeEdge {
            from: format!("leaf_{i}.cpp"),
            to: "popular.h".to_string(),
        }));
    }
    base_builder.add_edges(std::iter::once(IncludeEdge {
        from: "popular.h".to_string(),
        to: "core.h".to_string(),
    }));
    let base = base_builder.build();

    let mut pr_builder = IncludeGraphBuilder::new();
    // Same leaf structure in PR.
    pr_builder.add_node("heavy.h");
    for i in 0..150u32 {
        pr_builder.add_edges(std::iter::once(IncludeEdge {
            from: format!("leaf_{i}.cpp"),
            to: "popular.h".to_string(),
        }));
    }
    pr_builder.add_edges(std::iter::once(IncludeEdge {
        from: "popular.h".to_string(),
        to: "core.h".to_string(),
    }));
    // NEW in PR: popular.h (reach=150) now includes heavy.h
    pr_builder.add_edges(std::iter::once(IncludeEdge {
        from: "popular.h".to_string(),
        to: "heavy.h".to_string(),
    }));
    let pr = pr_builder.build();

    let engine = DeltaEngine::new(&base, &pr);
    let (bonus, threats, _entanglements) = engine.analyse();

    assert!(
        bonus.is_none(),
        "no edges removed in this PR, bonus must be None"
    );
    assert!(!threats.is_empty(), "bloat edge must trigger ThreatReport");
    let threat = &threats[0];
    assert_eq!(threat.label, BLOAT_LABEL);
    assert_eq!(threat.offending_file, "popular.h");
    assert_eq!(threat.heavy_header, "heavy.h");
    assert!(
        threat.reach_of_includer >= BLOAT_REACH_THRESHOLD,
        "reach {} must exceed threshold {}",
        threat.reach_of_includer,
        BLOAT_REACH_THRESHOLD
    );
}

// ─── Entanglement detection ────────────────────────────────────────────────────

#[test]
fn delta_engine_detects_graph_entanglement() {
    // Build a synthetic "hairball" scenario.
    //
    // Topology: 5 headers (a.h – e.h) form a near-clique: every pair has an edge.
    // A PR adds a new file hub.h that is simultaneously included by all 5 headers
    // (backward neighbours) and includes all 5 (forward neighbours), making
    // hub.h the centre of a complete bipartite structure.
    //
    // The neighbourhood of the new edge `hub.h → a.h` in the PR graph has k = 5
    // neighbours (a.h, b.h, c.h, d.h, e.h), and the existing clique edges among
    // them yield LCC >> 0.75.
    let mut base_builder = IncludeGraphBuilder::new();
    // Base: clique among 5 headers.
    let headers = ["a.h", "b.h", "c.h", "d.h", "e.h"];
    for &h in &headers {
        base_builder.add_node(h);
    }
    for i in 0..headers.len() {
        for j in 0..headers.len() {
            if i != j {
                base_builder.add_edges(std::iter::once(IncludeEdge {
                    from: headers[i].to_string(),
                    to: headers[j].to_string(),
                }));
            }
        }
    }
    let base = base_builder.build();

    let mut pr_builder = IncludeGraphBuilder::new();
    // Same clique in PR.
    for &h in &headers {
        pr_builder.add_node(h);
    }
    for i in 0..headers.len() {
        for j in 0..headers.len() {
            if i != j {
                pr_builder.add_edges(std::iter::once(IncludeEdge {
                    from: headers[i].to_string(),
                    to: headers[j].to_string(),
                }));
            }
        }
    }
    // PR adds hub.h which includes all 5 headers — plugging into the clique.
    pr_builder.add_node("hub.h");
    for &h in &headers {
        pr_builder.add_edges(std::iter::once(IncludeEdge {
            from: "hub.h".to_string(),
            to: h.to_string(),
        }));
    }
    let pr = pr_builder.build();

    let engine = DeltaEngine::new(&base, &pr);
    let (_bonus, _threats, entanglements) = engine.analyse();

    assert!(
        !entanglements.is_empty(),
        "hub.h plugging into a 5-clique must trigger EntanglementReport"
    );
    // The clique nodes and hub.h are all entangled; find the hub.h report.
    let hub_report = entanglements
        .iter()
        .find(|r| r.hub_file == "hub.h")
        .expect("an EntanglementReport for hub.h must be present");
    assert_eq!(hub_report.label, ENTANGLEMENT_LABEL);
    assert!(
        hub_report.local_clustering_coefficient > 0.75,
        "LCC {:.3} must exceed 0.75",
        hub_report.local_clustering_coefficient
    );
}

#[test]
fn linear_chain_pr_does_not_trigger_entanglement() {
    // A simple chain: a → b → c. Adding a → c (short-circuit) has neighbourhood
    // {b, c} for `a`, but there is only 1 edge (b→c) among 2 nodes — LCC = 0.5
    // which is below the 0.75 threshold.
    let mut base_builder = IncludeGraphBuilder::new();
    base_builder.add_edges([
        IncludeEdge {
            from: "a.h".into(),
            to: "b.h".into(),
        },
        IncludeEdge {
            from: "b.h".into(),
            to: "c.h".into(),
        },
    ]);
    let base = base_builder.build();

    let mut pr_builder = IncludeGraphBuilder::new();
    pr_builder.add_edges([
        IncludeEdge {
            from: "a.h".into(),
            to: "b.h".into(),
        },
        IncludeEdge {
            from: "b.h".into(),
            to: "c.h".into(),
        },
        IncludeEdge {
            from: "a.h".into(),
            to: "c.h".into(), // new shortcut
        },
    ]);
    let pr = pr_builder.build();

    let engine = DeltaEngine::new(&base, &pr);
    let (_bonus, _threats, entanglements) = engine.analyse();

    assert!(
        entanglements.is_empty(),
        "simple chain short-circuit must not trigger EntanglementReport"
    );
}

// ─── Performance gate — 50 ms for 10,000-node graph ──────────────────────────

#[test]
fn graph_and_delta_complete_within_50ms_for_10k_nodes() {
    // Build a synthetic chain graph: node_0 → node_1 → ... → node_9999
    // This is a worst-case deep DAG — reach of node_9999 = 9999.
    const N: usize = 10_000;

    let start = Instant::now();

    let mut base_builder = IncludeGraphBuilder::new();
    for i in 0..N - 1 {
        base_builder.add_edges(std::iter::once(IncludeEdge {
            from: format!("node_{i}.h"),
            to: format!("node_{}.h", i + 1),
        }));
    }
    let base = base_builder.build();

    let mut pr_builder = IncludeGraphBuilder::new();
    // PR removes the edge at the middle of the chain (index 5000 → 5001).
    for i in 0..N - 1 {
        if i == 5000 {
            continue; // severed
        }
        pr_builder.add_edges(std::iter::once(IncludeEdge {
            from: format!("node_{i}.h"),
            to: format!("node_{}.h", i + 1),
        }));
    }
    let pr = pr_builder.build();

    let engine = DeltaEngine::new(&base, &pr);
    let (bonus, _threats, _entanglements) = engine.analyse();

    let elapsed = start.elapsed();

    assert!(
        bonus.is_some(),
        "removing chain edge must produce DeflationBonus"
    );
    // Release builds must complete in <50ms; debug builds are unoptimized and
    // may be up to 10× slower — the correctness assertion above is the binding
    // contract, the timing gate is a release-mode invariant.
    // 2000ms debug ceiling accounts for thread-contention under --test-threads=4.
    let limit_ms: u128 = if cfg!(debug_assertions) { 2000 } else { 50 };
    assert!(
        elapsed.as_millis() < limit_ms,
        "10k-node graph + delta must complete in <{}ms, took {}ms",
        limit_ms,
        elapsed.as_millis()
    );
}
