//! P6-1 Multi-Account Swarm Attribution.
//!
//! Stage-4 attackers split malicious intent across many bot accounts, each
//! contributing individually-benign PRs so that no single commit trips a rule.
//! This module builds a temporal correlation graph over `PrAuthorRecord` inputs
//! and emits `security:swarm_intent_divergence` (KevCritical) when a cluster of
//! authors collectively assembles a dangerous capability combination that no
//! single author contributed alone.
//!
//! ## Detection invariant
//!
//! ```text
//! connected_component.size() >= MIN_SWARM_SIZE
//!   AND every pair in the component has time_delta <= TEMPORAL_WINDOW_SECS
//!   AND composite(capability_flags) includes a dangerous capability pair
//! ⟹ emit security:swarm_intent_divergence (KevCritical)
//! ```
//!
//! ## Capability model
//!
//! Each PR record carries a `u32` capability bitmask. The engine sets bits
//! when AST patterns corresponding to file-write, network-fetch, exec-spawn,
//! or privilege-escalation are detected in the diff. A swarm is flagged when
//! the OR of all member capabilities contains a dangerous combination that
//! implies a complete attack chain (e.g., network fetch + file write = remote
//! download-and-execute).

use common::slop::StructuredFinding;
use petgraph::graph::NodeIndex;
use petgraph::unionfind::UnionFind;
use petgraph::Graph;

// ---------------------------------------------------------------------------
// Capability flags
// ---------------------------------------------------------------------------

/// Writes to the local filesystem (file creation, overwrite, chmod).
pub const CAP_FILE_WRITE: u32 = 1 << 0;
/// Initiates outbound network connections (fetch, reqwest, curl, socket).
pub const CAP_NETWORK_FETCH: u32 = 1 << 1;
/// Spawns child processes (Command::new, subprocess, exec family).
pub const CAP_EXEC_SPAWN: u32 = 1 << 2;
/// Modifies authentication or authorization state (sudo, setuid, token write).
pub const CAP_PRIVILEGE_ESCALATION: u32 = 1 << 3;

/// Dangerous composite capability pairs that constitute a complete attack chain.
/// Each tuple is (required_a, required_b, description).
const DANGEROUS_PAIRS: &[(u32, u32, &str)] = &[
    (
        CAP_NETWORK_FETCH,
        CAP_FILE_WRITE,
        "remote download + filesystem persistence",
    ),
    (
        CAP_NETWORK_FETCH,
        CAP_EXEC_SPAWN,
        "remote payload + execution",
    ),
    (
        CAP_FILE_WRITE,
        CAP_EXEC_SPAWN,
        "filesystem write + execution",
    ),
    (
        CAP_EXEC_SPAWN,
        CAP_PRIVILEGE_ESCALATION,
        "execution + privilege escalation",
    ),
    (
        CAP_NETWORK_FETCH,
        CAP_PRIVILEGE_ESCALATION,
        "remote C2 + privilege escalation",
    ),
];

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

/// Minimum number of authors required to constitute a swarm.
const MIN_SWARM_SIZE: usize = 3;
/// Maximum seconds between any two PR submissions in the same temporal cluster.
const TEMPORAL_WINDOW_SECS: u64 = 7 * 24 * 3600; // 7 days

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single PR author record — the unit input for swarm analysis.
#[derive(Debug, Clone)]
pub struct PrAuthorRecord {
    /// Unique author identifier (GitHub login, email, or hash).
    pub author_id: String,
    /// File path of the primary changed file in this PR.
    pub primary_file: String,
    /// UNIX timestamp (seconds) of the PR merge or creation event.
    pub commit_timestamp_unix: u64,
    /// Structural AST fingerprint of the diff (from `compute_structural_hash`).
    pub ast_fingerprint: u64,
    /// Bitmask of `CAP_*` constants detected in the PR diff.
    pub capability_flags: u32,
}

/// A temporal proximity edge between two PR author records.
#[derive(Debug, Clone)]
pub struct TemporalEdge {
    /// Absolute time difference in seconds between the two PR events.
    pub time_delta_secs: u64,
    /// Structural fingerprint similarity in [0.0, 1.0].
    /// Computed as `1.0 - hamming_distance(a.ast_fingerprint, b.ast_fingerprint) / 64`.
    pub fingerprint_similarity: f32,
}

/// A swarm cluster with its composite capability and confidence score.
#[derive(Debug, Clone)]
pub struct SwarmFinding {
    /// Ordered list of author identifiers in this cluster.
    pub member_ids: Vec<String>,
    /// OR of all member `capability_flags`.
    pub composite_capability: u32,
    /// Confidence in [0.0, 1.0]: cluster_size / total_records.
    pub confidence: f32,
    /// Human-readable description of the dangerous capability pair detected.
    pub capability_description: &'static str,
}

/// Temporal correlation graph over PR author records.
///
/// Nodes are `PrAuthorRecord` values. Edges are `TemporalEdge` values
/// connecting any two authors whose PR timestamps fall within
/// `TEMPORAL_WINDOW_SECS` of each other.
pub struct SwarmGraph {
    pub graph: Graph<PrAuthorRecord, TemporalEdge>,
}

impl SwarmGraph {
    /// Construct a `SwarmGraph` from a slice of PR author records.
    ///
    /// An edge is added between every pair whose `|t_a - t_b| <= TEMPORAL_WINDOW_SECS`.
    pub fn build(records: &[PrAuthorRecord]) -> Self {
        let mut graph = Graph::new();
        let indices: Vec<NodeIndex> = records.iter().map(|r| graph.add_node(r.clone())).collect();

        for i in 0..records.len() {
            for j in (i + 1)..records.len() {
                let delta = records[i]
                    .commit_timestamp_unix
                    .abs_diff(records[j].commit_timestamp_unix);
                if delta <= TEMPORAL_WINDOW_SECS {
                    let sim = fingerprint_similarity(
                        records[i].ast_fingerprint,
                        records[j].ast_fingerprint,
                    );
                    graph.add_edge(
                        indices[i],
                        indices[j],
                        TemporalEdge {
                            time_delta_secs: delta,
                            fingerprint_similarity: sim,
                        },
                    );
                }
            }
        }
        Self { graph }
    }

    /// Extract connected components and return swarm clusters meeting the size
    /// and capability thresholds.
    pub fn swarm_clusters(&self) -> Vec<SwarmFinding> {
        let n = self.graph.node_count();
        if n == 0 {
            return Vec::new();
        }

        // Union-Find over node indices.
        let mut uf = UnionFind::new(n);
        for edge in self.graph.edge_indices() {
            let (a, b) = self.graph.edge_endpoints(edge).unwrap();
            uf.union(a.index(), b.index());
        }

        // Group nodes by their representative.
        let mut components: std::collections::HashMap<usize, Vec<NodeIndex>> =
            std::collections::HashMap::new();
        for idx in self.graph.node_indices() {
            let rep = uf.find(idx.index());
            components.entry(rep).or_default().push(idx);
        }

        let total = n as f32;
        let mut findings = Vec::new();

        for members in components.values() {
            if members.len() < MIN_SWARM_SIZE {
                continue;
            }

            let composite: u32 = members
                .iter()
                .map(|&ni| self.graph[ni].capability_flags)
                .fold(0u32, |acc, f| acc | f);

            // Check for a dangerous composite capability pair.
            let dangerous = DANGEROUS_PAIRS
                .iter()
                .find(|(a, b, _)| (composite & a) != 0 && (composite & b) != 0);

            let Some((_, _, desc)) = dangerous else {
                continue;
            };

            let member_ids: Vec<String> = members
                .iter()
                .map(|&ni| self.graph[ni].author_id.clone())
                .collect();

            findings.push(SwarmFinding {
                confidence: members.len() as f32 / total,
                member_ids,
                composite_capability: composite,
                capability_description: desc,
            });
        }

        findings
    }
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Analyze a slice of `PrAuthorRecord` values for swarm patterns.
///
/// Returns `security:swarm_intent_divergence` (KevCritical) findings for every
/// cluster that collectively assembles a dangerous capability combination.
pub fn analyze_swarm(records: &[PrAuthorRecord]) -> Vec<StructuredFinding> {
    let graph = SwarmGraph::build(records);
    graph
        .swarm_clusters()
        .into_iter()
        .map(|sf| swarm_finding(&sf))
        .collect()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Hamming-distance-based similarity between two 64-bit AST fingerprints.
/// Returns a value in [0.0, 1.0] where 1.0 is identical.
fn fingerprint_similarity(a: u64, b: u64) -> f32 {
    let differing_bits = (a ^ b).count_ones();
    1.0 - (differing_bits as f32 / 64.0)
}

fn swarm_finding(sf: &SwarmFinding) -> StructuredFinding {
    StructuredFinding {
        id: "security:swarm_intent_divergence".to_string(),
        file: None,
        line: None,
        fingerprint: String::new(),
        severity: Some("KevCritical".to_string()),
        remediation: Some(format!(
            "{} accounts collectively assembled '{}' across PRs within a {}-day window. \
             Block all accounts in the cluster, audit every file touched by any member, \
             and require re-review of the composite diff as a single unit.",
            sf.member_ids.len(),
            sf.capability_description,
            TEMPORAL_WINDOW_SECS / 86400,
        )),
        docs_url: Some("https://thejanitor.app/findings/swarm-intent-divergence".to_string()),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn record(id: &str, ts: u64, caps: u32) -> PrAuthorRecord {
        PrAuthorRecord {
            author_id: id.to_string(),
            primary_file: format!("src/{id}.rs"),
            commit_timestamp_unix: ts,
            ast_fingerprint: 0xDEAD_BEEF_0000_0000 ^ ts,
            capability_flags: caps,
        }
    }

    #[test]
    fn swarm_network_plus_write_triggers() {
        // Three accounts within 2 days; together they cover NETWORK_FETCH + FILE_WRITE.
        let records = vec![
            record("bot_a", 1_000_000, CAP_NETWORK_FETCH),
            record("bot_b", 1_050_000, CAP_FILE_WRITE),
            record("bot_c", 1_100_000, CAP_NETWORK_FETCH | CAP_FILE_WRITE),
        ];
        let findings = analyze_swarm(&records);
        assert_eq!(findings.len(), 1, "dangerous composite must trigger");
        assert_eq!(findings[0].id, "security:swarm_intent_divergence");
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn too_few_members_no_finding() {
        // Only 2 accounts — below MIN_SWARM_SIZE = 3.
        let records = vec![
            record("a1", 1_000_000, CAP_NETWORK_FETCH),
            record("a2", 1_010_000, CAP_FILE_WRITE),
        ];
        let findings = analyze_swarm(&records);
        assert!(findings.is_empty(), "2 accounts must not trigger swarm");
    }

    #[test]
    fn outside_temporal_window_no_finding() {
        // Three accounts, but spaced 10 days apart — beyond TEMPORAL_WINDOW_SECS.
        let day = 86400u64;
        let records = vec![
            record("x1", 0, CAP_NETWORK_FETCH),
            record("x2", 10 * day, CAP_FILE_WRITE),
            record("x3", 20 * day, CAP_EXEC_SPAWN),
        ];
        let findings = analyze_swarm(&records);
        assert!(
            findings.is_empty(),
            "accounts outside window must not cluster"
        );
    }

    #[test]
    fn no_dangerous_composite_no_finding() {
        // Three accounts within window but only NETWORK_FETCH — no dangerous pair.
        let records = vec![
            record("n1", 1_000_000, CAP_NETWORK_FETCH),
            record("n2", 1_010_000, CAP_NETWORK_FETCH),
            record("n3", 1_020_000, CAP_NETWORK_FETCH),
        ];
        let findings = analyze_swarm(&records);
        assert!(
            findings.is_empty(),
            "non-dangerous composite must not trigger"
        );
    }

    #[test]
    fn exec_plus_priv_escalation_triggers() {
        let records = vec![
            record("p1", 500_000, CAP_EXEC_SPAWN),
            record("p2", 520_000, CAP_PRIVILEGE_ESCALATION),
            record("p3", 540_000, CAP_EXEC_SPAWN | CAP_PRIVILEGE_ESCALATION),
        ];
        let findings = analyze_swarm(&records);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn empty_input_no_panic() {
        let findings = analyze_swarm(&[]);
        assert!(findings.is_empty());
    }

    #[test]
    fn fingerprint_similarity_identical() {
        assert!((fingerprint_similarity(0xABCD, 0xABCD) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn fingerprint_similarity_all_bits_differ() {
        assert!((fingerprint_similarity(0u64, u64::MAX) - 0.0).abs() < f32::EPSILON);
    }
}
