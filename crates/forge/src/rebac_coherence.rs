//! ReBAC Authorization Coherence Lattice — P2-5.
//!
//! Detects two authorization-race vulnerability classes in Zanzibar-class
//! systems (OpenFGA, AuthZed SpiceDB, Oso Cloud):
//!
//! ## Finding classes
//!
//! | ID | Trigger |
//! |----|---------|
//! | `security:rebac_coherence_gap` | Authorization predicate at `Eventual` consistency dominates a state-mutating sink without a re-check at `Strong` consistency. |
//! | `security:rebac_revocation_race` | Tuple-write precedes a check primitive in the same call context without consistency-token threading. |
//!
//! ## Detection strategy
//!
//! Both detectors operate on source text using a two-window scan:
//!
//! 1. **Coherence-gap**: locate an eventual-consistency token
//!    (`MINIMIZE_LATENCY`, `BEST_EFFORT`); confirm a check primitive appears
//!    within 512 bytes before it; confirm a mutation sink appears within
//!    1 024 bytes after it.  A `Strong`-consistency token in the same window
//!    suppresses the finding.
//!
//! 2. **Revocation-race**: locate a write-primitive call; confirm a check
//!    primitive appears within 1 024 bytes after it; if no consistency-
//!    threading token (`Zedtoken`, `zookie`, `AT_LEAST_AS_FRESH`, …) is
//!    present in that window, emit the finding.

use common::slop::StructuredFinding;

// ---------------------------------------------------------------------------
// 4-Tier Consistency Lattice
// ---------------------------------------------------------------------------

/// 4-tier consistency lattice for ReBAC authorization predicates.
///
/// Ordered weakest-to-strongest in the opposite direction of typical ordinals:
/// variants are numbered so that `Strong < BoundedStaleness < Eventual < Unknown`
/// under `derive(PartialOrd, Ord)` (lowest discriminant = strongest guarantee).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum ConsistencyLevel {
    /// Linearizable / fully consistent — guaranteed to reflect all prior writes.
    Strong,
    /// Bounded staleness — reflects all writes at least τ milliseconds old.
    BoundedStaleness,
    /// Eventual / cache-served — may return pre-revocation tuples.
    Eventual,
    /// No consistency information available.
    #[default]
    Unknown,
}

impl ConsistencyLevel {
    /// Pessimistic lattice composition: returns the weaker (higher-ordinal)
    /// level.  Used at control-flow join points where taint from multiple
    /// branches must be combined conservatively.
    pub fn meet(self, other: ConsistencyLevel) -> ConsistencyLevel {
        self.max(other)
    }

    /// Demote the level by one tier — applied when a predicate flows through
    /// a known cache primitive or is used at `MINIMIZE_LATENCY`.
    pub fn demote(self) -> ConsistencyLevel {
        match self {
            ConsistencyLevel::Strong => ConsistencyLevel::BoundedStaleness,
            ConsistencyLevel::BoundedStaleness => ConsistencyLevel::Eventual,
            ConsistencyLevel::Eventual | ConsistencyLevel::Unknown => ConsistencyLevel::Unknown,
        }
    }
}

// ---------------------------------------------------------------------------
// Static pattern tables
// ---------------------------------------------------------------------------

/// Argument tokens that signal eventual / stale consistency at a check site.
static EVENTUAL_CONSISTENCY_TOKENS: &[&str] = &["MINIMIZE_LATENCY", "BEST_EFFORT"];

/// Argument tokens that signal strong / linearizable consistency.
/// Presence of any of these in the analysis window suppresses findings.
static STRONG_CONSISTENCY_TOKENS: &[&str] = &[
    "HIGHER_CONSISTENCY",
    "FULL_CONSISTENCY",
    "AT_LEAST_AS_FRESH",
    "FULLY_CONSISTENT",
];

/// Bare function/method names that indicate a ReBAC authorization check.
static CHECK_PRIMITIVE_PATTERNS: &[&str] = &[
    "Check(",
    "BatchCheck(",
    "CheckPermission(",
    "BulkCheckPermission(",
    "authorize(",
    "bulk_authorize(",
    ".check(",
];

/// Bare function/method names that indicate a ReBAC tuple-write operation.
static WRITE_PRIMITIVE_PATTERNS: &[&str] = &[
    "WriteTuples(",
    "DeleteTuples(",
    "WriteRelationships(",
    "DeleteRelationships(",
    "bulk_tell(",
    ".tell(",
];

/// Substrings that indicate a state-mutating database sink.
static MUTATION_SINK_PATTERNS: &[&str] = &[
    "UpdateDocument(",
    "PutItem(",
    "DeleteItem(",
    "db.Update(",
    "db.Insert(",
    "db.Delete(",
    ".Update(",
    ".Insert(",
    ".Delete(",
    "ExecuteNonQuery(",
    "executeUpdate(",
    ".save(",
    ".Save(",
];

/// Tokens that indicate consistency-threading between a write and a check,
/// suppressing revocation-race findings.
static CONSISTENCY_THREAD_TOKENS: &[&str] = &[
    "Zedtoken",
    "zookie",
    "at_revision",
    "continuation_token",
    "AT_LEAST_AS_FRESH",
    "HIGHER_CONSISTENCY",
    "FULL_CONSISTENCY",
    "FULLY_CONSISTENT",
];

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Classify a source token as a [`ConsistencyLevel`].
///
/// Returns `Eventual` for known stale tokens, `Strong` for known linearizable
/// tokens, and `Unknown` for anything else.
pub fn classify_consistency(token: &str) -> ConsistencyLevel {
    if STRONG_CONSISTENCY_TOKENS.contains(&token) {
        ConsistencyLevel::Strong
    } else if EVENTUAL_CONSISTENCY_TOKENS.contains(&token) {
        ConsistencyLevel::Eventual
    } else {
        ConsistencyLevel::Unknown
    }
}

/// Scan `source` for authorization predicates at eventual consistency that
/// dominate state-mutating sinks.
///
/// Emits `security:rebac_coherence_gap` at `KevCritical` when:
/// - An eventual-consistency token (`MINIMIZE_LATENCY`, `BEST_EFFORT`) is
///   found.
/// - A check primitive appears within 512 bytes before the token.
/// - A mutation sink appears within 1 024 bytes after the token.
/// - No strong-consistency token appears in the forward window.
pub fn find_coherence_gaps(source: &str, file_path: &str) -> Vec<StructuredFinding> {
    for &eventual_token in EVENTUAL_CONSISTENCY_TOKENS {
        let Some(tok_idx) = source.find(eventual_token) else {
            continue;
        };

        // Backward 512-byte window: require a check primitive.
        let check_start = tok_idx.saturating_sub(512);
        let backward = &source[check_start..tok_idx];
        if !CHECK_PRIMITIVE_PATTERNS
            .iter()
            .any(|n| backward.contains(n))
        {
            continue;
        }

        // Forward 1 024-byte window: require a mutation sink.
        let mutation_end = tok_idx.saturating_add(1024).min(source.len());
        let forward = &source[tok_idx..mutation_end];

        // A strong-consistency token in the forward window resolves the gap.
        if STRONG_CONSISTENCY_TOKENS
            .iter()
            .any(|t| forward.contains(t))
        {
            continue;
        }

        if !MUTATION_SINK_PATTERNS.iter().any(|p| forward.contains(p)) {
            continue;
        }

        return vec![StructuredFinding {
            id: "security:rebac_coherence_gap".to_string(),
            file: Some(file_path.to_string()),
            severity: Some("KevCritical".to_string()),
            remediation: Some(format!(
                "Authorization check at eventual consistency ({eventual_token}) dominates a \
                 state-mutating operation without an intervening strong-consistency re-check. \
                 Use HIGHER_CONSISTENCY / AT_LEAST_AS_FRESH or thread a Zedtoken from a prior \
                 strong read before the mutation."
            )),
            ..Default::default()
        }];
    }

    Vec::new()
}

/// Scan `source` for tuple-write operations followed by check primitives
/// without consistency-token threading.
///
/// Emits `security:rebac_revocation_race` at `High` when:
/// - A write primitive (`WriteTuples`, `WriteRelationships`, etc.) is found.
/// - A check primitive appears within 1 024 bytes after it.
/// - No consistency-threading token (`Zedtoken`, `AT_LEAST_AS_FRESH`, …) is
///   present in that window.
pub fn find_revocation_races(source: &str, file_path: &str) -> Vec<StructuredFinding> {
    let first_write = WRITE_PRIMITIVE_PATTERNS
        .iter()
        .filter_map(|p| source.find(p))
        .min();

    let Some(write_idx) = first_write else {
        return Vec::new();
    };

    let end = write_idx.saturating_add(1024).min(source.len());
    let window = &source[write_idx..end];

    if !CHECK_PRIMITIVE_PATTERNS.iter().any(|n| window.contains(n)) {
        return Vec::new();
    }

    if CONSISTENCY_THREAD_TOKENS.iter().any(|t| window.contains(t)) {
        return Vec::new();
    }

    vec![StructuredFinding {
        id: "security:rebac_revocation_race".to_string(),
        file: Some(file_path.to_string()),
        severity: Some("High".to_string()),
        remediation: Some(
            "Tuple-write precedes an authorization check without consistency-token threading. \
             Capture the Zedtoken / zookie from the write response and pass it to the \
             subsequent check via AT_LEAST_AS_FRESH / HIGHER_CONSISTENCY to prevent \
             stale-cache bypass after privilege revocation."
                .to_string(),
        ),
        ..Default::default()
    }]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- ConsistencyLevel lattice ---

    #[test]
    fn consistency_level_ordering_strong_lt_eventual() {
        assert!(
            ConsistencyLevel::Strong < ConsistencyLevel::Eventual,
            "Strong must be less than Eventual in the lattice"
        );
        assert!(
            ConsistencyLevel::Eventual < ConsistencyLevel::Unknown,
            "Eventual must be less than Unknown in the lattice"
        );
    }

    #[test]
    fn consistency_level_meet_returns_weaker() {
        let result = ConsistencyLevel::Strong.meet(ConsistencyLevel::Eventual);
        assert_eq!(
            result,
            ConsistencyLevel::Eventual,
            "meet(Strong, Eventual) must return Eventual (pessimistic)"
        );
    }

    #[test]
    fn consistency_level_demote_strong_to_bounded_staleness() {
        assert_eq!(
            ConsistencyLevel::Strong.demote(),
            ConsistencyLevel::BoundedStaleness
        );
        assert_eq!(
            ConsistencyLevel::BoundedStaleness.demote(),
            ConsistencyLevel::Eventual
        );
    }

    #[test]
    fn classify_consistency_maps_minimize_latency_to_eventual() {
        assert_eq!(
            classify_consistency("MINIMIZE_LATENCY"),
            ConsistencyLevel::Eventual
        );
    }

    #[test]
    fn classify_consistency_maps_higher_consistency_to_strong() {
        assert_eq!(
            classify_consistency("HIGHER_CONSISTENCY"),
            ConsistencyLevel::Strong
        );
    }

    // --- find_coherence_gaps ---

    #[test]
    fn eventual_consistency_check_before_db_write_triggers_coherence_gap() {
        let source = r#"
            func editDocument(ctx context.Context, userID string, docID string) error {
                allowed, _ := fgaClient.Check(ctx, ClientCheckRequest{},
                    ClientCheckOptions{Consistency: openfga.MINIMIZE_LATENCY})
                if !allowed { return ErrForbidden }
                return db.UpdateDocument(ctx, docID)
            }
        "#;
        let findings = find_coherence_gaps(source, "api/handler.go");
        assert!(
            findings.iter().any(|f| f.id == "security:rebac_coherence_gap"),
            "eventual-consistency check before db.UpdateDocument must emit coherence gap finding, got: {findings:?}"
        );
        assert_eq!(
            findings[0].severity.as_deref(),
            Some("KevCritical"),
            "coherence gap must be KevCritical severity"
        );
    }

    #[test]
    fn strong_consistency_check_does_not_trigger_coherence_gap() {
        let source = r#"
            func editDocument(ctx context.Context, userID string, docID string) error {
                allowed, _ := fgaClient.Check(ctx, ClientCheckRequest{},
                    ClientCheckOptions{Consistency: openfga.HIGHER_CONSISTENCY})
                if !allowed { return ErrForbidden }
                return db.UpdateDocument(ctx, docID)
            }
        "#;
        let findings = find_coherence_gaps(source, "api/handler.go");
        assert!(
            findings.is_empty(),
            "HIGHER_CONSISTENCY check must not trigger coherence gap, got: {findings:?}"
        );
    }

    #[test]
    fn eventual_check_without_mutation_does_not_trigger() {
        let source = r#"
            func readDocument(ctx context.Context) (bool, error) {
                allowed, _ := fgaClient.Check(ctx, req,
                    ClientCheckOptions{Consistency: openfga.MINIMIZE_LATENCY})
                return allowed, nil
            }
        "#;
        let findings = find_coherence_gaps(source, "api/reader.go");
        assert!(
            findings.is_empty(),
            "eventual check with no mutation sink must not trigger coherence gap, got: {findings:?}"
        );
    }

    // --- find_revocation_races ---

    #[test]
    fn tuple_write_before_check_without_token_triggers_revocation_race() {
        let source = r#"
            func revokeAndCheck(ctx context.Context) error {
                fgaClient.WriteTuples(ctx, []ClientTupleKey{{User: "user:bad", Relation: "editor", Object: "doc:1"}})
                allowed, _ := fgaClient.Check(ctx, ClientCheckRequest{})
                if allowed { return ErrShouldBeRevoked }
                return nil
            }
        "#;
        let findings = find_revocation_races(source, "service/auth.go");
        assert!(
            findings.iter().any(|f| f.id == "security:rebac_revocation_race"),
            "WriteTuples before Check without consistency token must emit revocation race, got: {findings:?}"
        );
    }

    #[test]
    fn revocation_race_suppressed_when_zedtoken_threaded() {
        let source = r#"
            func revokeAndCheckWithToken(ctx context.Context) error {
                resp, _ := fgaClient.WriteTuples(ctx, tuples)
                token := resp.Zedtoken
                _ = token
                allowed, _ := fgaClient.Check(ctx, ClientCheckRequest{})
                return nil
            }
        "#;
        let findings = find_revocation_races(source, "service/auth.go");
        assert!(
            findings.is_empty(),
            "Zedtoken threading must suppress revocation race finding, got: {findings:?}"
        );
    }

    #[test]
    fn write_without_subsequent_check_does_not_trigger_race() {
        let source = r#"
            func revokeOnly(ctx context.Context) error {
                fgaClient.WriteTuples(ctx, tuples)
                return db.UpdateDocument(ctx, docID)
            }
        "#;
        let findings = find_revocation_races(source, "service/auth.go");
        assert!(
            findings.is_empty(),
            "write with no subsequent check must not emit revocation race, got: {findings:?}"
        );
    }
}
