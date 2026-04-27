//! ReBAC primitive catalog for authorization coherence analysis (P2-5).
//!
//! Provides a static table of known check, write, and list primitives across
//! the three major Zanzibar-class authorization libraries targeted by Sprint
//! Batch 64: OpenFGA, AuthZed (SpiceDB), and Oso Cloud.
//!
//! Each [`RebacPrimitive`] entry documents:
//! - The bare function/method name as it appears at call sites.
//! - Its semantic [`PrimitiveKind`] (check / write / list).
//! - Argument tokens that signal **eventual** (stale) consistency.
//! - Argument tokens that signal **strong** (linearizable) consistency.
//!
//! The `eventual_tokens` / `strong_tokens` fields are matched as substrings
//! against the surrounding call-site source window by the coherence detector
//! in `rebac_coherence.rs`.

// ---------------------------------------------------------------------------
// Primitive kind
// ---------------------------------------------------------------------------

/// Semantic category of a ReBAC library primitive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrimitiveKind {
    /// Authorization predicate evaluation — may return stale results.
    Check,
    /// Relationship tuple create / delete — always linearizable.
    Write,
    /// Enumerate relationships or resources.
    List,
}

// ---------------------------------------------------------------------------
// Catalog entry
// ---------------------------------------------------------------------------

/// One entry in the static ReBAC primitive catalog.
#[derive(Debug, Clone)]
pub struct RebacPrimitive {
    /// Originating library / SDK.
    pub library: &'static str,
    /// Bare function or method name (not qualified).
    pub function_name: &'static str,
    /// Semantic kind of the primitive.
    pub kind: PrimitiveKind,
    /// Argument tokens that signal eventual / stale consistency.
    pub eventual_tokens: &'static [&'static str],
    /// Argument tokens that signal strong / linearizable consistency.
    pub strong_tokens: &'static [&'static str],
}

// ---------------------------------------------------------------------------
// Static catalog
// ---------------------------------------------------------------------------

/// Static ReBAC primitive catalog covering OpenFGA, AuthZed, and Oso Cloud.
pub static REBAC_PRIMITIVES: &[RebacPrimitive] = &[
    // ------------------------------------------------------------------
    // OpenFGA — github.com/openfga/go-sdk
    // ------------------------------------------------------------------
    RebacPrimitive {
        library: "OpenFGA",
        function_name: "Check",
        kind: PrimitiveKind::Check,
        eventual_tokens: &["MINIMIZE_LATENCY"],
        strong_tokens: &["HIGHER_CONSISTENCY"],
    },
    RebacPrimitive {
        library: "OpenFGA",
        function_name: "BatchCheck",
        kind: PrimitiveKind::Check,
        eventual_tokens: &["MINIMIZE_LATENCY"],
        strong_tokens: &["HIGHER_CONSISTENCY"],
    },
    RebacPrimitive {
        library: "OpenFGA",
        function_name: "Write",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "OpenFGA",
        function_name: "WriteTuples",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "OpenFGA",
        function_name: "DeleteTuples",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "OpenFGA",
        function_name: "ListObjects",
        kind: PrimitiveKind::List,
        eventual_tokens: &["MINIMIZE_LATENCY"],
        strong_tokens: &["HIGHER_CONSISTENCY"],
    },
    // ------------------------------------------------------------------
    // AuthZed / SpiceDB — github.com/authzed/authzed-go
    // ------------------------------------------------------------------
    RebacPrimitive {
        library: "AuthZed",
        function_name: "CheckPermission",
        kind: PrimitiveKind::Check,
        eventual_tokens: &["MINIMIZE_LATENCY", "BEST_EFFORT"],
        strong_tokens: &["FULL_CONSISTENCY", "AT_LEAST_AS_FRESH"],
    },
    RebacPrimitive {
        library: "AuthZed",
        function_name: "BulkCheckPermission",
        kind: PrimitiveKind::Check,
        eventual_tokens: &["MINIMIZE_LATENCY", "BEST_EFFORT"],
        strong_tokens: &["FULL_CONSISTENCY", "AT_LEAST_AS_FRESH"],
    },
    RebacPrimitive {
        library: "AuthZed",
        function_name: "WriteRelationships",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "AuthZed",
        function_name: "DeleteRelationships",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "AuthZed",
        function_name: "LookupResources",
        kind: PrimitiveKind::List,
        eventual_tokens: &["MINIMIZE_LATENCY", "BEST_EFFORT"],
        strong_tokens: &["FULL_CONSISTENCY", "AT_LEAST_AS_FRESH"],
    },
    // ------------------------------------------------------------------
    // Oso Cloud — github.com/osohq/go-oso-cloud
    // ------------------------------------------------------------------
    RebacPrimitive {
        library: "Oso",
        function_name: "authorize",
        kind: PrimitiveKind::Check,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "Oso",
        function_name: "authorize_local",
        kind: PrimitiveKind::Check,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "Oso",
        function_name: "bulk_authorize",
        kind: PrimitiveKind::Check,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "Oso",
        function_name: "tell",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "Oso",
        function_name: "bulk_tell",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
    RebacPrimitive {
        library: "Oso",
        function_name: "delete",
        kind: PrimitiveKind::Write,
        eventual_tokens: &[],
        strong_tokens: &[],
    },
];

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_covers_three_providers() {
        let providers: std::collections::HashSet<&str> =
            REBAC_PRIMITIVES.iter().map(|p| p.library).collect();
        assert!(providers.contains("OpenFGA"), "OpenFGA must be in catalog");
        assert!(providers.contains("AuthZed"), "AuthZed must be in catalog");
        assert!(providers.contains("Oso"), "Oso must be in catalog");
    }

    #[test]
    fn openfga_check_has_minimize_latency_token() {
        let entry = REBAC_PRIMITIVES
            .iter()
            .find(|p| p.library == "OpenFGA" && p.function_name == "Check")
            .expect("OpenFGA Check must be in catalog");
        assert!(
            entry.eventual_tokens.contains(&"MINIMIZE_LATENCY"),
            "OpenFGA Check must list MINIMIZE_LATENCY as eventual token"
        );
        assert!(
            entry.strong_tokens.contains(&"HIGHER_CONSISTENCY"),
            "OpenFGA Check must list HIGHER_CONSISTENCY as strong token"
        );
    }

    #[test]
    fn authzed_check_has_at_least_as_fresh_token() {
        let entry = REBAC_PRIMITIVES
            .iter()
            .find(|p| p.library == "AuthZed" && p.function_name == "CheckPermission")
            .expect("AuthZed CheckPermission must be in catalog");
        assert!(
            entry.strong_tokens.contains(&"AT_LEAST_AS_FRESH"),
            "AuthZed CheckPermission must list AT_LEAST_AS_FRESH as strong token"
        );
    }

    #[test]
    fn write_primitives_have_no_consistency_tokens() {
        for entry in REBAC_PRIMITIVES
            .iter()
            .filter(|p| p.kind == PrimitiveKind::Write)
        {
            assert!(
                entry.eventual_tokens.is_empty() && entry.strong_tokens.is_empty(),
                "Write primitive '{}::{}' must have no consistency tokens — writes are always linearizable",
                entry.library, entry.function_name
            );
        }
    }
}
