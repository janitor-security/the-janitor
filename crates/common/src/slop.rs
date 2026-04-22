//! Shared finding DTOs for the Janitor MCP protocol.
//!
//! [`StructuredFinding`] is the canonical machine-readable envelope emitted by
//! `janitor_bounce` and `janitor_scan`.  Consumers (agents, CI integrations, IDE
//! plugins) parse this instead of regex-matching human-readable prose strings,
//! enabling deterministic pre-commit remediation and structured audit logging.

use serde::{Deserialize, Serialize};

/// Deterministic exploitability proof for a confirmed source-to-sink chain.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExploitWitness {
    /// Function where the tainted source originates.
    pub source_function: String,
    /// Human-readable label of the tainted source fact.
    pub source_label: String,
    /// Function that contains the reached sink.
    pub sink_function: String,
    /// Human-readable label of the reached sink.
    pub sink_label: String,
    /// Exact interprocedural call chain proving reachability.
    pub call_chain: Vec<String>,
    /// Verified deserialization gadget path when the finding proves an RCE
    /// chain against repository dependency evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gadget_chain: Option<Vec<String>>,
    /// Concrete reproduction command synthesised from a Z3 model after
    /// symbolic execution confirms the path is satisfiable. `None` when the
    /// Z3 refinement stage was not run, was inconclusive, or the witness was
    /// emitted by a detector without a repro template.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repro_cmd: Option<String>,
    /// Deterministic negative-taint audit proving that at least one
    /// source-to-sink path bypasses all registered sanitizers or validators.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sanitizer_audit: Option<String>,
    /// HTTP route path associated with the ingress handler, e.g. `"/api/v1/users"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_path: Option<String>,
    /// HTTP method associated with the ingress handler, e.g. `"POST"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_method: Option<String>,
    /// Optional authorization annotation or middleware requirement extracted
    /// from the ingress handler, e.g. `"ADMIN"` or `"Authenticated"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_requirement: Option<String>,
    /// True when negative-taint analysis proves that at least one reachable
    /// source-to-sink path bypasses all registered sanitizers or validators.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub upstream_validation_absent: bool,
    /// Captured HTTP response from executing `repro_cmd` against a live test
    /// tenant via `--live-tenant`. `None` when the flag was not supplied or
    /// the command was not executed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_proof: Option<String>,
}

/// A structured antipattern or dead-symbol finding for MCP tool consumption.
///
/// Fields map to the `{ "id": "security:...", "file": "src/main.rs", "line": 42 }`
/// envelope required by the P1-3 structured-findings mandate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredFinding {
    /// Machine-readable finding identifier, e.g. `"security:command_injection"`,
    /// `"dead_symbol"`, or `"architecture:version_silo"`.
    pub id: String,

    /// Relative path of the file containing the finding.
    ///
    /// `None` when the bounce path operates on a unified diff without per-file
    /// tracking (e.g. the MCP `janitor_bounce` tool receiving a raw patch string
    /// without `bounce_git` context).
    pub file: Option<String>,

    /// 1-indexed line number of the finding within the file.
    ///
    /// `None` for findings that are not line-addressable (e.g. symbol-level dead
    /// code entries where only the symbol name is known).
    pub line: Option<u32>,

    /// Deterministic BLAKE3 fingerprint of the finding's structural root.
    #[serde(default)]
    pub fingerprint: String,

    /// Severity tier of the finding, e.g. `"KevCritical"` or `"Critical"`.
    ///
    /// Optional for backwards compatibility with pre-severity structured
    /// findings and synthetic report-derived findings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<String>,

    /// Actionable remediation instruction for the developer, e.g.
    /// `"Remove the hallucinated dependency from your manifest and run cargo update"`.
    ///
    /// `None` for findings that have no structured remediation guidance yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,

    /// Stable documentation URL for this finding class, e.g.
    /// `"https://thejanitor.app/findings/security-slopsquat-injection"`.
    ///
    /// Mapped to `helpUri` in SARIF output so GitHub Advanced Security and
    /// Azure DevOps surface the "How to fix" link inside the PR review UI.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub docs_url: Option<String>,

    /// Deterministic proof that a source reaches a sink across function boundaries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exploit_witness: Option<ExploitWitness>,

    /// True when the engine proved that at least one reachable source-to-sink
    /// path bypasses all registered sanitizers or validators.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub upstream_validation_absent: bool,
}
