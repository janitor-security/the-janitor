//! Shared finding DTOs for the Janitor MCP protocol.
//!
//! [`StructuredFinding`] is the canonical machine-readable envelope emitted by
//! `janitor_bounce` and `janitor_scan`.  Consumers (agents, CI integrations, IDE
//! plugins) parse this instead of regex-matching human-readable prose strings,
//! enabling deterministic pre-commit remediation and structured audit logging.

use serde::{Deserialize, Serialize};

/// Regulatory regime identifiers recognized by Janitor structured findings.
pub const RECOGNIZED_REGULATORY_REGIMES: &[&str] = &[
    "GLBA",
    "EU_AI_Act_Art_10",
    "EU_NIS2",
    "EU_DORA",
    "NYDFS_500_11",
    "OCC_2024_32",
];

/// Structured verification harness artifact synthesized by the Kani bridge (P4-1).
///
/// Encapsulates the harness source text and run command emitted by
/// `crates/forge/src/kani_bridge::synthesize_kani_harness`. The artifact is
/// stored on [`ExploitWitness`] so it is carried through to SARIF and Bugcrowd
/// exports without requiring a separate pipeline lookup.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarnessArtifact {
    /// Name of the vulnerable function the harness exercises.
    pub function_name: String,
    /// Human-readable list of symbolic input descriptions (one per `kani::any()` call).
    pub inputs: Vec<String>,
    /// The safety assertion proven by the harness (negation of the bug class invariant).
    pub assertion: String,
    /// Complete harness source text (C or Rust) ready to be written to a temp file.
    pub harness_source: String,
    /// CLI command to invoke the bounded model checker, e.g.
    /// `cargo kani --harness harness_foo`.
    pub run_command: String,
}

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
    /// Deterministic IFDS proof path that established the taint chain, or a
    /// human-readable summary of the symbolic path used to prove reachability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_proof: Option<String>,
    /// Inert exploit payload blob (base64 or text) synthesized for
    /// deserialization and parser-injection findings.  Never contains live
    /// shellcode; use a signed Wasm policy to enable red-team mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<String>,
    /// Ordered human-readable steps to reproduce the vulnerability using the
    /// attached `payload`.  Populated by the deserialization and parser
    /// payload synthesis pipelines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reproduction_steps: Option<Vec<String>>,
    /// CVSS-informed plain-text risk classification, e.g.
    /// `"Critical RCE via Java ObjectOutputStream deserialization"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub risk_classification: Option<String>,
    /// `Some(true)` when Configuration Taint analysis proved the sink's source
    /// is a static developer-configured value (e.g., a compiled Stylus bundle),
    /// not an attacker-controlled runtime input — finding is pattern-true but
    /// exploitability-false.  `Some(false)` when a dynamic taint flow was confirmed.
    /// `None` when the analysis was not run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_source_proven: Option<bool>,
    /// Kani / CBMC bounded-model-checker harness synthesized from this witness
    /// by the P4-1 formal verification bridge. `None` when the harness synthesizer
    /// was not run or the witness lacked sufficient structural information.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub harness_artifact: Option<HarnessArtifact>,
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

    /// Regulatory compliance regimes implicated by this finding, e.g.
    /// `["GLBA", "EU_AI_Act_Art_10", "EU_NIS2", "EU_DORA", "NYDFS_500_11", "OCC_2024_32"]`.
    ///
    /// Populated by detectors with statutory exposure (Financial PII, health
    /// data, COPPA-scope children's data). Surfaced in SARIF `help.markdown`
    /// and Bugcrowd VRT exports.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub regulatory_regimes: Option<Vec<String>>,

    /// Estimated minimum regulatory fine floor in USD for this finding class.
    ///
    /// Populated alongside `regulatory_regimes` to support CFO-tier risk
    /// quantification in the actuarial ledger. `None` for findings without
    /// statutory dollar exposure (e.g. dead-code, logic clone).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_fine_floor_usd: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_source_proven_serializes_and_deserializes_correctly() {
        let finding = StructuredFinding {
            id: "security:dom_xss_innerHTML".to_string(),
            file: Some("src/core.js".to_string()),
            line: Some(248),
            fingerprint: "abc123".to_string(),
            severity: Some("Informational".to_string()),
            exploit_witness: Some(ExploitWitness {
                static_source_proven: Some(true),
                source_label: "static compiled bundle".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&finding).expect("serialization must not fail");
        assert!(
            json.contains("static_source_proven"),
            "field must appear in JSON output"
        );
        assert!(json.contains("true"), "value must be true");
        let round_trip: StructuredFinding =
            serde_json::from_str(&json).expect("deserialization must not fail");
        assert_eq!(
            round_trip.exploit_witness.unwrap().static_source_proven,
            Some(true)
        );
    }

    #[test]
    fn static_source_proven_none_omitted_from_json() {
        let finding = StructuredFinding {
            id: "security:command_injection".to_string(),
            exploit_witness: Some(ExploitWitness {
                static_source_proven: None,
                ..Default::default()
            }),
            ..Default::default()
        };
        let json = serde_json::to_string(&finding).expect("serialization must not fail");
        assert!(
            !json.contains("static_source_proven"),
            "None field must be omitted from JSON to preserve schema backwards-compatibility"
        );
    }
}
