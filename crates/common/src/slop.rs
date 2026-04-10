//! Shared finding DTOs for the Janitor MCP protocol.
//!
//! [`StructuredFinding`] is the canonical machine-readable envelope emitted by
//! `janitor_bounce` and `janitor_scan`.  Consumers (agents, CI integrations, IDE
//! plugins) parse this instead of regex-matching human-readable prose strings,
//! enabling deterministic pre-commit remediation and structured audit logging.

use serde::{Deserialize, Serialize};

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
}
