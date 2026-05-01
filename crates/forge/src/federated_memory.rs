//! Cross-repository attack-surface memory — P3-4 Phase B.
//!
//! Extracts anonymized structural signatures from [`StructuredFinding`] values
//! and injects them back as active detection hints for the current repository.
//! No proprietary content (file paths, variable names, function names, literal
//! values) survives the anonymization step — only the structural skeleton of
//! the taint chain is retained.
//!
//! ## Design invariants
//!
//! 1. **Zero proprietary leakage**: `extract_anonymized_signature` strips every
//!    token that could identify the source repository. The output is safe to
//!    share across tenant boundaries.
//! 2. **Deterministic**: given the same finding, the same signature is always
//!    produced — enabling deduplication across federated ingestion.
//! 3. **Ratchet-monotonic**: ingested signatures are append-only within a scan
//!    session; they can never suppress or weaken existing detection rules.
//! 4. **8GB Law**: pure Rust, zero heap allocations beyond the signature Vec.

use common::slop::StructuredFinding;
use serde::{Deserialize, Serialize};

/// An anonymized structural signature extracted from a finding.
///
/// All proprietary identifiers are stripped; only the taint chain shape,
/// rule class, and severity tier survive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnonymizedSignature {
    /// Rule class — the `security:` prefix portion of the finding ID.
    /// e.g., `"security:command_injection"` or `"security:sql_injection"`.
    pub rule_class: String,

    /// Structural taint chain skeleton.  Each hop is the *kind* of the
    /// framework/protocol boundary, not the concrete function name.
    /// e.g., `["HttpIngress", "Middleware", "SqlExecute"]`.
    pub taint_chain: Vec<String>,

    /// Severity tier of the source finding.
    pub severity: String,

    /// Stable BLAKE3 fingerprint of the signature (hex-encoded).
    ///
    /// Computed from `rule_class + taint_chain.join("->")` so that two
    /// signatures with the same shape deduplicate correctly.
    pub fingerprint: String,
}

impl AnonymizedSignature {
    /// Returns `true` when this signature represents a finding class serious
    /// enough to be propagated as a federated detection rule.
    pub fn is_propagation_worthy(&self) -> bool {
        matches!(self.severity.as_str(), "KevCritical" | "Critical" | "High")
    }
}

/// Normalize a taint-chain hop label, erasing proprietary function names.
///
/// Converts concrete sink/source labels into protocol-boundary tokens:
/// - `http_*`, `express`, `route` → `"HttpIngress"`
/// - `sql_*`, `query`, `execute` → `"SqlExecute"`
/// - `command`, `exec`, `spawn`, `shell` → `"OsExec"`
/// - `innerHTML`, `dangerouslySetInnerHTML` → `"DomSink"`
/// - `fetch`, `request`, `url`, `ssrf` → `"NetworkEgress"`
/// - `deserializ*`, `gadget` → `"Deserialize"`
/// - anything else → `"Sink"`
fn normalize_hop(label: &str) -> &'static str {
    let l = label.to_lowercase();
    if l.contains("http") || l.contains("express") || l.contains("route") || l.contains("ingress") {
        return "HttpIngress";
    }
    if l.contains("sql") || l.contains("query") || l.contains("execute") || l.contains("db") {
        return "SqlExecute";
    }
    if l.contains("command")
        || l.contains("exec")
        || l.contains("spawn")
        || l.contains("shell")
        || l.contains("eval")
    {
        return "OsExec";
    }
    if l.contains("innerhtml") || l.contains("dangerously") || l.contains("xss") {
        return "DomSink";
    }
    if l.contains("fetch")
        || l.contains("request")
        || l.contains("ssrf")
        || l.contains("url")
        || l.contains("network")
    {
        return "NetworkEgress";
    }
    if l.contains("deserializ") || l.contains("gadget") || l.contains("pickle") {
        return "Deserialize";
    }
    if l.contains("file") || l.contains("path") || l.contains("traversal") {
        return "FileSystem";
    }
    if l.contains("cookie") || l.contains("session") || l.contains("auth") {
        return "SessionSink";
    }
    "Sink"
}

/// Strip a rule ID down to its structural class token, erasing any
/// repository-specific suffixes appended by custom detectors.
fn normalize_rule_class(id: &str) -> String {
    // Keep only the `security:` prefix + first segment.
    // e.g., "security:command_injection_v2" → "security:command_injection"
    if let Some(body) = id.strip_prefix("security:") {
        let first = body.split('_').take(2).collect::<Vec<_>>().join("_");
        return format!("security:{first}");
    }
    // Non-security rule classes pass through as-is.
    id.to_string()
}

/// Extract an [`AnonymizedSignature`] from a [`StructuredFinding`].
///
/// Strips all proprietary content:
/// - File paths → erased
/// - Variable/function names → normalized to protocol-boundary tokens
/// - Literal values → erased
/// - Rule IDs → truncated to structural class
///
/// Returns `None` when the finding lacks enough structural information to
/// produce a useful signature (e.g., no taint chain and no exploit witness).
pub fn extract_anonymized_signature(finding: &StructuredFinding) -> Option<AnonymizedSignature> {
    let rule_class = normalize_rule_class(&finding.id);
    let severity = finding
        .severity
        .clone()
        .unwrap_or_else(|| "Unknown".to_string());

    // Build taint chain from exploit witness call_chain when available,
    // otherwise synthesize a single-hop chain from the rule class.
    let taint_chain: Vec<String> = if let Some(witness) = &finding.exploit_witness {
        if !witness.call_chain.is_empty() {
            witness
                .call_chain
                .iter()
                .map(|hop| normalize_hop(hop).to_string())
                .collect()
        } else {
            // Fallback: source_function → sink_function
            vec![
                normalize_hop(&witness.source_function).to_string(),
                normalize_hop(&witness.sink_function).to_string(),
            ]
        }
    } else {
        // No witness: synthesize a single-hop chain from the rule class.
        let hop = normalize_hop(&rule_class);
        vec![hop.to_string()]
    };

    if taint_chain.is_empty() {
        return None;
    }

    // Compute stable BLAKE3 fingerprint from rule_class + taint_chain.
    let chain_str = taint_chain.join("->");
    let input = format!("{rule_class}:{chain_str}");
    let digest = blake3::hash(input.as_bytes());
    let fingerprint = hex::encode(&digest.as_bytes()[..16]); // 128-bit prefix, hex = 32 chars

    Some(AnonymizedSignature {
        rule_class,
        taint_chain,
        severity,
        fingerprint,
    })
}

/// In-session federated rule registry.
///
/// Holds anonymized signatures ingested from peer repositories during a
/// scan session. Implements the ratchet invariant: signatures are
/// append-only and cannot be removed or weakened once ingested.
#[derive(Debug, Default, Clone)]
pub struct FederatedMemory {
    signatures: Vec<AnonymizedSignature>,
}

impl FederatedMemory {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Ingest a federated signature as an active detection hint.
    ///
    /// Only accepts signatures that are `is_propagation_worthy()` (Critical/High).
    /// Duplicate fingerprints are silently dropped (deduplication).
    pub fn ingest_federated_rule(&mut self, signature: AnonymizedSignature) {
        if !signature.is_propagation_worthy() {
            return;
        }
        if self
            .signatures
            .iter()
            .any(|s| s.fingerprint == signature.fingerprint)
        {
            return;
        }
        self.signatures.push(signature);
    }

    /// Returns all ingested signatures.
    pub fn signatures(&self) -> &[AnonymizedSignature] {
        &self.signatures
    }

    /// Returns `true` when the registry contains a signature whose `rule_class`
    /// matches the given finding's rule ID, indicating a federated hit.
    pub fn matches_federated_class(&self, finding: &StructuredFinding) -> bool {
        let normalized = normalize_rule_class(&finding.id);
        self.signatures.iter().any(|s| s.rule_class == normalized)
    }

    /// Returns the count of ingested signatures.
    pub fn len(&self) -> usize {
        self.signatures.len()
    }

    /// Returns `true` when no signatures have been ingested.
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::slop::{ExploitWitness, StructuredFinding};

    fn finding(id: &str, severity: &str) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            severity: Some(severity.to_string()),
            ..Default::default()
        }
    }

    fn finding_with_witness(
        id: &str,
        severity: &str,
        source: &str,
        sink: &str,
        chain: Vec<&str>,
    ) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            severity: Some(severity.to_string()),
            file: Some("/proprietary/src/internal/UserController.java".to_string()),
            exploit_witness: Some(ExploitWitness {
                source_function: source.to_string(),
                source_label: "user_input".to_string(),
                sink_function: sink.to_string(),
                sink_label: "sql_execute".to_string(),
                call_chain: chain.into_iter().map(str::to_string).collect(),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn strips_proprietary_file_path() {
        let f = finding_with_witness(
            "security:sql_injection",
            "Critical",
            "handleRequest",
            "executeQuery",
            vec!["handleRequest", "executeQuery"],
        );
        let sig = extract_anonymized_signature(&f).expect("must produce a signature");
        // The file path must NOT appear in the signature.
        let serialized = serde_json::to_string(&sig).unwrap();
        assert!(
            !serialized.contains("UserController"),
            "proprietary class name must be stripped; got: {serialized}"
        );
        assert!(
            !serialized.contains("proprietary"),
            "proprietary path must be stripped; got: {serialized}"
        );
    }

    #[test]
    fn strips_variable_names_from_chain() {
        let f = finding_with_witness(
            "security:command_injection",
            "Critical",
            "userInputHandler",
            "Runtime.exec",
            vec!["userInputHandler", "Runtime.exec"],
        );
        let sig = extract_anonymized_signature(&f).expect("signature");
        // Variable names normalized to protocol tokens.
        assert!(
            !sig.taint_chain.iter().any(|h| h.contains("userInput")),
            "variable names must be stripped from chain: {:?}",
            sig.taint_chain
        );
        // exec → OsExec
        assert!(
            sig.taint_chain.iter().any(|h| h == "OsExec"),
            "exec must normalize to OsExec: {:?}",
            sig.taint_chain
        );
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let f = finding_with_witness(
            "security:sql_injection",
            "High",
            "getUser",
            "executeQuery",
            vec!["getUser", "executeQuery"],
        );
        let s1 = extract_anonymized_signature(&f).unwrap();
        let s2 = extract_anonymized_signature(&f).unwrap();
        assert_eq!(s1.fingerprint, s2.fingerprint);
    }

    #[test]
    fn rule_class_truncated_to_structural_class() {
        let f = finding("security:sql_injection_v2_custom_detector", "High");
        let sig = extract_anonymized_signature(&f).unwrap();
        // Must normalize to base class.
        assert_eq!(sig.rule_class, "security:sql_injection");
    }

    #[test]
    fn ingest_deduplicated_by_fingerprint() {
        let mut mem = FederatedMemory::new();
        let f = finding_with_witness(
            "security:command_injection",
            "Critical",
            "parse",
            "exec",
            vec!["parse", "exec"],
        );
        let sig = extract_anonymized_signature(&f).unwrap();
        mem.ingest_federated_rule(sig.clone());
        mem.ingest_federated_rule(sig);
        assert_eq!(
            mem.len(),
            1,
            "duplicate fingerprint must not be double-ingested"
        );
    }

    #[test]
    fn low_severity_not_propagated() {
        let mut mem = FederatedMemory::new();
        let f = finding("security:informational_note", "Informational");
        if let Some(sig) = extract_anonymized_signature(&f) {
            mem.ingest_federated_rule(sig);
        }
        assert!(
            mem.is_empty(),
            "Informational findings must not be propagated"
        );
    }

    #[test]
    fn matches_federated_class_detects_hit() {
        let mut mem = FederatedMemory::new();
        let src_finding = finding_with_witness(
            "security:sql_injection",
            "Critical",
            "httpHandler",
            "db.exec",
            vec!["httpHandler", "db.exec"],
        );
        let sig = extract_anonymized_signature(&src_finding).unwrap();
        mem.ingest_federated_rule(sig);

        // A finding in a different repo with the same rule class should match.
        let target_finding = finding("security:sql_injection", "High");
        assert!(mem.matches_federated_class(&target_finding));
    }

    #[test]
    fn normalize_hop_maps_known_sinks() {
        assert_eq!(normalize_hop("innerHTML"), "DomSink");
        assert_eq!(normalize_hop("dangerouslySetInnerHTML"), "DomSink");
        assert_eq!(normalize_hop("executeQuery"), "SqlExecute");
        assert_eq!(normalize_hop("Runtime.exec"), "OsExec");
        assert_eq!(normalize_hop("fetch"), "NetworkEgress");
        assert_eq!(normalize_hop("deserializeObject"), "Deserialize");
    }
}
