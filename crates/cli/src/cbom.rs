//! CycloneDX v1.6 CBOM (Cryptography Bill of Materials) renderer.
//!
//! Converts a slice of [`BounceLogEntry`] records into a valid CycloneDX v1.6 JSON
//! document, suitable for supply-chain tooling and CI compliance pipelines.
//!
//! ## Output formats
//! - `markdown` (default)
//! - `json`
//! - `pdf`
//! - `cbom` — CycloneDX v1.6 JSON (this module)
//! - `sarif` — SARIF 2.1.0 JSON (see [`crate::report`])
//!
//! ## Schema overview
//! The CBOM encodes each actionable PR (score > 0 or necrotic flag set) as a
//! CycloneDX `vulnerability` entry.  The `components` array is intentionally
//! empty — the CLI does not enumerate cryptographic primitives at scan time.
//! Janitor Sentinel (SaaS) populates components on clean merge.
//!
//! ## Severity mapping
//! | Classification | CycloneDX severity |
//! |---|---|
//! | `is_critical_threat` | `critical` |
//! | `necrotic_flag.is_some()` | `medium` |
//! | Boilerplate | `none` |

use crate::report::{is_critical_threat, BounceLogEntry};
use serde_json::{json, Value};

/// Render `entries` as a CycloneDX v1.5 CBOM JSON string.
///
/// Only entries where `score > 0` or `necrotic_flag.is_some()` are emitted as
/// vulnerability entries.  Pure boilerplate entries (score == 0, no necrotic
/// flag, no critical threat) are skipped.
///
/// # Parameters
/// - `entries` — slice of bounce log entries to render.
/// - `repo_slug` — GitHub `owner/repo` slug used as the component name and in
///   the `affects[].ref` URN.
pub fn render_cbom(entries: &[BounceLogEntry], repo_slug: &str) -> String {
    let timestamp = crate::utc_now_iso8601();
    let serial = uuid::Uuid::new_v4();

    let vulnerabilities: Vec<Value> = entries
        .iter()
        .filter(|e| e.slop_score > 0 || e.necrotic_flag.is_some())
        .map(|e| {
            let pr_num = e.pr_number.unwrap_or(0);
            let severity = severity_for_entry(e);
            let description = if e.antipatterns.is_empty() {
                String::new()
            } else {
                e.antipatterns.join("|")
            };
            let affects_ref = format!("urn:cdx:{repo_slug}:pr/{pr_num}");

            json!({
                "id": format!("JANITOR-{pr_num}"),
                "source": {
                    "name": "The Janitor",
                    "url": "https://thejanitor.app"
                },
                "ratings": [
                    {
                        "source": { "name": "The Janitor" },
                        "severity": severity,
                        "method": "other"
                    }
                ],
                "description": description,
                "properties": cbom_entry_properties(e, true),
                "affects": [
                    {
                        "ref": affects_ref
                    }
                ]
            })
        })
        .collect();

    let doc = json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": format!("urn:uuid:{serial}"),
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "The Janitor",
                    "name": "janitor",
                    "version": env!("CARGO_PKG_VERSION")
                }
            ],
            "properties": cbom_metadata_properties(entries),
            "component": {
                "type": "application",
                "name": repo_slug
            }
        },
        "components": [],
        "vulnerabilities": vulnerabilities
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

/// Render a **single** [`BounceLogEntry`] as a deterministic CycloneDX v1.6 CBOM
/// JSON string suitable for ML-DSA-65 signing and offline verification.
///
/// **Determinism contract (never violate):**
/// - No `serialNumber` (UUID) — non-deterministic across invocations.
/// - No `metadata.timestamp` — would differ between sign and verify.
/// - Uses `serde_json::to_string` (compact, not pretty) for byte-stable output.
///
/// The verifier (`janitor verify-cbom`) re-derives the exact same bytes by
/// calling this function with the stored [`BounceLogEntry`] and repo slug,
/// then checking the detached PQC signatures stored in the bounce log entry.
pub fn render_cbom_for_entry(entry: &BounceLogEntry, repo_slug: &str) -> String {
    let pr_num = entry.pr_number.unwrap_or(0);
    let severity = severity_for_entry(entry);
    let description = if entry.antipatterns.is_empty() {
        String::new()
    } else {
        entry.antipatterns.join("|")
    };
    let affects_ref = format!("urn:cdx:{repo_slug}:pr/{pr_num}");

    let doc = serde_json::json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "tools": [{
                "vendor": "The Janitor",
                "name": "janitor",
                "version": env!("CARGO_PKG_VERSION")
            }],
            "properties": [],
            "component": {
                "type": "application",
                "name": repo_slug
            }
        },
        "components": [],
        "vulnerabilities": [{
            "id": format!("JANITOR-{pr_num}"),
            "source": {
                "name": "The Janitor",
                "url": "https://thejanitor.app"
            },
            "ratings": [{
                "source": { "name": "The Janitor" },
                "severity": severity,
                "method": "other"
            }],
            "properties": cbom_entry_properties(entry, false),
            "description": description,
            "affects": [{ "ref": affects_ref }]
        }]
    });

    // compact (not pretty) for byte-stable signing surface
    serde_json::to_string(&doc).unwrap_or_else(|_| "{}".to_string())
}

fn cbom_metadata_properties(entries: &[BounceLogEntry]) -> Vec<Value> {
    let mut props = Vec::new();
    for entry in entries {
        if let Some(proof) = entry.transparency_log.as_ref() {
            let pr = entry.pr_number.unwrap_or(0);
            props.push(json!({
                "name": format!("janitor:transparency_log:pr:{pr}:sequence_index"),
                "value": proof.sequence_index.to_string()
            }));
            props.push(json!({
                "name": format!("janitor:transparency_log:pr:{pr}:chained_hash"),
                "value": proof.chained_hash
            }));
        }
    }
    props
}

/// Map a bounce log entry to a CycloneDX severity string.
fn severity_for_entry(e: &BounceLogEntry) -> &'static str {
    if is_critical_threat(e) {
        "critical"
    } else if e.necrotic_flag.is_some() {
        "medium"
    } else {
        "none"
    }
}

fn cbom_entry_properties(entry: &BounceLogEntry, include_signatures: bool) -> Vec<Value> {
    let mut props = Vec::new();
    if let Some(source) = entry.pqc_key_source.as_deref() {
        props.push(json!({
            "name": "janitor:pqc_key_source",
            "value": source
        }));
    }
    if include_signatures {
        if let Some(sig) = entry.pqc_sig.as_deref() {
            props.push(json!({
                "name": "janitor:pqc_sig_ml_dsa_65",
                "value": sig
            }));
        }
        if let Some(sig) = entry.pqc_slh_sig.as_deref() {
            props.push(json!({
                "name": "janitor:pqc_sig_slh_dsa_shake_192s",
                "value": sig
            }));
        }
    }
    props
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{BounceLogEntry, PrState};

    fn make_entry(pr_number: u64, score: u32, antipatterns: Vec<String>) -> BounceLogEntry {
        BounceLogEntry {
            pr_number: Some(pr_number),
            author: Some("test-author".to_string()),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            slop_score: score,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns,
            comment_violations: vec![],
            min_hashes: vec![],
            zombie_deps: vec![],
            state: PrState::Open,
            is_bot: false,
            repo_slug: "owner/repo".to_string(),
            suppressed_by_domain: 0,
            collided_pr_numbers: vec![],
            necrotic_flag: None,
            commit_sha: String::new(),
            policy_hash: String::new(),
            version_silos: vec![],
            agentic_pct: 0.0,
            ci_energy_saved_kwh: if score > 0 { 0.1 } else { 0.0 },
            provenance: crate::report::Provenance::default(),
            governor_status: None,
            pqc_sig: None,
            pqc_slh_sig: None,
            pqc_key_source: None,
            transparency_log: None,
            cognition_surrender_index: 0.0,
        }
    }

    #[test]
    fn test_cbom_valid_json() {
        let entries = vec![
            make_entry(1, 50, vec!["security:compiled_payload_anomaly".to_string()]),
            make_entry(2, 0, vec![]), // boilerplate — should be skipped
        ];
        let out = render_cbom(&entries, "owner/repo");
        let parsed: serde_json::Value =
            serde_json::from_str(&out).expect("CBOM output must be valid JSON");
        assert_eq!(parsed["bomFormat"], "CycloneDX");
        assert_eq!(parsed["specVersion"], "1.6");
        // Only 1 vulnerability (boilerplate skipped)
        assert_eq!(parsed["vulnerabilities"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["vulnerabilities"][0]["id"], "JANITOR-1");
        assert_eq!(
            parsed["vulnerabilities"][0]["ratings"][0]["severity"],
            "critical"
        );
    }

    #[test]
    fn test_cbom_necrotic_severity() {
        let mut entry = make_entry(42, 0, vec![]);
        entry.necrotic_flag = Some("SEMANTIC_NULL".to_string());
        let out = render_cbom(&[entry], "owner/repo");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["vulnerabilities"][0]["ratings"][0]["severity"],
            "medium"
        );
    }

    #[test]
    fn test_cbom_boilerplate_skipped() {
        let entry = make_entry(99, 0, vec![]);
        let out = render_cbom(&[entry], "owner/repo");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(parsed["vulnerabilities"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_cbom_includes_pqc_key_source_property() {
        let mut entry = make_entry(7, 50, vec!["security:compiled_payload_anomaly".to_string()]);
        entry.pqc_key_source = Some("filesystem".to_string());
        let out = render_cbom_for_entry(&entry, "owner/repo");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            parsed["vulnerabilities"][0]["properties"][0]["name"],
            "janitor:pqc_key_source"
        );
        assert_eq!(
            parsed["vulnerabilities"][0]["properties"][0]["value"],
            "filesystem"
        );
    }

    #[test]
    fn test_cbom_includes_dual_signature_properties() {
        let mut entry = make_entry(7, 50, vec!["security:compiled_payload_anomaly".to_string()]);
        entry.pqc_sig = Some("mlsig".to_string());
        entry.pqc_slh_sig = Some("slhsig".to_string());
        let out = render_cbom(&[entry], "owner/repo");
        let parsed: serde_json::Value = serde_json::from_str(&out).unwrap();
        let properties = parsed["vulnerabilities"][0]["properties"]
            .as_array()
            .expect("properties must be present");
        assert!(
            properties
                .iter()
                .any(|prop| prop["name"] == "janitor:pqc_sig_ml_dsa_65"),
            "render_cbom must expose the ML-DSA-65 detached signature"
        );
        assert!(
            properties
                .iter()
                .any(|prop| prop["name"] == "janitor:pqc_sig_slh_dsa_shake_192s"),
            "render_cbom must expose the SLH-DSA detached signature"
        );
    }

    #[test]
    fn test_cbom_metadata_includes_transparency_anchor() {
        let mut entry = make_entry(
            7,
            150,
            vec!["security:compiled_payload_anomaly".to_string()],
        );
        entry.transparency_log = Some(crate::report::InclusionProof {
            sequence_index: 42,
            chained_hash: "abc123".to_string(),
        });
        let out = render_cbom(&[entry], "owner/repo");
        let parsed: serde_json::Value =
            serde_json::from_str(&out).expect("CBOM output must be valid JSON");
        let props = parsed["metadata"]["properties"]
            .as_array()
            .expect("metadata properties array must exist");
        assert!(props.iter().any(|p| {
            p["name"] == "janitor:transparency_log:pr:7:sequence_index" && p["value"] == "42"
        }));
        assert!(props.iter().any(|p| {
            p["name"] == "janitor:transparency_log:pr:7:chained_hash" && p["value"] == "abc123"
        }));
    }
}
