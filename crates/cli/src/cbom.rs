//! CycloneDX v1.5 CBOM (Cryptography Bill of Materials) renderer.
//!
//! Converts a slice of [`BounceLogEntry`] records into a valid CycloneDX v1.5 JSON
//! document, suitable for supply-chain tooling and CI compliance pipelines.
//!
//! ## Output formats
//! - `markdown` (default)
//! - `json`
//! - `pdf`
//! - `cbom` — CycloneDX v1.5 JSON (this module)
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
        "specVersion": "1.5",
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
        assert_eq!(parsed["specVersion"], "1.5");
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
}
