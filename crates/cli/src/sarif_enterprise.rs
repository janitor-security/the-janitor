//! Enterprise SARIF 2.1.0 serializer — P1-10.
//!
//! Renders a [`common::slop::StructuredFinding`] slice as a fully compliant
//! OASIS SARIF 2.1.0 JSON document.  Designed as a shared serializer for the
//! `bounce`, `report`, `hunt`, and `mesh-audit` workflows.
//!
//! ## Design goals
//!
//! * **Stable fingerprints** — derived from `(rule_id, normalized_path, line,
//!   fingerprint)` so GHAS, DefectDojo, and Jira Security Hub deduplicate
//!   across rebases and monorepo moves.
//! * **Baseline diffing** — `baselineState` is set to `"new"` for all results
//!   (callers can upgrade to `"unchanged"` or `"absent"` via a baseline import).
//! * **repro_cmd in fixes** — when `exploit_witness.repro_cmd` is populated it
//!   is surfaced as a SARIF `fix` object with a `description` so operators can
//!   reproduce the finding with a single command.
//! * **CI/CD telemetry correlation** — accepts an optional [`CiRunMetadata`]
//!   that is attached to `run.automationDetails` and `run.properties`.

use crate::ci_telemetry::CiRunMetadata;
use common::slop::StructuredFinding;
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// Map a Janitor severity string to a SARIF level token.
fn severity_to_sarif_level(severity: Option<&str>) -> &'static str {
    match severity {
        Some("KevCritical") | Some("Critical") => "error",
        Some("High") => "error",
        Some("Medium") => "warning",
        Some("Low") | Some("Informational") => "note",
        _ => "warning",
    }
}

/// Derive a stable SARIF partial-fingerprint from the finding's structural root.
///
/// Uses the engine-assigned BLAKE3 `fingerprint` field when present; falls back
/// to a deterministic combination of `(id, file, line)`.
fn partial_fingerprint(f: &StructuredFinding) -> String {
    if !f.fingerprint.is_empty() {
        return f.fingerprint.clone();
    }
    let file = f.file.as_deref().unwrap_or("");
    let line = f.line.unwrap_or(0);
    format!("{}/{file}:{line}", f.id)
}

/// Build a SARIF `rule` descriptor for a unique rule ID.
fn build_rule(id: &str, findings: &[&StructuredFinding]) -> Value {
    let level = findings
        .iter()
        .map(|f| severity_to_sarif_level(f.severity.as_deref()))
        .max_by_key(|l| match *l {
            "error" => 2u8,
            "warning" => 1u8,
            _ => 0u8,
        })
        .unwrap_or("warning");

    let docs_url = findings.iter().find_map(|f| f.docs_url.as_deref());
    let remediation = findings.iter().find_map(|f| f.remediation.as_deref());

    let help_text = match (remediation, docs_url) {
        (Some(r), Some(u)) => format!("{r}\n\nSee: {u}"),
        (Some(r), None) => r.to_string(),
        (None, Some(u)) => format!("See: {u}"),
        (None, None) => id.to_string(),
    };

    let mut rule = json!({
        "id": id,
        "name": id,
        "shortDescription": { "text": id },
        "defaultConfiguration": { "level": level },
        "help": { "markdown": help_text, "text": help_text }
    });

    if let Some(url) = docs_url {
        rule["helpUri"] = json!(url);
    }

    // Append regulatory regime data to help markdown when present.
    let regimes: Vec<&str> = findings
        .iter()
        .filter_map(|f| f.regulatory_regimes.as_ref())
        .flat_map(|v| v.iter().map(String::as_str))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    if !regimes.is_empty() {
        let regime_list = regimes.join(", ");
        let existing = rule["help"]["markdown"].as_str().unwrap_or("").to_string();
        rule["help"]["markdown"] = json!(format!(
            "{existing}\n\n**Regulatory exposure**: {regime_list}"
        ));
    }

    rule
}

/// Build a SARIF `result` object for a single finding.
fn build_result(f: &StructuredFinding) -> Value {
    let level = severity_to_sarif_level(f.severity.as_deref());
    let fingerprint = partial_fingerprint(f);

    let message_text = match f
        .exploit_witness
        .as_ref()
        .and_then(|w| w.repro_cmd.as_deref())
    {
        Some(cmd) => format!("{} — repro: {cmd}", f.id),
        None => f
            .remediation
            .as_deref()
            .map(|r| format!("{}: {r}", f.id))
            .unwrap_or_else(|| f.id.clone()),
    };

    let file_uri = f.file.as_deref().unwrap_or("unknown");
    let location: Value = match f.line {
        Some(line) => json!({
            "physicalLocation": {
                "artifactLocation": { "uri": file_uri, "uriBaseId": "%SRCROOT%" },
                "region": { "startLine": line }
            }
        }),
        None => json!({
            "physicalLocation": {
                "artifactLocation": { "uri": file_uri, "uriBaseId": "%SRCROOT%" }
            }
        }),
    };

    let mut result = json!({
        "ruleId": f.id,
        "level": level,
        "message": { "text": message_text },
        "locations": [location],
        "partialFingerprints": {
            "janitorFingerprint/v1": fingerprint
        },
        "baselineState": "new"
    });

    // Attach repro_cmd as a SARIF fix object.
    if let Some(cmd) = f
        .exploit_witness
        .as_ref()
        .and_then(|w| w.repro_cmd.as_deref())
    {
        result["fixes"] = json!([{
            "description": {
                "text": format!("Reproduction command: {cmd}")
            },
            "artifactChanges": []
        }]);
    }

    // Severity property for ASPM tools that read it from properties bag.
    if let Some(sev) = &f.severity {
        result["properties"] = json!({ "severity": sev });
    }

    result
}

/// Render a slice of [`StructuredFinding`] as an enterprise SARIF 2.1.0 JSON string.
///
/// Optionally attaches CI/CD run metadata to `run.automationDetails` and
/// `run.properties` for DefectDojo / GHAS pipeline correlation.
pub fn render_enterprise_sarif(
    findings: &[StructuredFinding],
    ci_meta: Option<&CiRunMetadata>,
) -> String {
    // Group findings by rule_id for rule descriptors.
    let mut by_rule: BTreeMap<&str, Vec<&StructuredFinding>> = BTreeMap::new();
    for f in findings {
        by_rule.entry(f.id.as_str()).or_default().push(f);
    }

    let rules: Vec<Value> = by_rule
        .iter()
        .map(|(id, fvec)| build_rule(id, fvec))
        .collect();

    let results: Vec<Value> = findings.iter().map(build_result).collect();

    let tool = json!({
        "driver": {
            "name": "Janitor",
            "informationUri": "https://thejanitor.app",
            "semanticVersion": env!("CARGO_PKG_VERSION"),
            "rules": rules
        }
    });

    let mut run = json!({
        "tool": tool,
        "results": results
    });

    if let Some(meta) = ci_meta {
        if meta.is_populated() {
            run["automationDetails"] = meta.to_sarif_automation_details();
            run["properties"] = meta.to_sarif_properties();
        }
    }

    let sarif = json!({
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [run]
    });

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|_| "{}".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ci_telemetry::{CiProvider, CiRunMetadata};
    use common::slop::{ExploitWitness, StructuredFinding};
    use std::collections::BTreeMap;

    fn make_finding(id: &str, file: &str, line: u32, severity: &str) -> StructuredFinding {
        StructuredFinding {
            id: id.to_string(),
            file: Some(file.to_string()),
            line: Some(line),
            fingerprint: "abc123".to_string(),
            severity: Some(severity.to_string()),
            remediation: Some("Remove the vulnerable call.".to_string()),
            docs_url: Some("https://thejanitor.app/findings/test".to_string()),
            exploit_witness: None,
            upstream_validation_absent: false,
            regulatory_regimes: None,
            estimated_fine_floor_usd: None,
        }
    }

    #[test]
    fn sarif_output_has_required_top_level_fields() {
        let findings = vec![make_finding(
            "security:command_injection",
            "src/main.rs",
            42,
            "Critical",
        )];
        let output = render_enterprise_sarif(&findings, None);
        let v: Value = serde_json::from_str(&output).expect("must be valid JSON");
        assert_eq!(v["version"], "2.1.0");
        assert!(v["runs"].is_array());
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "Janitor");
    }

    #[test]
    fn sarif_result_maps_file_and_line() {
        let findings = vec![make_finding(
            "security:sql_injection",
            "src/db.rs",
            10,
            "High",
        )];
        let output = render_enterprise_sarif(&findings, None);
        let v: Value = serde_json::from_str(&output).expect("valid JSON");
        let result = &v["runs"][0]["results"][0];
        assert_eq!(result["ruleId"], "security:sql_injection");
        assert_eq!(
            result["locations"][0]["physicalLocation"]["region"]["startLine"],
            10
        );
    }

    #[test]
    fn repro_cmd_appears_in_fixes_and_message() {
        let mut f = make_finding("security:command_injection", "src/exec.rs", 5, "Critical");
        f.exploit_witness = Some(ExploitWitness {
            source_function: "execute".to_string(),
            source_label: "user_input".to_string(),
            sink_function: "Command::new".to_string(),
            sink_label: "command_execution".to_string(),
            call_chain: vec!["execute".to_string(), "Command::new".to_string()],
            repro_cmd: Some(
                "curl -X POST https://example.com/run -d '{\"cmd\":\"id\"}'".to_string(),
            ),
            ..Default::default()
        });
        let output = render_enterprise_sarif(&[f], None);
        let v: Value = serde_json::from_str(&output).expect("valid JSON");
        let result = &v["runs"][0]["results"][0];
        // message must contain repro
        let msg = result["message"]["text"].as_str().unwrap_or("");
        assert!(
            msg.contains("repro:"),
            "expected repro in message, got: {msg}"
        );
        // fixes array must be present
        assert!(result["fixes"].is_array());
        let fix_desc = result["fixes"][0]["description"]["text"]
            .as_str()
            .unwrap_or("");
        assert!(
            fix_desc.contains("curl"),
            "expected curl in fix desc, got: {fix_desc}"
        );
    }

    #[test]
    fn ci_telemetry_attached_to_run_properties() {
        let findings = vec![make_finding("security:test", "src/lib.rs", 1, "Medium")];
        let meta = CiRunMetadata {
            provider: CiProvider::GitHubActions,
            commit_sha: Some("sha1234".to_string()),
            ref_name: Some("refs/heads/main".to_string()),
            run_id: Some("42".to_string()),
            workflow_name: Some("CI".to_string()),
            actor: Some("user".to_string()),
            repository: Some("owner/repo".to_string()),
            run_url: Some("https://github.com/owner/repo/actions/runs/42".to_string()),
            extra: BTreeMap::new(),
        };
        let output = render_enterprise_sarif(&findings, Some(&meta));
        let v: Value = serde_json::from_str(&output).expect("valid JSON");
        let run = &v["runs"][0];
        assert_eq!(run["automationDetails"]["id"], "owner/repo/run/42");
        assert_eq!(run["properties"]["commitSha"], "sha1234");
    }

    #[test]
    fn partial_fingerprint_uses_engine_fingerprint_when_present() {
        let f = make_finding("security:xss", "src/web.rs", 99, "High");
        assert_eq!(partial_fingerprint(&f), "abc123");
    }

    #[test]
    fn partial_fingerprint_falls_back_to_id_file_line() {
        let f = StructuredFinding {
            id: "security:xss".to_string(),
            file: Some("src/web.rs".to_string()),
            line: Some(7),
            fingerprint: String::new(),
            ..Default::default()
        };
        let fp = partial_fingerprint(&f);
        assert!(fp.contains("security:xss"), "got: {fp}");
        assert!(fp.contains("src/web.rs"), "got: {fp}");
    }

    #[test]
    fn empty_findings_produces_valid_sarif() {
        let output = render_enterprise_sarif(&[], None);
        let v: Value = serde_json::from_str(&output).expect("valid JSON");
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
