//! Jira ASPM synchronization for high-severity findings.

use anyhow::Context as _;
use base64::Engine as _;
use common::policy::JiraConfig;
use common::slop::StructuredFinding;
use serde_json::json;

fn jira_auth_header() -> anyhow::Result<String> {
    let user = std::env::var("JANITOR_JIRA_USER")
        .context("JANITOR_JIRA_USER is required for Jira sync")?;
    let token = std::env::var("JANITOR_JIRA_TOKEN")
        .context("JANITOR_JIRA_TOKEN is required for Jira sync")?;
    let creds = format!("{user}:{token}");
    Ok(format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(creds)
    ))
}

fn build_issue_payload(config: &JiraConfig, finding: &StructuredFinding) -> serde_json::Value {
    let file = finding.file.as_deref().unwrap_or("(no file)");
    let line = finding
        .line
        .map(|line| line.to_string())
        .unwrap_or_else(|| "?".to_string());
    let severity = finding.severity.as_deref().unwrap_or("Unknown");
    let remediation = finding
        .remediation
        .as_deref()
        .unwrap_or("No structured remediation provided.");

    json!({
        "fields": {
            "project": { "key": config.project_key },
            "issuetype": { "name": "Bug" },
            "summary": format!("Janitor finding: {}", finding.id),
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            { "type": "text", "text": format!("Finding: {}", finding.id) }
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            { "type": "text", "text": format!("Severity: {severity}") }
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            { "type": "text", "text": format!("Location: {file}:{line}") }
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            { "type": "text", "text": format!("Fingerprint: {}", finding.fingerprint) }
                        ]
                    },
                    {
                        "type": "paragraph",
                        "content": [
                            { "type": "text", "text": format!("Remediation: {remediation}") }
                        ]
                    }
                ]
            }
        }
    })
}

pub fn spawn_jira_ticket(config: &JiraConfig, finding: &StructuredFinding) -> anyhow::Result<()> {
    if !config.is_configured() {
        anyhow::bail!("jira config is incomplete");
    }

    let auth = jira_auth_header()?;
    let payload = build_issue_payload(config, finding);
    let url = format!("{}/rest/api/2/issue", config.url.trim_end_matches('/'));

    match ureq::post(&url)
        .header("Authorization", &auth)
        .header("Content-Type", "application/json")
        .send(
            serde_json::to_string(&payload)
                .map_err(|_| anyhow::anyhow!("jira payload serialization failed"))?,
        ) {
        Ok(_) => Ok(()),
        Err(ureq::Error::StatusCode(code)) => {
            anyhow::bail!("jira issue create failed with HTTP {code}")
        }
        Err(err) => Err(anyhow::anyhow!(
            "jira issue create transport failure: {err}"
        )),
    }
}

pub fn severity_is_kev_or_higher(finding: &StructuredFinding) -> bool {
    matches!(finding.severity.as_deref(), Some("KevCritical"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_issue_payload_contains_summary_and_fingerprint() {
        let config = JiraConfig {
            url: "https://corp.atlassian.net".to_string(),
            project_key: "SEC".to_string(),
        };
        let finding = StructuredFinding {
            id: "security:ai_prompt_injection".to_string(),
            file: Some("docs/review.md".to_string()),
            line: Some(7),
            fingerprint: "abc123fingerprint".to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: Some("Remove the hidden reviewer-invisible payload.".to_string()),
            docs_url: None,
        };

        let payload = build_issue_payload(&config, &finding);
        assert_eq!(payload["fields"]["project"]["key"], "SEC");
        assert_eq!(
            payload["fields"]["summary"],
            "Janitor finding: security:ai_prompt_injection"
        );
        let description = payload["fields"]["description"].to_string();
        assert!(description.contains("abc123fingerprint"));
        assert!(description.contains("Remove the hidden reviewer-invisible payload."));
        assert!(description.contains("KevCritical"));
    }
}
