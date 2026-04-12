//! Jira ASPM synchronization for high-severity findings.

use anyhow::Context as _;
use base64::Engine as _;
use common::policy::JiraConfig;
use common::slop::StructuredFinding;
use serde_json::json;
use std::path::Path;

trait JiraIssueSender {
    fn send(&self, url: &str, auth: &str, payload: &str) -> anyhow::Result<()>;
}

struct UreqJiraSender;

impl JiraIssueSender for UreqJiraSender {
    fn send(&self, url: &str, auth: &str, payload: &str) -> anyhow::Result<()> {
        match ureq::post(url)
            .header("Authorization", auth)
            .header("Content-Type", "application/json")
            .send(payload.to_owned())
        {
            Ok(_) => Ok(()),
            Err(ureq::Error::StatusCode(code)) => {
                anyhow::bail!("jira issue create failed with HTTP {code}")
            }
            Err(err) => Err(anyhow::anyhow!(
                "jira issue create transport failure: {err}"
            )),
        }
    }
}

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
    spawn_jira_ticket_with_sender(config, finding, &UreqJiraSender)
}

fn spawn_jira_ticket_with_sender(
    config: &JiraConfig,
    finding: &StructuredFinding,
    sender: &dyn JiraIssueSender,
) -> anyhow::Result<()> {
    if !config.is_configured() {
        anyhow::bail!("jira config is incomplete");
    }

    let auth = jira_auth_header()?;
    let payload = build_issue_payload(config, finding);
    let url = format!("{}/rest/api/2/issue", config.url.trim_end_matches('/'));
    let body = serde_json::to_string(&payload)
        .map_err(|_| anyhow::anyhow!("jira payload serialization failed"))?;
    sender.send(&url, &auth, &body)
}

pub fn sync_findings_to_jira(
    config: &JiraConfig,
    findings: &[StructuredFinding],
    janitor_dir: &Path,
) -> anyhow::Result<()> {
    if !config.is_configured() {
        return Ok(());
    }

    for finding in findings {
        if !severity_is_kev_or_higher(finding) {
            continue;
        }
        if let Err(err) = spawn_jira_ticket(config, finding) {
            let warning = format!("Failed to sync finding to Jira: {}: {err}", finding.id);
            eprintln!("{warning}");
            crate::report::append_diag_log(janitor_dir, &warning);
        }
    }

    Ok(())
}

#[cfg(test)]
fn sync_findings_to_jira_with_sender_and_logger(
    config: &JiraConfig,
    findings: &[StructuredFinding],
    janitor_dir: &Path,
    sender: &dyn JiraIssueSender,
    mut logger: impl FnMut(String),
) -> anyhow::Result<()> {
    if !config.is_configured() {
        return Ok(());
    }

    for finding in findings {
        if !severity_is_kev_or_higher(finding) {
            continue;
        }
        if let Err(err) = spawn_jira_ticket_with_sender(config, finding, sender) {
            let warning = format!("Failed to sync finding to Jira: {}: {err}", finding.id);
            logger(warning.clone());
            crate::report::append_diag_log(janitor_dir, &warning);
        }
    }

    Ok(())
}

pub fn severity_is_kev_or_higher(finding: &StructuredFinding) -> bool {
    matches!(finding.severity.as_deref(), Some("KevCritical"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};
    use tempfile::tempdir;

    #[derive(Clone)]
    struct MockJiraSender {
        outcomes: Arc<Mutex<VecDeque<anyhow::Result<()>>>>,
    }

    impl MockJiraSender {
        fn new(outcomes: Vec<anyhow::Result<()>>) -> Self {
            Self {
                outcomes: Arc::new(Mutex::new(VecDeque::from(outcomes))),
            }
        }
    }

    impl JiraIssueSender for MockJiraSender {
        fn send(&self, _url: &str, _auth: &str, _payload: &str) -> anyhow::Result<()> {
            self.outcomes
                .lock()
                .expect("mock sender mutex")
                .pop_front()
                .unwrap_or_else(|| Ok(()))
        }
    }

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

    #[test]
    fn test_jira_fail_open_logs_and_continues_on_http_and_timeout_errors() {
        let _guard_user = std::env::set_var("JANITOR_JIRA_USER", "operator@example.com");
        let _guard_token = std::env::set_var("JANITOR_JIRA_TOKEN", "token");

        let config = JiraConfig {
            url: "https://corp.atlassian.net".to_string(),
            project_key: "SEC".to_string(),
        };
        let findings = vec![
            StructuredFinding {
                id: "finding-500".to_string(),
                file: Some("package.json".to_string()),
                line: Some(1),
                fingerprint: "fp-500".to_string(),
                severity: Some("KevCritical".to_string()),
                remediation: Some("remove postinstall worm".to_string()),
                docs_url: None,
            },
            StructuredFinding {
                id: "finding-401".to_string(),
                file: Some("package.json".to_string()),
                line: Some(2),
                fingerprint: "fp-401".to_string(),
                severity: Some("KevCritical".to_string()),
                remediation: Some("rotate credentials".to_string()),
                docs_url: None,
            },
            StructuredFinding {
                id: "finding-timeout".to_string(),
                file: Some("package.json".to_string()),
                line: Some(3),
                fingerprint: "fp-timeout".to_string(),
                severity: Some("KevCritical".to_string()),
                remediation: Some("retry later".to_string()),
                docs_url: None,
            },
        ];
        let sender = MockJiraSender::new(vec![
            Err(anyhow::anyhow!("jira issue create failed with HTTP 500")),
            Err(anyhow::anyhow!("jira issue create failed with HTTP 401")),
            Err(anyhow::anyhow!(
                "jira issue create transport failure: timeout"
            )),
        ]);
        let janitor_tmp = tempdir().expect("tempdir");
        let janitor_dir = janitor_tmp.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).expect("create .janitor");
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let warnings_sink = Arc::clone(&warnings);

        let result = sync_findings_to_jira_with_sender_and_logger(
            &config,
            &findings,
            &janitor_dir,
            &sender,
            move |msg| warnings_sink.lock().expect("warnings mutex").push(msg),
        );

        assert!(result.is_ok(), "Jira sync must fail open");
        let warnings = warnings.lock().expect("warnings mutex");
        assert_eq!(warnings.len(), 3, "all Jira failures must emit warnings");
        assert!(
            warnings[0].contains("Failed to sync finding to Jira: finding-500"),
            "HTTP 500 must surface as stderr warning text"
        );
        assert!(
            warnings[1].contains("HTTP 401"),
            "HTTP 401 must surface as stderr warning text"
        );
        assert!(
            warnings[2].contains("timeout"),
            "transport timeout must surface as stderr warning text"
        );

        let diag = std::fs::read_to_string(janitor_dir.join("diag.log")).expect("read diag log");
        assert!(diag.contains("finding-500"));
        assert!(diag.contains("HTTP 401"));
        assert!(diag.contains("timeout"));
    }
}
