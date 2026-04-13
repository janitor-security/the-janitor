//! Jira ASPM synchronization for high-severity findings.

use anyhow::Context as _;
use base64::Engine as _;
use common::policy::JiraConfig;
use common::slop::StructuredFinding;
use serde_json::json;
use std::path::Path;

trait JiraIssueSender {
    fn send(&self, url: &str, auth: &str, payload: &str) -> anyhow::Result<()>;
    /// POST to the Jira REST v2 search endpoint and return the total number of
    /// matching issues.
    ///
    /// Used for deduplication: if > 0, a ticket with the same fingerprint is
    /// already open and creation can be skipped.
    fn search_total(&self, url: &str, auth: &str, payload: &str) -> anyhow::Result<u32>;
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

    fn search_total(&self, url: &str, auth: &str, payload: &str) -> anyhow::Result<u32> {
        match ureq::post(url)
            .header("Authorization", auth)
            .header("Content-Type", "application/json")
            .send(payload.to_owned())
        {
            Ok(response) => {
                let body: serde_json::Value = response
                    .into_body()
                    .read_json()
                    .context("jira search response JSON parse failed")?;
                Ok(body["total"].as_u64().unwrap_or(0) as u32)
            }
            Err(ureq::Error::StatusCode(code)) => {
                anyhow::bail!("jira search failed with HTTP {code}")
            }
            Err(err) => Err(anyhow::anyhow!("jira search transport failure: {err}")),
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

    let description = format!(
        "Finding: {}\nSeverity: {severity}\nLocation: {file}:{line}\nFingerprint: {}\nRemediation: {remediation}",
        finding.id,
        finding.fingerprint
    );

    json!({
        "fields": {
            "project": { "key": config.project_key },
            "summary": format!("Janitor finding: {}", finding.id),
            "description": description,
            "issuetype": { "name": "Task" }
        }
    })
}

/// Build the JSON body for `POST /rest/api/2/search`.
///
/// Avoids URL-encoding fragmentation that causes Atlassian's strict schema
/// validator to reject GET-based JQL queries containing special characters.
/// The project key is double-quoted in JQL so that keys containing hyphens or
/// digits are matched exactly.
fn build_jql_search_payload(config: &JiraConfig, fingerprint: &str) -> String {
    let jql = format!(
        "project=\"{}\" AND description~\"{}\" AND statusCategory != Done",
        config.project_key, fingerprint
    );
    serde_json::to_string(&json!({
        "jql": jql,
        "maxResults": 1
    }))
    .expect("jira search payload serialization")
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

    // Dedup: skip creation if an open ticket with this fingerprint already exists.
    if config.dedup {
        let search_url = format!("{}/rest/api/2/search", config.url.trim_end_matches('/'));
        let search_payload = build_jql_search_payload(config, &finding.fingerprint);
        match sender.search_total(&search_url, &auth, &search_payload) {
            Ok(total) if total > 0 => {
                eprintln!("jira dedup: open ticket found for fingerprint, skipping creation");
                return Ok(());
            }
            Err(e) => {
                // Fail open: log the search failure and proceed with creation.
                eprintln!("jira dedup: search failed, proceeding with creation: {e}");
            }
            Ok(_) => {} // no existing tickets — proceed with creation
        }
    }

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
        search_total_value: u32,
    }

    impl MockJiraSender {
        fn new(outcomes: Vec<anyhow::Result<()>>) -> Self {
            Self {
                outcomes: Arc::new(Mutex::new(VecDeque::from(outcomes))),
                search_total_value: 0,
            }
        }

        fn new_with_search_total(
            outcomes: Vec<anyhow::Result<()>>,
            search_total_value: u32,
        ) -> Self {
            Self {
                outcomes: Arc::new(Mutex::new(VecDeque::from(outcomes))),
                search_total_value,
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

        fn search_total(&self, _url: &str, _auth: &str, _payload: &str) -> anyhow::Result<u32> {
            Ok(self.search_total_value)
        }
    }

    #[test]
    fn test_build_issue_payload_contains_summary_and_fingerprint() {
        let config = JiraConfig {
            url: "https://corp.atlassian.net".to_string(),
            project_key: "SEC".to_string(),
            dedup: true,
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
        assert_eq!(payload["fields"]["issuetype"]["name"], "Task");
        let description = payload["fields"]["description"].to_string();
        assert!(description.contains("abc123fingerprint"));
        assert!(description.contains("Remove the hidden reviewer-invisible payload."));
        assert!(description.contains("KevCritical"));
    }

    #[test]
    fn build_jql_search_payload_uses_post_body_with_quoted_project() {
        let config = JiraConfig {
            url: "https://corp.atlassian.net".to_string(),
            project_key: "KAN".to_string(),
            dedup: true,
        };
        let payload = build_jql_search_payload(&config, "deadbeef");
        let parsed: serde_json::Value =
            serde_json::from_str(&payload).expect("payload must be valid JSON");
        let jql = parsed["jql"].as_str().expect("jql must be a string");
        assert!(
            jql.contains("project=\"KAN\""),
            "project key must be quoted"
        );
        assert!(
            jql.contains("description~\"deadbeef\""),
            "fingerprint must be quoted"
        );
        assert_eq!(parsed["maxResults"], 1);
    }

    #[test]
    fn test_jira_fail_open_logs_and_continues_on_http_and_timeout_errors() {
        let _guard_user = std::env::set_var("JANITOR_JIRA_USER", "operator@example.com");
        let _guard_token = std::env::set_var("JANITOR_JIRA_TOKEN", "token");

        let config = JiraConfig {
            url: "https://corp.atlassian.net".to_string(),
            project_key: "SEC".to_string(),
            dedup: false, // disable dedup so mock only needs send outcomes
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

    #[test]
    fn dedup_skips_creation_when_open_ticket_exists() {
        let _guard_user = std::env::set_var("JANITOR_JIRA_USER", "operator@example.com");
        let _guard_token = std::env::set_var("JANITOR_JIRA_TOKEN", "token");

        let config = JiraConfig {
            url: "https://corp.atlassian.net".to_string(),
            project_key: "SEC".to_string(),
            dedup: true,
        };
        let finding = StructuredFinding {
            id: "security:ai_prompt_injection".to_string(),
            file: Some("docs/review.md".to_string()),
            line: Some(7),
            fingerprint: "abc123dedup".to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: None,
            docs_url: None,
        };

        // search_total = 1 → open ticket exists → send must not be called.
        let sender = MockJiraSender::new_with_search_total(vec![Ok(())], 1);
        let janitor_tmp = tempdir().expect("tempdir");
        let janitor_dir = janitor_tmp.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).expect("create .janitor");
        let warnings = Arc::new(Mutex::new(Vec::new()));
        let warnings_sink = Arc::clone(&warnings);

        let result = sync_findings_to_jira_with_sender_and_logger(
            &config,
            &[finding],
            &janitor_dir,
            &sender,
            move |msg| warnings_sink.lock().expect("warnings mutex").push(msg),
        );

        assert!(result.is_ok(), "dedup skip must succeed");
        let warnings = warnings.lock().expect("warnings mutex");
        assert!(warnings.is_empty(), "no warnings when dedup fires cleanly");
        // send was never called — the Ok(()) outcome remains unconsumed.
        let remaining = sender.outcomes.lock().expect("outcomes mutex");
        assert_eq!(
            remaining.len(),
            1,
            "send must not be called when dedup fires"
        );
    }

    #[test]
    fn dedup_second_call_with_same_fingerprint_skips_creation() {
        let _guard_user = std::env::set_var("JANITOR_JIRA_USER", "operator@example.com");
        let _guard_token = std::env::set_var("JANITOR_JIRA_TOKEN", "token");

        let config = JiraConfig {
            url: "https://corp.atlassian.net".to_string(),
            project_key: "SEC".to_string(),
            dedup: true,
        };
        let finding = StructuredFinding {
            id: "security:credential_leak".to_string(),
            file: Some("src/main.rs".to_string()),
            line: Some(42),
            fingerprint: "stable-fingerprint-abc123".to_string(),
            severity: Some("KevCritical".to_string()),
            remediation: Some("Rotate the leaked credential immediately.".to_string()),
            docs_url: None,
        };
        let janitor_tmp = tempdir().expect("tempdir");
        let janitor_dir = janitor_tmp.path().join(".janitor");
        std::fs::create_dir_all(&janitor_dir).expect("create .janitor");

        // First call: search returns 0 open tickets → send is invoked.
        let first_sender = MockJiraSender::new_with_search_total(vec![Ok(())], 0);
        let result = spawn_jira_ticket_with_sender(&config, &finding, &first_sender);
        assert!(result.is_ok(), "first call must succeed");
        let remaining_after_first = first_sender.outcomes.lock().expect("mutex").len();
        assert_eq!(
            remaining_after_first, 0,
            "send must be called on the first ticket creation"
        );

        // Second call: search returns 1 open ticket (just created above) → send is skipped.
        let second_sender = MockJiraSender::new_with_search_total(vec![Ok(())], 1);
        let result = spawn_jira_ticket_with_sender(&config, &finding, &second_sender);
        assert!(result.is_ok(), "second call must succeed");
        let remaining_after_second = second_sender.outcomes.lock().expect("mutex").len();
        assert_eq!(
            remaining_after_second, 1,
            "send must NOT be called when dedup detects an existing open ticket"
        );
    }
}
