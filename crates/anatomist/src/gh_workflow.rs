//! GitHub Actions OIDC Trust-Boundary Auditor (P3-7).
//!
//! Parses `.github/workflows/*.yml` files and emits findings when a workflow
//! exposes an OIDC identity token to untrusted fork pull requests.
//!
//! ## Threat Model
//!
//! A workflow triggered by `pull_request_target` or `workflow_run` with
//! `id-token: write` permission can mint a 60-minute OIDC token scoped to the
//! repository's trusted publishers (PyPI, npm, Docker Hub, AWS STS). A fork
//! contributor can extract that token via a malicious `run:` step and publish
//! a backdoored release without any static credential being rotated.
//!
//! ## Detection Rules
//!
//! | ID | Condition | Severity |
//! |----|-----------|----------|
//! | `security:oidc_fork_compromise` | `pull_request_target` + `id-token: write` | KevCritical |
//! | `security:oidc_overprivileged_workflow` | `id-token: write` + `contents: write` simultaneously | Critical |

use common::slop::StructuredFinding;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan a single workflow YAML `source` (file contents) and return any
/// OIDC trust-boundary findings.
///
/// `workflow_path` is used for the `file` field in findings (e.g.
/// `.github/workflows/release.yml`).
pub fn detect_oidc_trust_boundary(source: &[u8], workflow_path: &str) -> Vec<StructuredFinding> {
    let text = match std::str::from_utf8(source) {
        Ok(s) => s,
        Err(_) => return vec![],
    };
    let mut findings = Vec::new();
    let ctx = WorkflowContext::parse(text);

    // Rule 1: pull_request_target + id-token: write → fork OIDC token steal.
    let triggers_prt = ctx.triggers_pull_request_target || ctx.triggers_workflow_run;
    let idtoken_write = ctx.global_idtoken_write || ctx.any_job_idtoken_write;

    if triggers_prt && idtoken_write {
        let line = ctx.idtoken_write_line.unwrap_or(1);
        findings.push(StructuredFinding {
            id: "security:oidc_fork_compromise".to_string(),
            file: Some(workflow_path.to_string()),
            line: Some(line as u32),
            fingerprint: fingerprint_workflow(workflow_path, "oidc_fork_compromise"),
            severity: Some("KevCritical".to_string()),
            remediation: Some(
                "Replace `pull_request_target` with `pull_request`. \
                 Restrict `id-token: write` to specific jobs that require it. \
                 Pin all action refs to commit SHAs rather than branch names."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    // Rule 2: id-token: write + contents: write simultaneously (over-privilege).
    if idtoken_write && ctx.global_contents_write {
        let line = ctx.idtoken_write_line.unwrap_or(1);
        findings.push(StructuredFinding {
            id: "security:oidc_overprivileged_workflow".to_string(),
            file: Some(workflow_path.to_string()),
            line: Some(line as u32),
            fingerprint: fingerprint_workflow(workflow_path, "oidc_overprivileged"),
            severity: Some("Critical".to_string()),
            remediation: Some(
                "Scope `id-token: write` and `contents: write` to separate jobs \
                 with minimal permission sets. Granting both globally allows any \
                 step to both mint tokens and push artifacts."
                    .to_string(),
            ),
            ..Default::default()
        });
    }

    findings
}

// ---------------------------------------------------------------------------
// Workflow YAML context (line-by-line heuristic parser)
// ---------------------------------------------------------------------------

/// Parsed context extracted from a workflow YAML file.
#[derive(Debug, Default)]
struct WorkflowContext {
    triggers_pull_request_target: bool,
    triggers_workflow_run: bool,
    global_idtoken_write: bool,
    any_job_idtoken_write: bool,
    global_contents_write: bool,
    /// Line number where `id-token: write` was first found (1-indexed).
    idtoken_write_line: Option<usize>,
}

impl WorkflowContext {
    /// Heuristic line-by-line YAML parser — avoids a full YAML dependency while
    /// still correctly identifying nested permission blocks.
    fn parse(text: &str) -> Self {
        let mut ctx = Self::default();
        // Track indentation state for nested permission blocks.
        let mut in_on_block = false;
        let mut in_permissions_block = false;
        let mut permissions_indent: Option<usize> = None;

        for (idx, line) in text.lines().enumerate() {
            let lineno = idx + 1;
            let trimmed = line.trim();
            let indent = line.len() - line.trim_start().len();

            // Detect top-level `on:` trigger block.
            // Also handle inline form: `on: [push, pull_request_target]`
            if trimmed == "on:" || trimmed.starts_with("on:") {
                in_on_block = true;
                in_permissions_block = false;
                permissions_indent = None;
                // Inline trigger detection (e.g. `on: [push, pull_request_target]`).
                if line.contains("pull_request_target") {
                    ctx.triggers_pull_request_target = true;
                }
                if line.contains("workflow_run") {
                    ctx.triggers_workflow_run = true;
                }
                continue;
            }

            // Detect `permissions:` block at any level.
            // Also handle inline form: `permissions: write-all`
            if trimmed == "permissions:" || trimmed.starts_with("permissions:") {
                in_permissions_block = true;
                permissions_indent = Some(indent);
                in_on_block = false;
                // Inline shorthand: `permissions: write-all`
                if trimmed.contains("write-all") {
                    ctx.global_idtoken_write = true;
                    ctx.global_contents_write = true;
                    ctx.idtoken_write_line.get_or_insert(lineno);
                }
                continue;
            }

            // Detect top-level key transitions (reset state).
            if !trimmed.is_empty()
                && !trimmed.starts_with('#')
                && indent == 0
                && !trimmed.starts_with("on:")
                && !trimmed.starts_with("permissions:")
                && !trimmed.starts_with('-')
            {
                if in_on_block {
                    in_on_block = false;
                }
                // Only reset permissions block if we've moved to a new top-level key
                // at the same or lesser indent as the permissions block.
                if let Some(pi) = permissions_indent {
                    if indent <= pi && in_permissions_block {
                        in_permissions_block = false;
                        permissions_indent = None;
                    }
                }
            }

            // Inside on: block — detect triggers.
            if in_on_block {
                if trimmed.starts_with("pull_request_target") {
                    ctx.triggers_pull_request_target = true;
                }
                if trimmed.starts_with("workflow_run") {
                    ctx.triggers_workflow_run = true;
                }
            }

            // Inside permissions: block — detect id-token: write / contents: write.
            if in_permissions_block {
                if trimmed.starts_with("id-token:") && trimmed.contains("write") {
                    ctx.global_idtoken_write = true;
                    ctx.idtoken_write_line.get_or_insert(lineno);
                }
                if trimmed.starts_with("contents:") && trimmed.contains("write") {
                    ctx.global_contents_write = true;
                }
                // Check for write-all shorthand.
                if trimmed == "permissions: write-all" || trimmed == "write-all" {
                    ctx.global_idtoken_write = true;
                    ctx.global_contents_write = true;
                    ctx.idtoken_write_line.get_or_insert(lineno);
                }
            }

            // Scan for per-job id-token: write outside a global permissions block.
            if !in_permissions_block
                && trimmed.starts_with("id-token:")
                && trimmed.contains("write")
            {
                ctx.any_job_idtoken_write = true;
                ctx.idtoken_write_line.get_or_insert(lineno);
            }

            // Also catch inline `pull_request_target` anywhere (e.g. `on: [push, pull_request_target]`).
            if line.contains("pull_request_target") {
                ctx.triggers_pull_request_target = true;
            }
        }

        ctx
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic fingerprint for workflow findings (no BLAKE3 dep in anatomist).
fn fingerprint_workflow(path: &str, rule: &str) -> String {
    // Simple but deterministic: rule + last path segment.
    let filename = path.rsplit('/').next().unwrap_or(path);
    format!("oidc:{}:{}", rule, filename)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const VULNERABLE_WORKFLOW: &str = r#"
name: Release

on:
  pull_request_target:
    types: [opened, synchronize]

permissions:
  id-token: write
  contents: read

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@main
      - run: npm ci && npm publish --provenance
"#;

    const SAFE_WORKFLOW: &str = r#"
name: CI

on:
  pull_request:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo test
"#;

    const OVERPRIVILEGED_WORKFLOW: &str = r#"
name: Deploy

on:
  push:
    branches: [main]

permissions:
  id-token: write
  contents: write

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
"#;

    #[test]
    fn vulnerable_workflow_fires_oidc_fork_compromise() {
        let findings = detect_oidc_trust_boundary(
            VULNERABLE_WORKFLOW.as_bytes(),
            ".github/workflows/release.yml",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"security:oidc_fork_compromise"),
            "pull_request_target + id-token: write must emit oidc_fork_compromise; got {ids:?}"
        );
        let f = findings
            .iter()
            .find(|f| f.id == "security:oidc_fork_compromise")
            .unwrap();
        assert_eq!(f.severity.as_deref(), Some("KevCritical"));
    }

    #[test]
    fn safe_workflow_does_not_fire() {
        let findings =
            detect_oidc_trust_boundary(SAFE_WORKFLOW.as_bytes(), ".github/workflows/ci.yml");
        assert!(
            findings.is_empty(),
            "pull_request without id-token must not fire; got {findings:?}"
        );
    }

    #[test]
    fn overprivileged_workflow_fires_overprivilege() {
        let findings = detect_oidc_trust_boundary(
            OVERPRIVILEGED_WORKFLOW.as_bytes(),
            ".github/workflows/deploy.yml",
        );
        let ids: Vec<&str> = findings.iter().map(|f| f.id.as_str()).collect();
        assert!(
            ids.contains(&"security:oidc_overprivileged_workflow"),
            "id-token: write + contents: write must emit overprivileged; got {ids:?}"
        );
    }

    #[test]
    fn inline_pull_request_target_fires() {
        let src = b"
on: [push, pull_request_target]
permissions:
  id-token: write
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
";
        let findings = detect_oidc_trust_boundary(src, ".github/workflows/test.yml");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:oidc_fork_compromise"),
            "inline pull_request_target must fire"
        );
    }

    #[test]
    fn workflow_run_trigger_fires() {
        let src = b"
on:
  workflow_run:
    workflows: [CI]
    types: [completed]

permissions:
  id-token: write
";
        let findings = detect_oidc_trust_boundary(src, ".github/workflows/publish.yml");
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:oidc_fork_compromise"),
            "workflow_run + id-token: write must fire"
        );
    }
}
