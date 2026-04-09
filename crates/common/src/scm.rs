//! Provider-neutral source control context detection.
//!
//! Normalizes CI metadata from GitHub Actions, GitLab CI, Bitbucket Pipelines,
//! and Azure DevOps into a single struct consumed by CLI entrypoints.

use anyhow::Result;
use std::collections::HashMap;
use std::io::Write as _;

/// Supported SCM / CI providers with normalized environment extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScmProvider {
    GitHub,
    GitLab,
    Bitbucket,
    AzureDevOps,
    #[default]
    Unknown,
}

/// Normalized SCM execution context derived from runner environment variables.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScmContext {
    pub provider: ScmProvider,
    pub commit_sha: Option<String>,
    pub repo_slug: Option<String>,
    pub pr_number: Option<u64>,
    pub base_ref: Option<String>,
    pub head_ref: Option<String>,
}

/// Provider-neutral CI verdict severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerdictLevel {
    Success,
    Warning,
    Failure,
}

/// Normalized CI verdict emitted to a provider-specific check/status channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusVerdict {
    pub title: String,
    pub summary: String,
    pub level: VerdictLevel,
}

impl StatusVerdict {
    pub fn bounce(gate_passed: bool, slop_score: u32, governor_status: Option<&str>) -> Self {
        let governor_suffix = match governor_status {
            Some("ok") => "Governor attested.",
            Some("degraded") => "Governor degraded.",
            Some("local_pqc") => "Local PQC attestation applied.",
            _ => "Local-only verdict.",
        };
        if gate_passed {
            Self {
                title: "Janitor verdict clean".to_string(),
                summary: format!("Patch accepted at slop score {slop_score}. {governor_suffix}"),
                level: VerdictLevel::Success,
            }
        } else {
            Self {
                title: "Janitor verdict blocked".to_string(),
                summary: format!("Patch blocked at slop score {slop_score}. {governor_suffix}"),
                level: VerdictLevel::Failure,
            }
        }
    }

    pub fn timeout(timeout_secs: u64) -> Self {
        Self {
            title: "Janitor analysis timeout".to_string(),
            summary: format!("Bounce analysis exceeded the {timeout_secs}s execution budget."),
            level: VerdictLevel::Failure,
        }
    }

    pub fn governor_failure() -> Self {
        Self {
            title: "Janitor governor transport degraded".to_string(),
            summary: "Governor network request failed.".to_string(),
            level: VerdictLevel::Warning,
        }
    }
}

/// Provider-specific CI verdict sink.
pub trait StatusPublisher {
    fn provider(&self) -> ScmProvider;
    fn render_verdict(&self, ctx: &ScmContext, verdict: &StatusVerdict) -> String;

    fn publish_verdict(&self, ctx: &ScmContext, verdict: &StatusVerdict) -> Result<()> {
        let line = self.render_verdict(ctx, verdict);
        std::io::stderr().write_all(line.as_bytes())?;
        std::io::stderr().write_all(b"\n")?;
        Ok(())
    }
}

pub fn status_publisher_for(ctx: &ScmContext) -> Box<dyn StatusPublisher + Send + Sync> {
    match ctx.provider {
        ScmProvider::GitHub => Box::new(GitHubStatusPublisher),
        ScmProvider::GitLab => Box::new(GitLabStatusPublisher),
        ScmProvider::Bitbucket => Box::new(BitbucketStatusPublisher),
        ScmProvider::AzureDevOps => Box::new(AzureDevOpsStatusPublisher),
        ScmProvider::Unknown => Box::new(NullStatusPublisher),
    }
}

impl ScmContext {
    /// Resolve the current SCM context from the process environment.
    pub fn from_env() -> Self {
        Self::from_pairs(std::env::vars())
    }

    /// Resolve SCM context from arbitrary key-value pairs.
    ///
    /// Used by tests to avoid mutating process-global environment state.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let map: HashMap<String, String> = pairs
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();

        if map.contains_key("GITHUB_ACTIONS") {
            return Self {
                provider: ScmProvider::GitHub,
                commit_sha: get(&map, "GITHUB_SHA"),
                repo_slug: get(&map, "GITHUB_REPOSITORY"),
                pr_number: get(&map, "GITHUB_EVENT_NUMBER")
                    .and_then(parse_u64)
                    .or_else(|| parse_github_pr_number(&map)),
                base_ref: get(&map, "GITHUB_BASE_REF"),
                head_ref: get(&map, "GITHUB_HEAD_REF"),
            };
        }

        if map.contains_key("GITLAB_CI") {
            return Self {
                provider: ScmProvider::GitLab,
                commit_sha: get(&map, "CI_COMMIT_SHA"),
                repo_slug: get(&map, "CI_PROJECT_PATH"),
                pr_number: get(&map, "CI_MERGE_REQUEST_IID").and_then(parse_u64),
                base_ref: get(&map, "CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
                    .or_else(|| get(&map, "CI_DEFAULT_BRANCH")),
                head_ref: get(&map, "CI_MERGE_REQUEST_SOURCE_BRANCH_NAME")
                    .or_else(|| get(&map, "CI_COMMIT_REF_NAME")),
            };
        }

        if map.contains_key("BITBUCKET_BUILD_NUMBER") {
            return Self {
                provider: ScmProvider::Bitbucket,
                commit_sha: get(&map, "BITBUCKET_COMMIT"),
                repo_slug: get(&map, "BITBUCKET_REPO_FULL_NAME"),
                pr_number: get(&map, "BITBUCKET_PR_ID").and_then(parse_u64),
                base_ref: get(&map, "BITBUCKET_PR_DESTINATION_BRANCH"),
                head_ref: get(&map, "BITBUCKET_BRANCH"),
            };
        }

        if map.contains_key("TF_BUILD") {
            return Self {
                provider: ScmProvider::AzureDevOps,
                commit_sha: get(&map, "BUILD_SOURCEVERSION"),
                repo_slug: azure_repo_slug(&map),
                pr_number: get(&map, "SYSTEM_PULLREQUEST_PULLREQUESTNUMBER")
                    .and_then(parse_u64)
                    .or_else(|| get(&map, "SYSTEM_PULLREQUEST_PULLREQUESTID").and_then(parse_u64)),
                base_ref: get(&map, "SYSTEM_PULLREQUEST_TARGETBRANCH").map(|s| strip_git_ref(&s)),
                head_ref: get(&map, "SYSTEM_PULLREQUEST_SOURCEBRANCH")
                    .map(|s| strip_git_ref(&s))
                    .or_else(|| get(&map, "BUILD_SOURCEBRANCHNAME")),
            };
        }

        Self::default()
    }
}

fn get(map: &HashMap<String, String>, key: &str) -> Option<String> {
    map.get(key).cloned().filter(|v| !v.is_empty())
}

fn parse_u64(raw: String) -> Option<u64> {
    raw.parse::<u64>().ok()
}

fn parse_github_pr_number(map: &HashMap<String, String>) -> Option<u64> {
    get(map, "GITHUB_REF")
        .or_else(|| get(map, "GITHUB_REF_NAME"))
        .and_then(|raw| {
            raw.split('/')
                .find(|segment| !segment.is_empty() && segment.chars().all(|c| c.is_ascii_digit()))
                .and_then(|segment| segment.parse::<u64>().ok())
        })
}

fn azure_repo_slug(map: &HashMap<String, String>) -> Option<String> {
    if let Some(full) = get(map, "BUILD_REPOSITORY_NAME") {
        if full.contains('/') {
            return Some(full);
        }
        if let Some(project) = get(map, "SYSTEM_TEAMPROJECT") {
            return Some(format!("{project}/{full}"));
        }
        return Some(full);
    }
    None
}

fn strip_git_ref(raw: &str) -> String {
    raw.strip_prefix("refs/heads/")
        .or_else(|| raw.strip_prefix("refs/pull/"))
        .or_else(|| raw.strip_prefix("refs/merge-requests/"))
        .unwrap_or(raw)
        .to_string()
}

struct GitHubStatusPublisher;
struct GitLabStatusPublisher;
struct BitbucketStatusPublisher;
struct AzureDevOpsStatusPublisher;
struct NullStatusPublisher;

impl StatusPublisher for GitHubStatusPublisher {
    fn provider(&self) -> ScmProvider {
        ScmProvider::GitHub
    }

    fn render_verdict(&self, ctx: &ScmContext, verdict: &StatusVerdict) -> String {
        let level = match verdict.level {
            VerdictLevel::Success => "notice",
            VerdictLevel::Warning => "warning",
            VerdictLevel::Failure => "error",
        };
        let title = github_escape(&verdict.title);
        let scope = scoped_target(ctx);
        let summary = github_escape(&format!("{scope} {}", verdict.summary));
        format!("::{level} title={title}::{summary}")
    }
}

impl StatusPublisher for GitLabStatusPublisher {
    fn provider(&self) -> ScmProvider {
        ScmProvider::GitLab
    }

    fn render_verdict(&self, ctx: &ScmContext, verdict: &StatusVerdict) -> String {
        format!(
            "janitor-gitlab-status [{}] {} — {}",
            verdict_level_label(verdict.level),
            scoped_target(ctx).trim(),
            verdict.summary
        )
    }
}

impl StatusPublisher for BitbucketStatusPublisher {
    fn provider(&self) -> ScmProvider {
        ScmProvider::Bitbucket
    }

    fn render_verdict(&self, ctx: &ScmContext, verdict: &StatusVerdict) -> String {
        format!(
            "janitor-bitbucket-status [{}] {} — {}",
            verdict_level_label(verdict.level),
            scoped_target(ctx).trim(),
            verdict.summary
        )
    }
}

impl StatusPublisher for AzureDevOpsStatusPublisher {
    fn provider(&self) -> ScmProvider {
        ScmProvider::AzureDevOps
    }

    fn render_verdict(&self, ctx: &ScmContext, verdict: &StatusVerdict) -> String {
        let issue_type = match verdict.level {
            VerdictLevel::Success | VerdictLevel::Warning => "warning",
            VerdictLevel::Failure => "error",
        };
        format!(
            "##vso[task.logissue type={issue_type};sourcepath=janitor;]{0} {1}",
            scoped_target(ctx).trim(),
            verdict.summary
        )
    }
}

impl StatusPublisher for NullStatusPublisher {
    fn provider(&self) -> ScmProvider {
        ScmProvider::Unknown
    }

    fn render_verdict(&self, ctx: &ScmContext, verdict: &StatusVerdict) -> String {
        format!(
            "janitor-status [{}] {} — {}",
            verdict_level_label(verdict.level),
            scoped_target(ctx).trim(),
            verdict.summary
        )
    }
}

fn verdict_level_label(level: VerdictLevel) -> &'static str {
    match level {
        VerdictLevel::Success => "success",
        VerdictLevel::Warning => "warning",
        VerdictLevel::Failure => "failure",
    }
}

fn scoped_target(ctx: &ScmContext) -> String {
    let repo = ctx.repo_slug.as_deref().unwrap_or("unknown-repo");
    match (ctx.pr_number, ctx.commit_sha.as_deref()) {
        (Some(pr), Some(sha)) => format!("[{repo} PR #{pr} @ {}]", short_sha(sha)),
        (Some(pr), None) => format!("[{repo} PR #{pr}]"),
        (None, Some(sha)) => format!("[{repo} @ {}]", short_sha(sha)),
        (None, None) => format!("[{repo}]"),
    }
}

fn short_sha(sha: &str) -> &str {
    let end = sha.len().min(12);
    &sha[..end]
}

fn github_escape(raw: &str) -> String {
    raw.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

#[cfg(test)]
mod tests {
    use super::{status_publisher_for, ScmContext, ScmProvider, StatusVerdict, VerdictLevel};

    #[test]
    fn detects_github_actions_context() {
        let ctx = ScmContext::from_pairs([
            ("GITHUB_ACTIONS", "true"),
            ("GITHUB_SHA", "deadbeef"),
            ("GITHUB_REPOSITORY", "acme/api"),
            ("GITHUB_REF", "refs/pull/42/merge"),
            ("GITHUB_BASE_REF", "main"),
            ("GITHUB_HEAD_REF", "feature/kev"),
        ]);
        assert_eq!(ctx.provider, ScmProvider::GitHub);
        assert_eq!(ctx.commit_sha.as_deref(), Some("deadbeef"));
        assert_eq!(ctx.repo_slug.as_deref(), Some("acme/api"));
        assert_eq!(ctx.pr_number, Some(42));
        assert_eq!(ctx.base_ref.as_deref(), Some("main"));
        assert_eq!(ctx.head_ref.as_deref(), Some("feature/kev"));
    }

    #[test]
    fn detects_gitlab_context() {
        let ctx = ScmContext::from_pairs([
            ("GITLAB_CI", "true"),
            ("CI_COMMIT_SHA", "cafebabe"),
            ("CI_PROJECT_PATH", "acme/platform"),
            ("CI_MERGE_REQUEST_IID", "17"),
            ("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main"),
            ("CI_MERGE_REQUEST_SOURCE_BRANCH_NAME", "mr/scm"),
        ]);
        assert_eq!(ctx.provider, ScmProvider::GitLab);
        assert_eq!(ctx.commit_sha.as_deref(), Some("cafebabe"));
        assert_eq!(ctx.repo_slug.as_deref(), Some("acme/platform"));
        assert_eq!(ctx.pr_number, Some(17));
        assert_eq!(ctx.base_ref.as_deref(), Some("main"));
        assert_eq!(ctx.head_ref.as_deref(), Some("mr/scm"));
    }

    #[test]
    fn detects_bitbucket_context() {
        let ctx = ScmContext::from_pairs([
            ("BITBUCKET_BUILD_NUMBER", "99"),
            ("BITBUCKET_COMMIT", "abc123"),
            ("BITBUCKET_REPO_FULL_NAME", "acme/service"),
            ("BITBUCKET_PR_ID", "51"),
            ("BITBUCKET_PR_DESTINATION_BRANCH", "main"),
            ("BITBUCKET_BRANCH", "feature/pipe"),
        ]);
        assert_eq!(ctx.provider, ScmProvider::Bitbucket);
        assert_eq!(ctx.commit_sha.as_deref(), Some("abc123"));
        assert_eq!(ctx.repo_slug.as_deref(), Some("acme/service"));
        assert_eq!(ctx.pr_number, Some(51));
        assert_eq!(ctx.base_ref.as_deref(), Some("main"));
        assert_eq!(ctx.head_ref.as_deref(), Some("feature/pipe"));
    }

    #[test]
    fn detects_azure_devops_context() {
        let ctx = ScmContext::from_pairs([
            ("TF_BUILD", "True"),
            ("BUILD_SOURCEVERSION", "f00dbabe"),
            ("SYSTEM_TEAMPROJECT", "Acme"),
            ("BUILD_REPOSITORY_NAME", "janitor"),
            ("SYSTEM_PULLREQUEST_PULLREQUESTNUMBER", "8"),
            ("SYSTEM_PULLREQUEST_TARGETBRANCH", "refs/heads/main"),
            ("SYSTEM_PULLREQUEST_SOURCEBRANCH", "refs/heads/feature/scm"),
        ]);
        assert_eq!(ctx.provider, ScmProvider::AzureDevOps);
        assert_eq!(ctx.commit_sha.as_deref(), Some("f00dbabe"));
        assert_eq!(ctx.repo_slug.as_deref(), Some("Acme/janitor"));
        assert_eq!(ctx.pr_number, Some(8));
        assert_eq!(ctx.base_ref.as_deref(), Some("main"));
        assert_eq!(ctx.head_ref.as_deref(), Some("feature/scm"));
    }

    #[test]
    fn github_publisher_renders_annotation_command() {
        let ctx = ScmContext {
            provider: ScmProvider::GitHub,
            repo_slug: Some("acme/api".to_string()),
            pr_number: Some(42),
            commit_sha: Some("deadbeefcafebabe".to_string()),
            ..ScmContext::default()
        };
        let publisher = status_publisher_for(&ctx);
        let line = publisher.render_verdict(
            &ctx,
            &StatusVerdict {
                title: "Janitor verdict blocked".to_string(),
                summary: "Patch blocked at slop score 120.".to_string(),
                level: VerdictLevel::Failure,
            },
        );
        assert!(line.starts_with("::error title=Janitor verdict blocked::"));
        assert!(line.contains("acme/api PR #42"));
    }

    #[test]
    fn azure_publisher_renders_vso_command() {
        let ctx = ScmContext {
            provider: ScmProvider::AzureDevOps,
            repo_slug: Some("Acme/janitor".to_string()),
            pr_number: Some(8),
            ..ScmContext::default()
        };
        let publisher = status_publisher_for(&ctx);
        let line = publisher.render_verdict(&ctx, &StatusVerdict::governor_failure());
        assert!(line.starts_with("##vso[task.logissue type=warning;"));
        assert!(line.contains("Governor network request failed."));
    }

    #[test]
    fn bounce_verdict_tracks_gate_outcome() {
        let clean = StatusVerdict::bounce(true, 0, Some("ok"));
        let blocked = StatusVerdict::bounce(false, 250, Some("degraded"));
        assert_eq!(clean.level, VerdictLevel::Success);
        assert_eq!(blocked.level, VerdictLevel::Failure);
        assert!(blocked.summary.contains("Governor degraded."));
    }
}
