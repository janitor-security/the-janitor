//! Provider-neutral source control context detection.
//!
//! Normalizes CI metadata from GitHub Actions, GitLab CI, Bitbucket Pipelines,
//! and Azure DevOps into a single struct consumed by CLI entrypoints.

use std::collections::HashMap;

/// Supported SCM / CI providers with normalized environment extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScmProvider {
    GitHub,
    GitLab,
    Bitbucket,
    AzureDevOps,
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

impl Default for ScmProvider {
    fn default() -> Self {
        Self::Unknown
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

#[cfg(test)]
mod tests {
    use super::{ScmContext, ScmProvider};

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
}
