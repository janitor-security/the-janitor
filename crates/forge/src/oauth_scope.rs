//! OAuth Scope Drift Detector — Vercel / Context AI class (P1-3).
//!
//! Parses OAuth scope-request strings from JS/TS/Go/Python/Java/C# source
//! files, classifies each scope against a static provider taxonomy, and emits
//! `security:oauth_scope_drift` when a high-risk scope is present.
//!
//! ## Detection strategy
//!
//! 1. Extract scope strings from common OAuth patterns (array literals,
//!    space-separated strings, URLSearchParams, etc.).
//! 2. Classify each scope token against the provider taxonomy table.
//! 3. Emit a finding when any token maps to `RiskClass::Admin`,
//!    `RiskClass::Write`, `RiskClass::Delete`, or `RiskClass::Unbounded`.
//! 4. Upgrade severity to `KevCritical` when the detected package also
//!    appears in the CISA KEV catalog (caller responsibility — pass
//!    `kev_match = true`).

use common::slop::StructuredFinding;

// ---------------------------------------------------------------------------
// Provider taxonomy
// ---------------------------------------------------------------------------

/// Risk classification for a single OAuth scope token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskClass {
    Read,
    Write,
    Admin,
    Delete,
    /// Unbounded wildcard (`*`, `__all__`, etc.).
    Unbounded,
}

/// An entry in the static provider taxonomy.
#[derive(Debug, Clone)]
pub struct ScopeTaxonomyEntry {
    /// Exact scope token or prefix pattern (ends with `*` for prefix match).
    pub pattern: &'static str,
    /// Originating OAuth provider.
    pub provider: &'static str,
    pub risk: RiskClass,
}

/// Static taxonomy: top-15 providers × high-risk scope surface.
/// Only scopes at or above `Write` are enumerated — `Read`-only scopes are
/// omitted to keep the false-positive rate low.
pub static SCOPE_TAXONOMY: &[ScopeTaxonomyEntry] = &[
    // GitHub
    ScopeTaxonomyEntry {
        pattern: "repo",
        provider: "GitHub",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "repo:status",
        provider: "GitHub",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "repo:deployment",
        provider: "GitHub",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "public_repo",
        provider: "GitHub",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "repo:invite",
        provider: "GitHub",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "security_events",
        provider: "GitHub",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "admin:org",
        provider: "GitHub",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "admin:public_key",
        provider: "GitHub",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "admin:repo_hook",
        provider: "GitHub",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "admin:org_hook",
        provider: "GitHub",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "delete_repo",
        provider: "GitHub",
        risk: RiskClass::Delete,
    },
    ScopeTaxonomyEntry {
        pattern: "admin:*",
        provider: "GitHub",
        risk: RiskClass::Admin,
    },
    // Google
    ScopeTaxonomyEntry {
        pattern: "https://www.googleapis.com/auth/admin.*",
        provider: "Google",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "https://www.googleapis.com/auth/cloud-platform",
        provider: "Google",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "https://www.googleapis.com/auth/iam",
        provider: "Google",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "https://www.googleapis.com/auth/drive",
        provider: "Google",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "https://www.googleapis.com/auth/gmail.modify",
        provider: "Google",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "https://www.googleapis.com/auth/gmail.compose",
        provider: "Google",
        risk: RiskClass::Write,
    },
    // Slack
    ScopeTaxonomyEntry {
        pattern: "admin",
        provider: "Slack",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "admin:*",
        provider: "Slack",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "chat:write",
        provider: "Slack",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "channels:write",
        provider: "Slack",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "groups:write",
        provider: "Slack",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "users:write",
        provider: "Slack",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "files:write",
        provider: "Slack",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "pins:write",
        provider: "Slack",
        risk: RiskClass::Delete,
    },
    ScopeTaxonomyEntry {
        pattern: "reactions:write",
        provider: "Slack",
        risk: RiskClass::Write,
    },
    // Microsoft / Azure AD
    ScopeTaxonomyEntry {
        pattern: "RoleManagement.ReadWrite.Directory",
        provider: "Microsoft",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "Directory.ReadWrite.All",
        provider: "Microsoft",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "Application.ReadWrite.All",
        provider: "Microsoft",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "Group.ReadWrite.All",
        provider: "Microsoft",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "User.ReadWrite.All",
        provider: "Microsoft",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "Files.ReadWrite.All",
        provider: "Microsoft",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "Mail.ReadWrite",
        provider: "Microsoft",
        risk: RiskClass::Write,
    },
    // Discord
    ScopeTaxonomyEntry {
        pattern: "guilds",
        provider: "Discord",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "guilds.join",
        provider: "Discord",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "guilds.members.read",
        provider: "Discord",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "bot",
        provider: "Discord",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "applications.commands.update",
        provider: "Discord",
        risk: RiskClass::Admin,
    },
    // Atlassian
    ScopeTaxonomyEntry {
        pattern: "write:confluence-content",
        provider: "Atlassian",
        risk: RiskClass::Write,
    },
    ScopeTaxonomyEntry {
        pattern: "delete:confluence-content",
        provider: "Atlassian",
        risk: RiskClass::Delete,
    },
    ScopeTaxonomyEntry {
        pattern: "manage:jira-project",
        provider: "Atlassian",
        risk: RiskClass::Admin,
    },
    ScopeTaxonomyEntry {
        pattern: "manage:jira-configuration",
        provider: "Atlassian",
        risk: RiskClass::Admin,
    },
    // Unbounded wildcards — any provider
    ScopeTaxonomyEntry {
        pattern: "*",
        provider: "generic",
        risk: RiskClass::Unbounded,
    },
    ScopeTaxonomyEntry {
        pattern: "__all__",
        provider: "generic",
        risk: RiskClass::Unbounded,
    },
];

// ---------------------------------------------------------------------------
// Scope extraction
// ---------------------------------------------------------------------------

/// Extracts OAuth scope tokens from a source file string.
///
/// Recognizes:
/// - JS/TS/Python/Java/C# array literals: `scope: ["read:user", "repo"]`
/// - Space-separated strings: `"openid profile email offline_access"`
/// - Dynamic spread/concat: `[...baseScopes, "admin:org"]` (string literals only)
/// - URLSearchParams: `{ scope: "..." }`
pub fn extract_scope_tokens(source: &str) -> Vec<String> {
    let mut tokens: Vec<String> = Vec::new();

    // Find each occurrence of the `scope` keyword, then collect all quoted
    // string literals within the next 512 characters and tokenize by whitespace.
    for (idx, _) in source.match_indices("scope") {
        let window = &source[idx..std::cmp::min(idx + 512, source.len())];
        let mut pos = 0;
        while pos < window.len() {
            if let Some(q) = window[pos..].find('"').map(|i| pos + i) {
                let rest = &window[q + 1..];
                if let Some(end) = rest.find('"') {
                    let literal = &rest[..end];
                    for tok in literal.split_whitespace() {
                        if is_plausible_scope_token(tok) {
                            tokens.push(tok.to_string());
                        }
                    }
                    pos = q + 1 + end + 1;
                } else {
                    break;
                }
            } else {
                break;
            }
            // Stop at a statement boundary to avoid crossing into unrelated code.
            let remaining = &window[pos..];
            if remaining.starts_with(';') || remaining.starts_with(")\n") {
                break;
            }
        }
    }

    tokens.sort();
    tokens.dedup();
    tokens
}

/// Returns `true` if the string looks like an OAuth scope token and not a
/// noise literal that happens to reside inside a `scope`-keyed object.
fn is_plausible_scope_token(s: &str) -> bool {
    if s.is_empty() || s.len() > 256 {
        return false;
    }
    s.chars()
        .all(|c| c.is_ascii_alphanumeric() || ":/_.-*".contains(c))
}

// ---------------------------------------------------------------------------
// Taxonomy lookup
// ---------------------------------------------------------------------------

/// Classifies a single scope token against the static provider taxonomy.
/// Exact matches take precedence over prefix patterns.
pub fn classify_scope(token: &str) -> Option<&'static ScopeTaxonomyEntry> {
    if let Some(entry) = SCOPE_TAXONOMY.iter().find(|e| e.pattern == token) {
        return Some(entry);
    }
    for entry in SCOPE_TAXONOMY {
        if let Some(prefix) = entry.pattern.strip_suffix('*') {
            // Skip empty prefixes (pattern is literally "*") — those are
            // exact-match-only entries and must not act as a universal wildcard.
            if !prefix.is_empty() && token.starts_with(prefix) {
                return Some(entry);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Finding emission
// ---------------------------------------------------------------------------

/// Analyzes `source` for high-risk OAuth scope declarations.
///
/// `file_path` is used only for the finding's `file` field.
/// `kev_match` upgrades any finding to `KevCritical` severity.
pub fn find_oauth_scope_drift(
    source: &str,
    file_path: &str,
    kev_match: bool,
) -> Vec<StructuredFinding> {
    let tokens = extract_scope_tokens(source);
    let mut findings: Vec<StructuredFinding> = Vec::new();

    for token in &tokens {
        if let Some(entry) = classify_scope(token) {
            if entry.risk >= RiskClass::Write {
                let severity = if kev_match {
                    "KevCritical".to_string()
                } else {
                    "High".to_string()
                };
                findings.push(StructuredFinding {
                    id: "security:oauth_scope_drift".to_string(),
                    file: Some(file_path.to_string()),
                    severity: Some(severity),
                    remediation: Some(format!(
                        "Remove or restrict high-risk OAuth scope '{}' (provider: {}, risk: {:?}). \
                         Apply principle of least privilege.",
                        token, entry.provider, entry.risk
                    )),
                    ..Default::default()
                });
            }
        }
    }

    findings
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_org_scope_triggers_drift_finding() {
        let source = r#"
            const client = new OAuthClient({
                scope: ["read:user", "admin:org"],
                clientId: "abc123",
            });
        "#;
        let findings = find_oauth_scope_drift(source, "app/auth.ts", false);
        assert!(
            findings.iter().any(|f| {
                f.id == "security:oauth_scope_drift"
                    && f.remediation.as_deref().unwrap_or("").contains("admin:org")
            }),
            "expected oauth_scope_drift for admin:org, got: {findings:?}"
        );
    }

    #[test]
    fn read_only_scope_does_not_trigger() {
        let source = r#"
            const params = new URLSearchParams({
                scope: "read:user openid profile",
            });
        "#;
        let findings = find_oauth_scope_drift(source, "auth.js", false);
        assert!(
            findings.is_empty(),
            "expected no findings for read-only scopes, got: {findings:?}"
        );
    }

    #[test]
    fn kev_match_upgrades_to_kev_critical() {
        let source = r#"{ scope: ["repo", "admin:org"] }"#;
        let findings = find_oauth_scope_drift(source, "auth.js", true);
        assert!(
            findings
                .iter()
                .any(|f| f.severity.as_deref() == Some("KevCritical")),
            "expected KevCritical severity with kev_match=true, got: {findings:?}"
        );
    }

    #[test]
    fn unbounded_wildcard_triggers_finding() {
        let source = r#"scope: ["*"]"#;
        let findings = find_oauth_scope_drift(source, "config.py", false);
        assert!(
            findings
                .iter()
                .any(|f| f.id == "security:oauth_scope_drift"),
            "expected drift finding for unbounded wildcard scope"
        );
    }

    #[test]
    fn extract_scope_tokens_space_separated() {
        let source = r#"scope: "openid profile email admin:org offline_access""#;
        let tokens = extract_scope_tokens(source);
        assert!(tokens.contains(&"admin:org".to_string()));
        assert!(tokens.contains(&"openid".to_string()));
    }

    #[test]
    fn classify_scope_prefix_match() {
        let entry = classify_scope("admin:enterprise");
        assert!(
            entry.is_some(),
            "admin:enterprise should match admin:* prefix"
        );
        assert_eq!(entry.unwrap().risk, RiskClass::Admin);
    }

    #[test]
    fn classify_scope_exact_match() {
        let entry = classify_scope("delete_repo");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().risk, RiskClass::Delete);
    }
}
