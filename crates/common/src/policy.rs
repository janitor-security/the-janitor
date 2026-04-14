//! Governance manifest: `janitor.toml`.
//!
//! [`JanitorPolicy`] is the version-controlled, maintainer-controlled
//! configuration that overrides The Janitor's global defaults.  Place a
//! `janitor.toml` at the repository root to opt into stricter or more
//! permissive slop gates — without modifying CI pipeline variables.
//!
//! # Differentiation from platform kill-switches
//!
//! GitHub's built-in merge queue and ruleset features operate as opaque
//! kill-switches: a single global threshold applies to all PRs with no
//! context about the project's risk tolerance.  `janitor.toml` encodes
//! the maintainers' *specific* slop tolerance, committed alongside the code
//! it governs.  It is reviewable, diffable, and auditable by the entire team.
//!
//! # Example `janitor.toml`
//!
//! ```toml
//! # Raise the gate threshold for a high-velocity repo.
//! min_slop_score     = 150
//!
//! # All PRs must reference a GitHub issue.
//! require_issue_link = true
//!
//! # Resurrecting previously-deleted symbols is intentional here.
//! allowed_zombies    = false
//!
//! # PRs tagged [REFACTOR] get a 30-point gate relaxation.
//! refactor_bonus     = 30
//!
//! # Project-specific antipattern detectors.
//! custom_antipatterns = ["tools/queries/no_global_state.scm"]
//! ```

use serde::{Deserialize, Serialize};
use sha2::Digest as _;
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// BillingConfig — [billing] sub-table
// ---------------------------------------------------------------------------

/// Financial calculation parameters configurable per-organisation.
///
/// Controls the dollar/time estimates in the Workslop actuarial ledger.
/// Override in `[billing]` TOML table.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct BillingConfig {
    /// Senior-engineer triage minutes per finding intercept.
    ///
    /// Used to compute `Time_Saved_Hours` in the CSV export.
    /// The 12-minute default is a conservative estimate from Workslop
    /// research (2026).  Set this to your organisation's measured value
    /// to make the CFO conversation defensible.
    ///
    /// **Set this in `janitor.toml` and cite your own incident post-mortems
    /// in the CFO meeting — do not rely on the default.**
    #[serde(default = "BillingConfig::default_triage_minutes")]
    pub triage_minutes_per_finding: f64,

    /// Billing rate for Critical Threats (security antipattern / Swarm collision).
    #[serde(default = "BillingConfig::default_critical_usd")]
    pub critical_threat_usd: f64,

    /// Billing rate for Necrotic GC (bot-automatable dead-code).
    #[serde(default = "BillingConfig::default_necrotic_usd")]
    pub necrotic_usd: f64,

    /// kWh of CI datacenter energy conserved per actionable intercept.
    ///
    /// Basis: a 15-minute CI run at 400 W consumes 0.1 kWh.  Configure to
    /// your organisation's measured CI runtime and power consumption to make
    /// the energy-conservation claim in the actuarial ledger defensible.
    ///
    /// **Set this in `janitor.toml` `[billing]` and cite your own cloud
    /// provider's energy metrics — do not rely on the default.**
    ///
    /// Default: **0.1** kWh.
    #[serde(default = "BillingConfig::default_ci_kwh_per_run")]
    pub ci_kwh_per_run: f64,
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            triage_minutes_per_finding: Self::default_triage_minutes(),
            critical_threat_usd: Self::default_critical_usd(),
            necrotic_usd: Self::default_necrotic_usd(),
            ci_kwh_per_run: Self::default_ci_kwh_per_run(),
        }
    }
}

impl BillingConfig {
    fn default_triage_minutes() -> f64 {
        12.0
    }
    fn default_critical_usd() -> f64 {
        150.0
    }
    fn default_necrotic_usd() -> f64 {
        20.0
    }
    fn default_ci_kwh_per_run() -> f64 {
        0.1
    }
}

// ---------------------------------------------------------------------------
// WebhookConfig — [webhook] sub-table
// ---------------------------------------------------------------------------

/// Configuration for outbound webhook delivery of bounce findings.
///
/// When configured, the Janitor POSTs a HMAC-SHA256 signed JSON payload
/// to `url` on each bounce that matches the `events` filter.  The signature
/// appears in the `X-Janitor-Signature-256` header as `sha256=<hex>`.
/// Consumers should verify it against the configured secret before processing.
///
/// Configure via `[webhook]` TOML table in `janitor.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct WebhookConfig {
    /// Destination URL for outbound webhook POSTs.
    ///
    /// Supports HTTPS and HTTP.  Leave empty to disable webhook delivery.
    #[serde(default)]
    pub url: String,

    /// HMAC-SHA256 secret used to sign outbound payloads.
    ///
    /// Accepts two forms:
    /// - `"env:VAR_NAME"` — reads the secret from environment variable `VAR_NAME`
    ///   at runtime (recommended for production).
    /// - Any other string — used directly as the secret (development only).
    ///
    /// When empty, payloads are delivered unsigned.
    #[serde(default)]
    pub secret: String,

    /// Event filter governing which bounce results trigger a delivery.
    ///
    /// Recognised values: `"critical_threat"`, `"necrotic_flag"`, `"all"`.
    /// Defaults to `["critical_threat"]` when omitted.
    #[serde(default = "WebhookConfig::default_events")]
    pub events: Vec<String>,

    /// Enables bidirectional ASPM lifecycle notifications (`finding_opened` /
    /// `finding_resolved`) over the configured webhook transport.
    #[serde(default)]
    pub lifecycle_events: bool,

    /// Optional external ticketing project key (JIRA / ServiceNow / Linear).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ticket_project: Option<String>,
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            secret: String::new(),
            events: Self::default_events(),
            lifecycle_events: false,
            ticket_project: None,
        }
    }
}

impl WebhookConfig {
    fn default_events() -> Vec<String> {
        vec!["critical_threat".to_string()]
    }

    /// Returns `true` if this configuration should fire a webhook for an entry
    /// with the given classification flags.
    pub fn should_fire(&self, is_critical: bool, is_necrotic: bool) -> bool {
        if self.url.is_empty() {
            return false;
        }
        self.events.iter().any(|e| match e.as_str() {
            "critical_threat" => is_critical,
            "necrotic_flag" => is_necrotic,
            "all" => true,
            _ => false,
        })
    }
}

// ---------------------------------------------------------------------------
// JiraConfig — [jira] sub-table
// ---------------------------------------------------------------------------

/// Configuration for Jira issue creation on high-severity findings.
///
/// Credentials are sourced from the environment:
/// - `JANITOR_JIRA_USER`
/// - `JANITOR_JIRA_TOKEN`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct JiraConfig {
    /// Jira base URL, e.g. `https://corp.atlassian.net`.
    pub url: String,

    /// Jira project key, e.g. `SEC`.
    pub project_key: String,

    /// Skip ticket creation when an open ticket with the same finding fingerprint already exists.
    ///
    /// Queries the Jira search API before creation; fails open on search errors.
    /// Default: `true`.
    #[serde(default = "JiraConfig::default_dedup")]
    pub dedup: bool,
}

impl Default for JiraConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            project_key: String::new(),
            dedup: Self::default_dedup(),
        }
    }
}

impl JiraConfig {
    /// Returns `true` when Jira issue creation is configured.
    pub fn is_configured(&self) -> bool {
        !self.url.is_empty() && !self.project_key.is_empty()
    }

    fn default_dedup() -> bool {
        true
    }
}

// ---------------------------------------------------------------------------
// ForgeConfig — [forge] sub-table
// ---------------------------------------------------------------------------

/// Engine-level configuration nested under `[forge]` in `janitor.toml`.
///
/// These settings control the slop-detection engine's behaviour independently
/// of the governance gate thresholds that live at the top level of the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct ForgeConfig {
    /// Ecosystem-specific automation account handles that are exempt from the
    /// **unlinked-PR penalty only**.
    ///
    /// Use this field for accounts that lack the standard GitHub `[bot]` suffix
    /// but are verified, non-human contributors — e.g. `r-ryantm` (NixOS package
    /// updater) or `app/nixpkgs-ci`.  These accounts do not open companion GitHub
    /// Issues for their PRs by design; penalising them with `unlinked_pr × 20`
    /// systematically inflates slop scores and destroys ROI signal.
    ///
    /// **Full slop analysis still executes.** Only the issue-link check is
    /// bypassed.  Dead symbols, logic clones, and antipatterns are still scored.
    ///
    /// Matched **case-insensitively** against the PR author.  Exact handle, no
    /// glob or regex.
    ///
    /// ```toml
    /// [forge]
    /// automation_accounts = ["r-ryantm", "app/nixpkgs-ci"]
    /// ```
    pub automation_accounts: Vec<String>,
    /// Base URL for the Janitor Governor control plane.
    ///
    /// When present, `janitor bounce --analysis-token ...` POSTs attestation
    /// payloads to `<governor_url>/v1/report` and heartbeat probes to
    /// `<governor_url>/health`. When absent, the CLI falls back to its built-in
    /// default Governor base URL.
    pub governor_url: Option<String>,
    /// Optional path to a PEM-encoded client certificate used for mTLS when
    /// reporting to the Governor.
    pub mtls_cert: Option<String>,
    /// Optional path to a PEM-encoded private key paired with `mtls_cert`.
    pub mtls_key: Option<String>,
    /// Raises bounce analysis budgets from the default 1 MiB / 500 ms path to
    /// the deep-scan 32 MiB / 30 s path for AST-evasion-resistant analysis.
    pub deep_scan: bool,
    /// Number of days before the on-disk threat corpus is considered stale
    /// after a network-partition event.  When the corpus exceeds this age
    /// and no fresh download succeeded, the CLI warns and exits gracefully.
    ///
    /// Default: 7.  Air-gapped enterprises may lower this to increase
    /// sensitivity to corpus drift.
    #[serde(default = "ForgeConfig::default_corpus_stale_days")]
    pub corpus_stale_days: u32,
}

impl Default for ForgeConfig {
    fn default() -> Self {
        Self {
            automation_accounts: Vec::new(),
            governor_url: None,
            mtls_cert: None,
            mtls_key: None,
            deep_scan: false,
            corpus_stale_days: Self::default_corpus_stale_days(),
        }
    }
}

impl ForgeConfig {
    fn default_corpus_stale_days() -> u32 {
        7
    }
}

// ---------------------------------------------------------------------------
// PqcConfig — [pqc] sub-table
// ---------------------------------------------------------------------------

/// Post-quantum key lifecycle controls nested under `[pqc]` in `janitor.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct PqcConfig {
    /// Maximum permitted age for the active filesystem-backed PQC key bundle.
    ///
    /// Default: `Some(90)` days.
    #[serde(default = "PqcConfig::default_max_key_age_days")]
    pub max_key_age_days: Option<u32>,
}

impl Default for PqcConfig {
    fn default() -> Self {
        Self {
            max_key_age_days: Self::default_max_key_age_days(),
        }
    }
}

impl PqcConfig {
    fn default_max_key_age_days() -> Option<u32> {
        Some(90)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WisdomQuorumConfig {
    pub mirrors: Vec<String>,
    #[serde(default = "WisdomQuorumConfig::default_threshold")]
    pub threshold: usize,
}

impl Default for WisdomQuorumConfig {
    fn default() -> Self {
        Self {
            mirrors: Vec::new(),
            threshold: Self::default_threshold(),
        }
    }
}

impl WisdomQuorumConfig {
    fn default_threshold() -> usize {
        1
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct WisdomConfig {
    pub quorum: WisdomQuorumConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Suppression {
    pub id: String,
    pub rule: String,
    pub path_glob: String,
    pub expires: Option<String>,
    pub owner: String,
    pub reason: String,
    #[serde(skip)]
    pub approved: bool,
}

impl Suppression {
    pub fn is_active_at(&self, now_unix_secs: u64) -> bool {
        match self.expires.as_deref() {
            None => true,
            Some(expires) => parse_suppression_expiry(expires)
                .map(|expiry| now_unix_secs < expiry)
                .unwrap_or(false),
        }
    }

    pub fn matches(&self, rule: &str, path: &str, now_unix_secs: u64) -> bool {
        self.rule == rule && glob_match(&self.path_glob, path) && self.is_active_at(now_unix_secs)
    }
}

// ---------------------------------------------------------------------------
// RbacConfig — [rbac] sub-table
// ---------------------------------------------------------------------------

/// A single team entry in the `[[rbac.teams]]` TOML array.
///
/// Each team binds a human-readable name to a Governor role and an optional
/// set of repository slugs the team is permitted to access.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RbacTeam {
    /// Human-readable team name (e.g. `"security-engineering"`).
    pub name: String,

    /// Governor role assigned to this team.
    ///
    /// Valid values:
    /// - `"admin"` — full read/write access including policy override.
    /// - `"ci-writer"` — may post bounce verdicts; cannot change policy.
    /// - `"auditor"` — read-only; the `/v1/report` endpoint returns HTTP 403.
    pub role: String,

    /// Repository slugs (`"owner/repo"`) this team may access.
    ///
    /// An empty list permits all repos visible to the Governor.
    #[serde(default)]
    pub allowed_repos: Vec<String>,
}

/// Role-Based Access Control configuration for the Governor.
///
/// Configure under `[rbac]` in `janitor.toml`.
///
/// # Example
///
/// ```toml
/// [[rbac.teams]]
/// name         = "security-engineering"
/// role         = "admin"
/// allowed_repos = []
///
/// [[rbac.teams]]
/// name         = "ci-runners"
/// role         = "ci-writer"
/// allowed_repos = ["acme/backend", "acme/frontend"]
///
/// [[rbac.teams]]
/// name         = "external-auditors"
/// role         = "auditor"
/// allowed_repos = ["acme/backend"]
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct RbacConfig {
    /// Team entries defining role assignments and repository scope.
    pub teams: Vec<RbacTeam>,
}

// ---------------------------------------------------------------------------
// JanitorPolicy
// ---------------------------------------------------------------------------

/// Governance manifest loaded from `janitor.toml` at the repository root.
///
/// All fields carry defaults that match The Janitor's built-in constants, so
/// the *absence* of a manifest is functionally identical to an all-defaults
/// configuration.  Unknown fields are silently ignored — forward-compatible
/// with future Janitor versions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct JanitorPolicy {
    /// Composite slop-score threshold above which `janitor bounce` reports a
    /// gate failure.
    ///
    /// Corresponds to the `fail_on_slop` threshold in the GitHub Action.
    /// Default: **100**.  Lower values tighten the gate; higher values allow
    /// noisier PRs through.
    pub min_slop_score: u32,

    /// When `true`, any PR with no linked GitHub issue is automatically
    /// treated as failing the gate, regardless of `min_slop_score`.
    ///
    /// Default: `false`.
    pub require_issue_link: bool,

    /// When `true`, zombie-symbol re-introductions (verbatim body match to a
    /// previously deleted dead symbol) do not contribute to the score.
    ///
    /// Default: `false`.  Set to `true` only when the codebase is actively
    /// resurrecting symbols that were incorrectly deleted in a prior cleanup
    /// pass.
    pub allowed_zombies: bool,

    /// Reserved for post-quantum cryptography enforcement.
    ///
    /// When `true`, The Janitor will refuse patches that introduce pre-quantum
    /// cryptographic primitives (RSA, ECDSA, AES-128, SHA-1).
    ///
    /// Default: `false`.  Not yet implemented; this flag is a
    /// forward-compatibility placeholder for the PQC enforcement module.
    pub pqc_enforced: bool,

    /// Post-quantum key lifecycle settings nested under `[pqc]`.
    #[serde(default)]
    pub pqc: PqcConfig,

    /// Paths to custom `.scm` tree-sitter query files that define
    /// project-specific antipatterns.
    ///
    /// Each file must contain a named pattern `@slop` — the Slop Hunter
    /// counts each match as one antipattern finding (weight ×50 against the
    /// composite slop score).
    ///
    /// Paths are relative to the repository root.
    ///
    /// Default: `[]` (no custom queries).
    pub custom_antipatterns: Vec<String>,

    /// Score reduction applied when a PR body contains a `[REFACTOR]` or
    /// `[FIXES-DEBT]` marker — the **Refactor Bonus**.
    ///
    /// When set, the gate threshold is *raised* by this amount for marked PRs,
    /// effectively relaxing the gate for intentional restructuring work.  The
    /// threshold floors at `min_slop_score` (no negative gate).
    ///
    /// A PR body qualifies if it contains the literal string `[REFACTOR]` or
    /// `[FIXES-DEBT]` anywhere in the text.
    ///
    /// Default: `0` (no bonus).
    pub refactor_bonus: u32,

    /// Automation account handles that are exempt from the unlinked-PR penalty.
    ///
    /// Entries are matched **case-insensitively** against the PR author.  Exact
    /// handle string, no glob or regex.  Use this to suppress the
    /// `unlinked_pr = 1` penalty for known, trusted automation accounts that
    /// are unlikely to open companion issues (e.g. a project-local CI bot).
    ///
    /// **Deliberately empty by default** — maintainers must explicitly commit
    /// each trusted automation handle.  The engine hardcodes nothing; if you
    /// want `r-ryantm` or `dependabot[bot]` to be exempt, list them here.
    ///
    /// ```toml
    /// trusted_bot_authors = ["r-ryantm", "dependabot[bot]", "renovate[bot]"]
    /// ```
    ///
    /// Default: `[]` (no exemptions — all authors are investigated equally).
    pub trusted_bot_authors: Vec<String>,

    /// Engine-level settings nested under `[forge]`.
    ///
    /// See [`ForgeConfig`] for available fields.  Defaults to an empty
    /// configuration when the `[forge]` section is absent from `janitor.toml`.
    pub forge: ForgeConfig,

    /// Outbound webhook delivery for SIEM / Slack / Teams integration.
    ///
    /// Configure in `[webhook]` TOML table.  See [`WebhookConfig`].
    #[serde(default)]
    pub webhook: WebhookConfig,

    /// Financial calculation parameters for the Workslop actuarial ledger.
    ///
    /// Configure in `[billing]` TOML table.  See [`BillingConfig`].
    #[serde(default)]
    pub billing: BillingConfig,

    /// Enterprise ticketing integration for actionable security findings.
    ///
    /// Configure in `[jira]` TOML table.  See [`JiraConfig`].
    #[serde(default)]
    pub jira: JiraConfig,

    /// Allow the pipeline to proceed when the Governor endpoint is unreachable.
    ///
    /// When `true` and a Governor POST fails (timeout, 5xx, network error),
    /// `janitor bounce` emits a `[JANITOR DEGRADED]` warning to stderr, marks
    /// the bounce log entry with `governor_status: "degraded"`, and exits `0`.
    ///
    /// Without this flag (default `false`) the CLI exits `1` on any Governor
    /// transport failure — fail-closed behaviour that prevents silent bypass.
    ///
    /// Can also be set via `--soft-fail` on the CLI (CLI flag takes precedence).
    ///
    /// Default: `false`.
    #[serde(default)]
    pub soft_fail: bool,

    /// Sovereign threat-intel distribution policy.
    ///
    /// Configure mirror quorum under `[wisdom.quorum]`.
    #[serde(default)]
    pub wisdom: WisdomConfig,

    /// Paths to BYOP (Bring Your Own Policy) Wasm rule modules.
    ///
    /// Each module is executed against the patch source bytes inside a
    /// fuel- and memory-bounded sandbox (10 MiB RAM cap, 100 M fuel units).
    /// Modules must export the host-guest ABI defined in
    /// [`forge::wasm_host`]: `memory`, `analyze(i32, i32) -> i32`, and
    /// `output_ptr() -> i32`.
    ///
    /// Findings emitted by Wasm modules are injected into the bounce result at
    /// **Critical severity (50 pts each)** and appear in `antipattern_details`
    /// alongside built-in detector output.
    ///
    /// Paths are relative to the repository root.  Overridden or supplemented
    /// by the `--wasm-rules <PATH>` CLI flag.
    ///
    /// Default: `[]` (no proprietary rules).
    #[serde(default)]
    pub wasm_rules: Vec<String>,

    /// BLAKE3 integrity pins for BYOP Wasm rule modules.
    ///
    /// Keys are the rule paths listed in [`Self::wasm_rules`] or passed via
    /// `--wasm-rules`; values are lowercase BLAKE3 hex digests of the expected
    /// module bytes. When a configured pin does not match the loaded bytes, the
    /// Wasm host aborts module initialisation immediately.
    ///
    /// Default: `{}` (no integrity pins).
    #[serde(default)]
    pub wasm_pins: HashMap<String, String>,

    /// ML-DSA-65 publisher public key for Wasm rule signature verification.
    ///
    /// When set, every `.wasm` rule loaded at runtime must have an accompanying
    /// `<path>.sig` file containing a base64-encoded ML-DSA-65 detached signature
    /// over the BLAKE3 hash of the module bytes (context: `janitor-wasm-rule`).
    /// Modules without a valid signature are rejected before compilation.
    ///
    /// The key is base64-encoded (standard alphabet, padded).  Generate with
    /// `janitor sign-asset` or any ML-DSA-65 keygen tool.
    ///
    /// Default: `None` (no publisher verification).
    #[serde(default)]
    pub wasm_pqc_pub_key: Option<String>,

    /// Repository-governed waivers for individual findings.
    #[serde(default)]
    pub suppressions: Option<Vec<Suppression>>,

    /// Governor RBAC team assignments.
    ///
    /// Configure under `[rbac]` in `janitor.toml`.
    /// Defines which teams may perform which operations against the Governor.
    /// See [`RbacConfig`] for available fields.
    #[serde(default)]
    pub rbac: RbacConfig,
}

impl Default for JanitorPolicy {
    fn default() -> Self {
        Self {
            min_slop_score: 100,
            require_issue_link: false,
            allowed_zombies: false,
            pqc_enforced: false,
            pqc: PqcConfig::default(),
            custom_antipatterns: Vec::new(),
            refactor_bonus: 0,
            trusted_bot_authors: Vec::new(),
            forge: ForgeConfig::default(),
            webhook: WebhookConfig::default(),
            billing: BillingConfig::default(),
            jira: JiraConfig::default(),
            soft_fail: false,
            wisdom: WisdomConfig::default(),
            wasm_rules: Vec::new(),
            wasm_pins: HashMap::new(),
            wasm_pqc_pub_key: None,
            suppressions: None,
            rbac: RbacConfig::default(),
        }
    }
}

fn parse_suppression_expiry(raw: &str) -> Option<u64> {
    if let Ok(unix_secs) = raw.parse::<u64>() {
        return Some(unix_secs);
    }

    let ts = raw.strip_suffix('Z')?;
    let bytes = ts.as_bytes();
    if bytes.len() != 19
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }

    let year = ts[0..4].parse::<i64>().ok()?;
    let month = ts[5..7].parse::<u32>().ok()?;
    let day = ts[8..10].parse::<u32>().ok()?;
    let hour = ts[11..13].parse::<u32>().ok()?;
    let minute = ts[14..16].parse::<u32>().ok()?;
    let second = ts[17..19].parse::<u32>().ok()?;

    if !(1..=12).contains(&month)
        || day == 0
        || day > days_in_month(year, month)
        || hour > 23
        || minute > 59
        || second > 59
    {
        return None;
    }

    let days = days_from_civil(year, month, day)?;
    Some((days as u64) * 86_400 + (hour as u64) * 3600 + (minute as u64) * 60 + second as u64)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_from_civil(year: i64, month: u32, day: u32) -> Option<i64> {
    let y = year - i64::from(month <= 2);
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = month as i64 + if month > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + day as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    (days >= 0).then_some(days)
}

fn glob_match(pattern: &str, candidate: &str) -> bool {
    let p = pattern.as_bytes();
    let s = candidate.as_bytes();
    let (mut pi, mut si) = (0usize, 0usize);
    let (mut star_pi, mut star_si) = (None, 0usize);

    while si < s.len() {
        if pi < p.len() && (p[pi] == s[si] || p[pi] == b'?') {
            pi += 1;
            si += 1;
        } else if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_si = si;
        } else if let Some(star) = star_pi {
            pi = star + 1;
            star_si += 1;
            si = star_si;
        } else {
            return false;
        }
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }

    pi == p.len()
}

impl JanitorPolicy {
    // -----------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------

    /// Attempts to load `janitor.toml` from `repo_root`.
    ///
    /// Returns `Ok(default)` when `janitor.toml` does not exist — absence is
    /// the expected case for repos that have not opted into explicit governance.
    ///
    /// Returns `Err` (hard-fails the pipeline) when:
    /// - `janitor.toml` exists but cannot be read (I/O error).
    /// - `janitor.toml` exists but contains invalid TOML or unknown fields.
    ///
    /// **A broken policy is a broken gate.** Falling back to defaults on a
    /// malformed manifest would silently disable operator-configured security
    /// constraints — an unacceptable fail-open posture for a security tool.
    pub fn load(repo_root: &Path) -> anyhow::Result<Self> {
        let path = repo_root.join("janitor.toml");
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path).map_err(|e| {
            anyhow::anyhow!("janitor.toml — failed to read {}: {}", path.display(), e)
        })?;
        toml::from_str::<Self>(&raw).map_err(|e| {
            anyhow::anyhow!(
                "janitor.toml — parse error in {}: {}. Fix the manifest before running.",
                path.display(),
                e
            )
        })
    }

    // -----------------------------------------------------------------------
    // Automation account detection
    // -----------------------------------------------------------------------

    /// Returns `true` when `author` is a recognized automation account.
    ///
    /// Four detection layers, evaluated in order — all zero-allocation in the
    /// hot path (no `String` clones):
    ///
    /// 1. **GitHub App path prefix** — any author beginning with `app/` is
    ///    unconditionally a GitHub App installation (e.g. `app/dependabot`,
    ///    `app/renovate`, `app/github-actions`).  No configuration required.
    ///    GitHub's REST API resolves App-authored PRs to this `app/<slug>`
    ///    format when queried via `gh pr list --json author`.
    ///
    /// 2. **GitHub App suffix** — any author ending with `[bot]` is
    ///    unconditionally recognized (e.g. `dependabot[bot]`, `renovate[bot]`).
    ///    No configuration required.
    ///
    /// 3. **`trusted_bot_authors`** — handles listed at the top level of
    ///    `janitor.toml`.  Backwards-compatible with existing manifests.
    ///
    /// 4. **`[forge].automation_accounts`** — handles listed in the `[forge]`
    ///    sub-section of `janitor.toml`.  Designed for ecosystem accounts that
    ///    lack the `[bot]` suffix (e.g. `r-ryantm`, `app/nixpkgs-ci`).
    ///
    /// Matching for layers 3 and 4 is **case-insensitive** and exact.
    ///
    /// When all config lists are empty (the default), only layers 1 and 2 fire —
    /// no author is unconditionally exempted by configuration alone.
    pub fn is_automation_account(&self, author: &str) -> bool {
        // Layer 1: GitHub App path prefix — `app/<slug>` format used by
        // GitHub's REST API for App-authored PRs.  Zero-allocation check.
        // Covers: app/dependabot, app/renovate, app/copilot, app/github-copilot, etc.
        if author.starts_with("app/") {
            return true;
        }
        // Layer 2: standard GitHub App suffix — zero-allocation static check.
        // Covers: dependabot[bot], renovate[bot], github-actions[bot],
        // copilot[bot], github-copilot[bot], and any future GitHub App bots.
        if author.ends_with("[bot]") {
            return true;
        }
        // Layers 3 & 4: config-defined lists — `eq_ignore_ascii_case` is
        // zero-allocation (byte-level comparison, no String allocation).
        self.trusted_bot_authors
            .iter()
            .any(|b| b.eq_ignore_ascii_case(author))
            || self
                .forge
                .automation_accounts
                .iter()
                .any(|a| a.eq_ignore_ascii_case(author))
    }

    /// Returns `true` when `author` or `pr_body` indicates an **autonomous coding agent**
    /// made commits in this PR — distinct from basic CI bots like Dependabot.
    ///
    /// ## AgenticOrigin Penalty
    ///
    /// Autonomous coding agents warrant a mandatory structural quality surcharge of
    /// **+50 points** applied to the composite slop score (see
    /// [`crate::slop_filter::SlopScore::agentic_origin_penalty`]).
    ///
    /// This ensures machine-authored code must be structurally flawless to pass the
    /// 100-point gate — a PR from `copilot[bot]` with one Critical antipattern already
    /// scores 100 (50 antipattern + 50 surcharge) and fails.  A structurally clean
    /// agent PR scores 50 and passes — the penalty enforces a higher bar, not a blanket
    /// block.
    ///
    /// ## Detection layers
    ///
    /// 1. **Known agentic handles** — exact case-insensitive match against the GitHub
    ///    Copilot coding agent account names active as of 2026-03-24:
    ///    `copilot[bot]`, `github-copilot[bot]`, `app/copilot`, `app/github-copilot`.
    ///
    /// 2. **Co-authored-by trailer** — scans PR body lines starting with
    ///    `co-authored-by:` for any Copilot handle.  Catches the case where a human
    ///    opens the PR but the Copilot coding agent autonomously pushes commits on top —
    ///    the scenario introduced by GitHub's March 24, 2026 "assign to Copilot" feature.
    ///
    /// ## Distinction from `is_automation_account`
    ///
    /// | Function               | `dependabot[bot]` | `copilot[bot]` |
    /// |------------------------|:-----------------:|:--------------:|
    /// | `is_automation_account`| `true`            | `true`         |
    /// | `is_agentic_actor`     | `false`           | `true`         |
    ///
    /// Both functions returning `true` for Copilot is intentional:
    /// automation accounts are exempt from the unlinked-PR penalty;
    /// agentic actors additionally receive the +50 surcharge.
    pub fn is_agentic_actor(&self, author: &str, pr_body: Option<&str>) -> bool {
        // Layer 1: GitHub Copilot coding agent handle patterns (zero-allocation).
        // These are the exact account names GitHub uses for the Copilot coding agent
        // (App format and [bot] suffix) as of the 2026-03-24 feature rollout.
        if author.eq_ignore_ascii_case("copilot[bot]")
            || author.eq_ignore_ascii_case("github-copilot[bot]")
            || author.eq_ignore_ascii_case("app/copilot")
            || author.eq_ignore_ascii_case("app/github-copilot")
        {
            return true;
        }
        // Layer 2: Co-authored-by trailer in the PR body.
        // The Copilot coding agent appends a `Co-authored-by: Copilot <...>` trailer
        // when it pushes autonomous commits onto an existing human-authored PR.
        if let Some(body) = pr_body {
            for line in body.lines() {
                let line_lower = line.to_ascii_lowercase();
                if line_lower.starts_with("co-authored-by:") && line_lower.contains("copilot") {
                    return true;
                }
            }
        }
        false
    }

    /// Returns `true` when the agentic-origin signal fires due to a
    /// `Co-authored-by: Copilot` trailer rather than the author handle.
    ///
    /// This identifies *author impersonation*: a human-owned PR where the Copilot
    /// coding agent autonomously pushed commits.  The commit author attribution
    /// (human handle) does not reflect the actual code origin (Copilot).
    ///
    /// ## Invariant
    /// ```text
    /// is_author_impersonation(author, body)
    ///   ≡ is_agentic_actor(author, body) && !is_agentic_actor(author, None)
    /// ```
    pub fn is_author_impersonation(&self, author: &str, pr_body: Option<&str>) -> bool {
        self.is_agentic_actor(author, pr_body) && !self.is_agentic_actor(author, None)
    }

    /// Returns `true` when `author` appears in [`Self::trusted_bot_authors`].
    ///
    /// Delegates to [`Self::is_automation_account`], which additionally
    /// checks the standard GitHub `[bot]` suffix and `[forge].automation_accounts`.
    pub fn is_trusted_bot(&self, author: &str) -> bool {
        self.is_automation_account(author)
    }

    // -----------------------------------------------------------------------
    // Gate logic
    // -----------------------------------------------------------------------

    /// Returns `true` if the PR body contains a Refactor Bonus marker.
    ///
    /// Recognised markers: `[REFACTOR]`, `[FIXES-DEBT]`.
    pub fn is_refactor_pr(pr_body: Option<&str>) -> bool {
        pr_body
            .map(|b| b.contains("[REFACTOR]") || b.contains("[FIXES-DEBT]"))
            .unwrap_or(false)
    }

    /// Returns the effective gate threshold for this PR.
    ///
    /// If the PR carries a refactor marker and `refactor_bonus > 0`, the
    /// threshold is raised by `refactor_bonus` (the gate is relaxed for
    /// intentional restructuring work).
    pub fn effective_gate(&self, pr_body: Option<&str>) -> u32 {
        if self.refactor_bonus > 0 && Self::is_refactor_pr(pr_body) {
            self.min_slop_score.saturating_add(self.refactor_bonus)
        } else {
            self.min_slop_score
        }
    }

    /// Returns `true` when the composite score passes the policy gate.
    ///
    /// Equivalent to `score < self.effective_gate(pr_body)`.
    pub fn gate_passes(&self, score: u32, pr_body: Option<&str>) -> bool {
        score < self.effective_gate(pr_body)
    }

    /// Computes a stable SHA-256 hash over the security-relevant canonical fields.
    ///
    /// Only fields that affect enforcement semantics are included — ephemeral
    /// settings such as `soft_fail` or `forge.governor_url` are excluded so
    /// that infrastructure-only changes do not trigger policy-drift alerts.
    ///
    /// The hash is deterministic: maps are sorted before serialization.
    /// Output is a 64-character lowercase hex string (SHA-256, FIPS 180-4).
    pub fn content_hash(&self) -> String {
        // Sort wasm_pins HashMap keys for deterministic ordering.
        let mut pins_sorted: Vec<(&String, &String)> = self.wasm_pins.iter().collect();
        pins_sorted.sort_by_key(|(k, _)| k.as_str());

        // Sort trusted_bot_authors for determinism (callers may insert in any order).
        let mut trusted_sorted = self.trusted_bot_authors.clone();
        trusted_sorted.sort();

        let canonical = serde_json::json!({
            "min_slop_score": self.min_slop_score,
            "require_issue_link": self.require_issue_link,
            "allowed_zombies": self.allowed_zombies,
            "pqc_enforced": self.pqc_enforced,
            "pqc.max_key_age_days": self.pqc.max_key_age_days,
            "custom_antipatterns": self.custom_antipatterns,
            "refactor_bonus": self.refactor_bonus,
            "trusted_bot_authors": trusted_sorted,
            "wasm_rules": self.wasm_rules,
            "wasm_pins": pins_sorted,
            "wasm_pqc_pub_key": self.wasm_pqc_pub_key,
            "suppressions": self.suppressions,
        });
        sha2::Sha256::digest(canonical.to_string().as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn default_gate_is_100() {
        let p = JanitorPolicy::default();
        assert_eq!(p.min_slop_score, 100);
        assert!(p.gate_passes(99, None));
        assert!(!p.gate_passes(100, None));
    }

    #[test]
    fn refactor_bonus_raises_threshold() {
        let p = JanitorPolicy {
            min_slop_score: 100,
            refactor_bonus: 30,
            ..Default::default()
        };
        // Without marker: gate at 100.
        assert!(!p.gate_passes(100, Some("Normal PR")));
        // With marker: gate raised to 130.
        assert!(p.gate_passes(100, Some("Refactoring internals [REFACTOR]")));
        assert!(p.gate_passes(129, Some("[REFACTOR]")));
        assert!(!p.gate_passes(130, Some("[REFACTOR]")));
    }

    #[test]
    fn fixes_debt_marker_also_qualifies() {
        let p = JanitorPolicy {
            min_slop_score: 100,
            refactor_bonus: 20,
            ..Default::default()
        };
        assert!(p.gate_passes(110, Some("Remove dead helpers [FIXES-DEBT]")));
    }

    #[test]
    fn zero_bonus_has_no_effect_on_gate() {
        let p = JanitorPolicy::default(); // refactor_bonus = 0
        assert!(!p.gate_passes(100, Some("[REFACTOR]")));
    }

    #[test]
    fn roundtrip_toml_serialization() {
        let original = JanitorPolicy {
            min_slop_score: 150,
            require_issue_link: true,
            allowed_zombies: false,
            pqc_enforced: false,
            pqc: PqcConfig::default(),
            custom_antipatterns: vec!["tools/queries/no_global.scm".to_owned()],
            refactor_bonus: 25,
            trusted_bot_authors: vec!["release-bot".to_owned()],
            forge: ForgeConfig::default(),
            webhook: WebhookConfig::default(),
            billing: BillingConfig::default(),
            jira: JiraConfig::default(),
            soft_fail: false,
            wisdom: WisdomConfig::default(),
            wasm_rules: Vec::new(),
            wasm_pins: HashMap::new(),
            wasm_pqc_pub_key: None,
            suppressions: Some(vec![Suppression {
                id: "waive-1".to_string(),
                rule: "security:test".to_string(),
                path_glob: "src/*.rs".to_string(),
                expires: Some("4102444800".to_string()),
                owner: "appsec".to_string(),
                reason: "test fixture".to_string(),
                approved: false,
            }]),
            rbac: RbacConfig::default(),
        };
        let serialised = toml::to_string(&original).unwrap();
        let deserialised: JanitorPolicy = toml::from_str(&serialised).unwrap();
        assert_eq!(original, deserialised);
    }

    #[test]
    fn suppression_matches_future_unix_expiry_and_glob() {
        let suppression = Suppression {
            id: "waive-1".to_string(),
            rule: "security:command_injection".to_string(),
            path_glob: "src/*.rs".to_string(),
            expires: Some("4102444800".to_string()),
            owner: "secops".to_string(),
            reason: "accepted risk".to_string(),
            approved: false,
        };
        assert!(suppression.matches("security:command_injection", "src/main.rs", 1_900_000_000));
        assert!(!suppression.matches("security:command_injection", "tests/main.rs", 1_900_000_000));
    }

    #[test]
    fn suppression_rfc3339_expiry_enforced() {
        let suppression = Suppression {
            id: "waive-2".to_string(),
            rule: "security:eval".to_string(),
            path_glob: "app.py".to_string(),
            expires: Some("2026-04-10T00:00:00Z".to_string()),
            owner: "secops".to_string(),
            reason: "temporary waiver".to_string(),
            approved: false,
        };
        assert!(suppression.is_active_at(1_775_779_199));
        assert!(!suppression.is_active_at(1_775_779_200));
    }

    #[test]
    fn wisdom_quorum_defaults_to_threshold_one() {
        let policy = JanitorPolicy::default();
        assert_eq!(policy.wisdom.quorum.threshold, 1);
        assert!(policy.wisdom.quorum.mirrors.is_empty());
    }

    #[test]
    fn webhook_should_fire_logic() {
        let cfg = WebhookConfig {
            url: "https://example.com/hook".to_string(),
            secret: String::new(),
            events: vec!["critical_threat".to_string()],
            lifecycle_events: false,
            ticket_project: None,
        };
        assert!(cfg.should_fire(true, false));
        assert!(!cfg.should_fire(false, false));
        assert!(!cfg.should_fire(false, true)); // necrotic_flag not in events

        let cfg2 = WebhookConfig {
            url: "https://example.com/hook".to_string(),
            secret: String::new(),
            events: vec!["all".to_string()],
            lifecycle_events: true,
            ticket_project: Some("SEC".to_string()),
        };
        assert!(cfg2.should_fire(false, false));

        let cfg3 = WebhookConfig::default(); // url is empty
        assert!(!cfg3.should_fire(true, true)); // empty url = no fire
        assert!(!cfg3.lifecycle_events);
        assert!(cfg3.ticket_project.is_none());
    }

    #[test]
    fn trusted_bot_empty_by_default() {
        let p = JanitorPolicy::default();
        assert!(p.trusted_bot_authors.is_empty());
        // With empty lists, [bot]-suffix authors ARE detected (layer 1 — no config required).
        assert!(p.is_trusted_bot("dependabot[bot]"));
        // Non-[bot] authors with no config entry must NOT be exempt.
        assert!(!p.is_trusted_bot("r-ryantm"));
        assert!(!p.is_trusted_bot(""));
    }

    #[test]
    fn trusted_bot_exact_case_insensitive_match() {
        let p = JanitorPolicy {
            trusted_bot_authors: vec!["release-bot".to_owned(), "R-RyanTM".to_owned()],
            ..Default::default()
        };
        assert!(p.is_trusted_bot("release-bot"));
        assert!(p.is_trusted_bot("RELEASE-BOT")); // case-insensitive
        assert!(p.is_trusted_bot("r-ryantm")); // mixed-case entry normalised
        assert!(!p.is_trusted_bot("release")); // prefix match must not fire
        assert!(!p.is_trusted_bot(""));
    }

    #[test]
    fn trusted_bot_roundtrip_toml() {
        let raw = "trusted_bot_authors = [\"release-bot\", \"ci-runner\"]\n";
        let p: JanitorPolicy = toml::from_str(raw).unwrap();
        assert_eq!(p.trusted_bot_authors, ["release-bot", "ci-runner"]);
        assert!(p.is_trusted_bot("ci-runner"));
        // [bot]-suffix authors are detected via layer-1 even when not in trusted_bot_authors.
        assert!(p.is_trusted_bot("dependabot[bot]"));
    }

    // --- Automation shield ---

    #[test]
    fn bot_suffix_detected_without_config() {
        // Any author ending with "[bot]" is recognised automatically — no
        // trusted_bot_authors or automation_accounts entry required.
        let p = JanitorPolicy::default();
        assert!(p.is_automation_account("dependabot[bot]"));
        assert!(p.is_automation_account("renovate[bot]"));
        assert!(p.is_automation_account("github-actions[bot]"));
        assert!(p.is_automation_account("app/nixpkgs-ci[bot]"));
    }

    #[test]
    fn non_bot_prefix_or_suffix_not_detected_without_config() {
        // Accounts without "app/" prefix, "[bot]" suffix, and not in any config
        // list must NOT be detected.
        let p = JanitorPolicy::default();
        assert!(!p.is_automation_account("r-ryantm"));
        assert!(!p.is_automation_account("human-dev"));
        assert!(!p.is_automation_account(""));
    }

    #[test]
    fn app_prefix_detected_without_config() {
        // Any author beginning with "app/" is unconditionally a GitHub App
        // installation — no trusted_bot_authors or automation_accounts entry
        // required.  This covers "app/dependabot", "app/renovate", etc.
        let p = JanitorPolicy::default();
        assert!(p.is_automation_account("app/dependabot"));
        assert!(p.is_automation_account("app/renovate"));
        assert!(p.is_automation_account("app/github-actions"));
        assert!(p.is_automation_account("app/nixpkgs-ci"));
        // Must not fire for strings that merely contain "app/" in the middle.
        assert!(!p.is_automation_account("myapp/renovate"));
    }

    #[test]
    fn forge_automation_accounts_detected() {
        let p = JanitorPolicy {
            forge: ForgeConfig {
                automation_accounts: vec!["r-ryantm".to_owned(), "app/nixpkgs-ci".to_owned()],
                governor_url: None,
                mtls_cert: None,
                mtls_key: None,
                deep_scan: false,
                corpus_stale_days: 7,
            },
            ..Default::default()
        };
        assert!(p.is_automation_account("r-ryantm"));
        assert!(p.is_automation_account("R-RyanTM")); // case-insensitive
        assert!(p.is_automation_account("app/nixpkgs-ci"));
        assert!(!p.is_automation_account("some-human"));
    }

    #[test]
    fn forge_automation_accounts_roundtrip_toml() {
        let raw = "[forge]\nautomation_accounts = [\"r-ryantm\", \"app/nixpkgs-ci\"]\ngovernor_url = \"http://127.0.0.1:3000\"\nmtls_cert = \"/tmp/client.pem\"\nmtls_key = \"/tmp/client.key\"\ndeep_scan = true\n";
        let p: JanitorPolicy = toml::from_str(raw).unwrap();
        assert_eq!(p.forge.automation_accounts, ["r-ryantm", "app/nixpkgs-ci"]);
        assert_eq!(
            p.forge.governor_url.as_deref(),
            Some("http://127.0.0.1:3000")
        );
        assert_eq!(p.forge.mtls_cert.as_deref(), Some("/tmp/client.pem"));
        assert_eq!(p.forge.mtls_key.as_deref(), Some("/tmp/client.key"));
        assert!(p.forge.deep_scan);
        assert!(p.is_automation_account("r-ryantm"));
        assert!(p.is_automation_account("app/nixpkgs-ci"));
        assert!(!p.is_automation_account("human-author"));
    }

    #[test]
    fn is_trusted_bot_delegates_to_is_automation_account() {
        // is_trusted_bot() is a backwards-compat alias — must match is_automation_account().
        let p = JanitorPolicy {
            forge: ForgeConfig {
                automation_accounts: vec!["r-ryantm".to_owned()],
                governor_url: None,
                mtls_cert: None,
                mtls_key: None,
                deep_scan: false,
                corpus_stale_days: 7,
            },
            ..Default::default()
        };
        assert_eq!(
            p.is_trusted_bot("r-ryantm"),
            p.is_automation_account("r-ryantm")
        );
        assert_eq!(
            p.is_trusted_bot("dependabot[bot]"),
            p.is_automation_account("dependabot[bot]")
        );
    }

    #[test]
    fn load_missing_file_returns_default() {
        let tmp = std::env::temp_dir().join("janitor_policy_missing_test");
        let p = JanitorPolicy::load(&tmp).unwrap();
        assert_eq!(p, JanitorPolicy::default());
    }

    #[test]
    fn load_valid_toml() {
        let dir = std::env::temp_dir().join("janitor_policy_test_load");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("janitor.toml"),
            "min_slop_score = 200\nrequire_issue_link = true\n[forge]\ngovernor_url = \"http://127.0.0.1:4040\"\n",
        )
        .unwrap();
        let p = JanitorPolicy::load(&dir).unwrap();
        assert_eq!(p.min_slop_score, 200);
        assert!(p.require_issue_link);
        assert_eq!(
            p.forge.governor_url.as_deref(),
            Some("http://127.0.0.1:4040")
        );
        assert!(p.forge.mtls_cert.is_none());
        assert!(p.forge.mtls_key.is_none());
    }

    #[test]
    fn load_malformed_toml_returns_error() {
        let dir = std::env::temp_dir().join("janitor_policy_malformed_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("janitor.toml"), "min_slop_score = [[[").unwrap();
        let result = JanitorPolicy::load(&dir);
        assert!(
            result.is_err(),
            "malformed janitor.toml must return an error"
        );
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("parse error"), "error must cite parse error");
    }

    // --- AgenticOrigin detection ---

    #[test]
    fn copilot_bot_suffix_is_agentic() {
        let p = JanitorPolicy::default();
        assert!(p.is_agentic_actor("copilot[bot]", None));
        assert!(p.is_agentic_actor("github-copilot[bot]", None));
    }

    #[test]
    fn copilot_app_prefix_is_agentic() {
        let p = JanitorPolicy::default();
        assert!(p.is_agentic_actor("app/copilot", None));
        assert!(p.is_agentic_actor("app/github-copilot", None));
    }

    #[test]
    fn copilot_handles_are_case_insensitive() {
        let p = JanitorPolicy::default();
        assert!(p.is_agentic_actor("Copilot[bot]", None));
        assert!(p.is_agentic_actor("GITHUB-COPILOT[BOT]", None));
        assert!(p.is_agentic_actor("App/Copilot", None));
    }

    #[test]
    fn basic_ci_bots_are_not_agentic() {
        // Dependabot, Renovate, and GitHub Actions are NOT agentic actors.
        let p = JanitorPolicy::default();
        assert!(!p.is_agentic_actor("dependabot[bot]", None));
        assert!(!p.is_agentic_actor("renovate[bot]", None));
        assert!(!p.is_agentic_actor("github-actions[bot]", None));
        assert!(!p.is_agentic_actor("r-ryantm", None));
        assert!(!p.is_agentic_actor("app/dependabot", None));
        assert!(!p.is_agentic_actor("app/renovate", None));
    }

    #[test]
    fn human_authors_are_not_agentic() {
        let p = JanitorPolicy::default();
        assert!(!p.is_agentic_actor("human-dev", None));
        assert!(!p.is_agentic_actor("alice", None));
        assert!(!p.is_agentic_actor("", None));
    }

    #[test]
    fn coauthored_by_copilot_trailer_fires_agentic() {
        let p = JanitorPolicy::default();
        let body = "Fixes #42\n\nCo-authored-by: Copilot <copilot@github.com>";
        // Human PR author but Copilot co-committed.
        assert!(p.is_agentic_actor("human-dev", Some(body)));
    }

    #[test]
    fn coauthored_by_trailer_case_insensitive() {
        let p = JanitorPolicy::default();
        let body = "co-authored-by: COPILOT <copilot@github.com>";
        assert!(p.is_agentic_actor("human-dev", Some(body)));
    }

    #[test]
    fn coauthored_by_non_copilot_does_not_fire() {
        let p = JanitorPolicy::default();
        let body = "Co-authored-by: alice <alice@example.com>";
        assert!(!p.is_agentic_actor("human-dev", Some(body)));
    }

    #[test]
    fn copilot_author_is_also_automation_account() {
        // Copilot[bot] matches both is_automation_account (via [bot] suffix)
        // AND is_agentic_actor — these are independent, non-exclusive gates.
        let p = JanitorPolicy::default();
        assert!(p.is_automation_account("copilot[bot]"));
        assert!(p.is_agentic_actor("copilot[bot]", None));
    }

    // --- AuthorImpersonation detection ---

    #[test]
    fn human_pr_with_copilot_coauthor_trailer_is_impersonation() {
        // A human opens the PR; Copilot autonomously pushed commits.
        // The body trailer is the only trigger — the author handle is clean.
        let p = JanitorPolicy::default();
        let body = "Fixes #123\n\nCo-authored-by: Copilot <copilot@github.com>";
        assert!(
            p.is_author_impersonation("alice", Some(body)),
            "human PR with Copilot co-author trailer must fire impersonation"
        );
    }

    #[test]
    fn copilot_bot_handle_is_not_impersonation() {
        // When the PR author IS Copilot, it's agentic origin — not impersonation.
        // Impersonation requires the handle to be clean while the body triggers.
        let p = JanitorPolicy::default();
        assert!(
            !p.is_author_impersonation("copilot[bot]", None),
            "Copilot handle author is agentic origin, not impersonation"
        );
    }

    #[test]
    fn human_pr_without_copilot_trailer_is_not_impersonation() {
        let p = JanitorPolicy::default();
        let body = "Fixes #456\n\nCo-authored-by: alice <alice@example.com>";
        assert!(
            !p.is_author_impersonation("alice", Some(body)),
            "non-Copilot co-author trailer must not trigger impersonation"
        );
    }

    #[test]
    fn copilot_handle_with_copilot_body_is_not_impersonation() {
        // Both handle and body fire → agentic_origin, NOT impersonation.
        // Impersonation is only when body fires but handle does NOT.
        let p = JanitorPolicy::default();
        let body = "Co-authored-by: Copilot <copilot@github.com>";
        assert!(
            !p.is_author_impersonation("copilot[bot]", Some(body)),
            "when handle already triggers, body trailer cannot add impersonation"
        );
    }

    #[test]
    fn content_hash_is_deterministic_for_default_policy() {
        let p = JanitorPolicy::default();
        let h1 = p.content_hash();
        let h2 = p.content_hash();
        assert_eq!(h1, h2, "content_hash must be stable across calls");
        assert_eq!(h1.len(), 64, "SHA-256 hex output is 64 characters");
    }

    #[test]
    fn content_hash_changes_on_security_field_mutation() {
        let p1 = JanitorPolicy::default();
        let p2 = JanitorPolicy {
            min_slop_score: 200,
            ..Default::default()
        };
        assert_ne!(
            p1.content_hash(),
            p2.content_hash(),
            "different min_slop_score must produce a different content hash"
        );
    }

    #[test]
    fn content_hash_stable_despite_map_insertion_order() {
        let mut pins1 = HashMap::new();
        pins1.insert("rules/a.wasm".to_string(), "aaa".to_string());
        pins1.insert("rules/b.wasm".to_string(), "bbb".to_string());
        let p1 = JanitorPolicy {
            wasm_pins: pins1,
            ..Default::default()
        };

        let mut pins2 = HashMap::new();
        pins2.insert("rules/b.wasm".to_string(), "bbb".to_string());
        pins2.insert("rules/a.wasm".to_string(), "aaa".to_string());
        let p2 = JanitorPolicy {
            wasm_pins: pins2,
            ..Default::default()
        };

        assert_eq!(
            p1.content_hash(),
            p2.content_hash(),
            "HashMap insertion order must not affect content_hash"
        );
    }
}
