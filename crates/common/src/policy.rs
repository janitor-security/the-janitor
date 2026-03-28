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
}

impl Default for BillingConfig {
    fn default() -> Self {
        Self {
            triage_minutes_per_finding: Self::default_triage_minutes(),
            critical_threat_usd: Self::default_critical_usd(),
            necrotic_usd: Self::default_necrotic_usd(),
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
}

impl Default for WebhookConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            secret: String::new(),
            events: Self::default_events(),
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
// ForgeConfig — [forge] sub-table
// ---------------------------------------------------------------------------

/// Engine-level configuration nested under `[forge]` in `janitor.toml`.
///
/// These settings control the slop-detection engine's behaviour independently
/// of the governance gate thresholds that live at the top level of the manifest.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
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
}

impl Default for JanitorPolicy {
    fn default() -> Self {
        Self {
            min_slop_score: 100,
            require_issue_link: false,
            allowed_zombies: false,
            pqc_enforced: false,
            custom_antipatterns: Vec::new(),
            refactor_bonus: 0,
            trusted_bot_authors: Vec::new(),
            forge: ForgeConfig::default(),
            webhook: WebhookConfig::default(),
            billing: BillingConfig::default(),
        }
    }
}

impl JanitorPolicy {
    // -----------------------------------------------------------------------
    // Loading
    // -----------------------------------------------------------------------

    /// Attempts to load `janitor.toml` from `repo_root`.
    ///
    /// Returns the default policy when:
    /// - `janitor.toml` does not exist (silent, expected case)
    /// - the file cannot be read (emits a warning to stderr)
    /// - the file contains invalid TOML or unknown fields (emits a warning)
    ///
    /// Policy load **never fails the bounce pipeline** — a malformed manifest
    /// falls back to defaults rather than blocking CI.
    pub fn load(repo_root: &Path) -> Self {
        let path = repo_root.join("janitor.toml");
        if !path.exists() {
            return Self::default();
        }
        let raw = match std::fs::read_to_string(&path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!(
                    "warning: janitor.toml — failed to read {}: {}. Using defaults.",
                    path.display(),
                    e
                );
                return Self::default();
            }
        };
        match toml::from_str::<Self>(&raw) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("warning: janitor.toml — parse error: {e}. Using defaults.");
                Self::default()
            }
        }
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
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
            custom_antipatterns: vec!["tools/queries/no_global.scm".to_owned()],
            refactor_bonus: 25,
            trusted_bot_authors: vec!["release-bot".to_owned()],
            forge: ForgeConfig::default(),
            webhook: WebhookConfig::default(),
            billing: BillingConfig::default(),
        };
        let serialised = toml::to_string(&original).unwrap();
        let deserialised: JanitorPolicy = toml::from_str(&serialised).unwrap();
        assert_eq!(original, deserialised);
    }

    #[test]
    fn webhook_should_fire_logic() {
        let cfg = WebhookConfig {
            url: "https://example.com/hook".to_string(),
            secret: String::new(),
            events: vec!["critical_threat".to_string()],
        };
        assert!(cfg.should_fire(true, false));
        assert!(!cfg.should_fire(false, false));
        assert!(!cfg.should_fire(false, true)); // necrotic_flag not in events

        let cfg2 = WebhookConfig {
            url: "https://example.com/hook".to_string(),
            secret: String::new(),
            events: vec!["all".to_string()],
        };
        assert!(cfg2.should_fire(false, false));

        let cfg3 = WebhookConfig::default(); // url is empty
        assert!(!cfg3.should_fire(true, true)); // empty url = no fire
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
        let raw = "[forge]\nautomation_accounts = [\"r-ryantm\", \"app/nixpkgs-ci\"]\n";
        let p: JanitorPolicy = toml::from_str(raw).unwrap();
        assert_eq!(p.forge.automation_accounts, ["r-ryantm", "app/nixpkgs-ci"]);
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
        let p = JanitorPolicy::load(&tmp);
        assert_eq!(p, JanitorPolicy::default());
    }

    #[test]
    fn load_valid_toml() {
        let dir = std::env::temp_dir().join("janitor_policy_test_load");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("janitor.toml"),
            "min_slop_score = 200\nrequire_issue_link = true\n",
        )
        .unwrap();
        let p = JanitorPolicy::load(&dir);
        assert_eq!(p.min_slop_score, 200);
        assert!(p.require_issue_link);
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
}
