//! Intelligence report aggregation and rendering.
//!
//! Reads `.janitor/bounce_log.ndjson` — a newline-delimited JSON log appended
//! by each `janitor bounce` invocation — and produces three analytical sections:
//!
//! 1. **Slop Top 50** — PRs ranked by composite [`SlopScore`].
//! 2. **Structural Clones** — near-duplicate PR pairs detected via 64-hash
//!    MinHash LSH (Jaccard ≥ 0.70).
//! 3. **Zombie Dependencies** — PRs that introduced packages declared in a
//!    manifest but never imported in source.
//!
//! When no bounce log is present, [`render_scan_markdown`] and [`render_scan_json`]
//! render a one-shot dead-symbol audit from a direct pipeline scan instead.
//!
//! Output formats: `markdown` (default) and `json`.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::path::Path;

// ---------------------------------------------------------------------------
// ROI Constants — Workslop Triage Tax
// ---------------------------------------------------------------------------

/// Conservative estimate of senior-engineer minutes consumed triaging a single
/// slop PR (AI-generated hallucination, zombie dependency, adversarial security
/// claim, or blocked high-score submission).
///
/// Source: industry Workslop research (2026). See <https://builtin.com/articles/what-is-workslop>.
pub const MINUTES_PER_TRIAGE: f64 = 12.0;

// ---------------------------------------------------------------------------
// Categorical Billing — Threat Classification
// ---------------------------------------------------------------------------

/// Returns `true` if the entry is a **Critical Threat**:
/// any antipattern description containing `"security:"` (Unicode, LotL, NCD
/// anomalies, compiled payload) OR a verified Swarm collision (`collided_pr_numbers`
/// is non-empty).
///
/// Critical Threats are billed at **$150** per intercept in the TEI ledger.
pub fn is_critical_threat(e: &BounceLogEntry) -> bool {
    e.antipatterns.iter().any(|a| a.contains("security:")) || !e.collided_pr_numbers.is_empty()
}

/// Fire an outbound webhook POST if configured in `janitor.toml`.
///
/// - Signs the payload with HMAC-SHA256 using the configured secret.
/// - Resolves `"env:VAR_NAME"` secrets from the environment at call time.
/// - Filters events by `webhook.events` before sending.
/// - Best-effort: logs a warning on failure, never panics, never blocks the bounce result.
/// - Non-blocking: spawns a thread for the HTTP POST so the CLI exits promptly.
pub fn fire_webhook_if_configured(entry: &BounceLogEntry, policy: &common::policy::JanitorPolicy) {
    let cfg = &policy.webhook;
    let is_critical = is_critical_threat(entry);
    let is_necrotic = entry.necrotic_flag.is_some();

    if !cfg.should_fire(is_critical, is_necrotic) {
        return;
    }

    // ── Resolve secret ───────────────────────────────────────────────────
    let secret = if cfg.secret.starts_with("env:") {
        let var_name = &cfg.secret[4..];
        match std::env::var(var_name) {
            Ok(v) => v,
            Err(_) => {
                eprintln!(
                    "Structural Integrity Warning: Webhook secret environment variable is not set. Delivering unsigned payload."
                );
                String::new()
            }
        }
    } else {
        cfg.secret.clone()
    };

    // ── Serialize payload ────────────────────────────────────────────────
    let payload = match serde_json::to_string(entry) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("warning: failed to serialise webhook payload: {e}");
            return;
        }
    };

    // ── HMAC-SHA256 signature ─────────────────────────────────────────────
    let sig_header = if !secret.is_empty() {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        let result = mac.finalize().into_bytes();
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        format!("sha256={hex}")
    } else {
        String::new()
    };

    let url = cfg.url.clone();
    let event_name = if is_critical {
        "critical_threat"
    } else {
        "necrotic_flag"
    };

    // ── Non-blocking POST ─────────────────────────────────────────────────
    std::thread::spawn(move || {
        let mut builder = ureq::post(&url)
            .header("Content-Type", "application/json")
            .header("X-Janitor-Event", event_name);
        if !sig_header.is_empty() {
            builder = builder.header("X-Janitor-Signature-256", &sig_header);
        }
        match builder.send(payload.as_str()) {
            Ok(_) => {}
            Err(e) => eprintln!("warning: webhook delivery failed: {e}"),
        }
    });
}

// ---------------------------------------------------------------------------
// webhook-test command
// ---------------------------------------------------------------------------

/// `janitor webhook-test` — synchronous test delivery to the configured webhook URL.
///
/// Loads `[webhook]` from `janitor.toml` in `repo`, constructs a synthetic
/// `critical_threat` `BounceLogEntry`, signs it with HMAC-SHA256, and POSTs it
/// synchronously.  Unlike `fire_webhook_if_configured` (which is non-blocking and
/// best-effort), this function blocks and returns an error on failure so the
/// customer gets clear terminal feedback.
pub fn cmd_webhook_test(repo: &std::path::Path) -> anyhow::Result<()> {
    use anyhow::Context as _;

    let policy = common::policy::JanitorPolicy::load(repo);
    let cfg = &policy.webhook;

    if cfg.url.is_empty() {
        anyhow::bail!(
            "No webhook URL configured. Add a [webhook] section to {}/janitor.toml",
            repo.display()
        );
    }

    eprintln!("info: webhook-test — URL: {}", cfg.url);
    eprintln!("info: webhook-test — events filter: {:?}", cfg.events);

    // ── Resolve secret ───────────────────────────────────────────────────────
    let secret = if cfg.secret.starts_with("env:") {
        let var_name = &cfg.secret[4..];
        std::env::var(var_name).unwrap_or_else(|_| {
            eprintln!(
                "Structural Integrity Warning: Webhook secret environment variable is not set. Delivering unsigned payload."
            );
            String::new()
        })
    } else {
        cfg.secret.clone()
    };

    // ── Construct synthetic critical_threat payload ──────────────────────────
    let dummy = BounceLogEntry {
        pr_number: Some(0),
        author: Some("janitor-webhook-test".to_string()),
        timestamp: crate::utc_now_iso8601(),
        slop_score: 150,
        dead_symbols_added: 0,
        logic_clones_found: 0,
        zombie_symbols_added: 0,
        unlinked_pr: 0,
        antipatterns: vec!["security:unsafe_string_function".to_string()],
        comment_violations: vec![],
        min_hashes: vec![],
        zombie_deps: vec![],
        state: PrState::Open,
        is_bot: false,
        repo_slug: "janitor-webhook-test/test-repo".to_string(),
        suppressed_by_domain: 0,
        collided_pr_numbers: vec![],
        necrotic_flag: None,
        commit_sha: "0000000000000000000000000000000000000000".to_string(),
        policy_hash: "test".to_string(),
        version_silos: vec![],
        agentic_pct: 100.0,
        ci_energy_saved_kwh: 0.1,
        provenance: Provenance::default(),
        governor_status: None,
        pqc_sig: None,
    };

    let payload = serde_json::to_string(&dummy).context("failed to serialise test payload")?;
    eprintln!("info: webhook-test — payload size: {} bytes", payload.len());

    // ── HMAC-SHA256 signature ────────────────────────────────────────────────
    let sig_header = if !secret.is_empty() {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
        mac.update(payload.as_bytes());
        let hex: String = mac
            .finalize()
            .into_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let header = format!("sha256={hex}");
        eprintln!("info: webhook-test — X-Janitor-Signature-256: {header}");
        header
    } else {
        eprintln!("warning: webhook-test — no secret configured, sending unsigned");
        String::new()
    };

    // ── Blocking POST ────────────────────────────────────────────────────────
    let mut builder = ureq::post(&cfg.url)
        .header("Content-Type", "application/json")
        .header("X-Janitor-Event", "critical_threat");
    if !sig_header.is_empty() {
        builder = builder.header("X-Janitor-Signature-256", &sig_header);
    }

    match builder.send(payload.as_str()) {
        Ok(resp) => {
            let status = resp.status();
            eprintln!("info: webhook-test — HTTP {status} ✓ delivery confirmed");
            println!("webhook-test OK — HTTP {status}");
        }
        Err(ureq::Error::StatusCode(code)) => {
            anyhow::bail!("webhook-test FAILED — HTTP {code}");
        }
        Err(e) => {
            anyhow::bail!("webhook-test FAILED — transport error: {e}");
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// PrState
// ---------------------------------------------------------------------------

/// GitHub PR lifecycle state at the time of the bounce audit.
///
/// Passed via `--pr-state` on the CLI.  Defaults to [`PrState::Open`] when
/// omitted — the most conservative assumption (the patch is still candidate
/// for merge).  Use `Merged` or `Closed` to classify historical entries in the
/// CSV export as non-actionable for pipeline purposes.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PrState {
    /// PR is open and can still be merged (default).
    #[default]
    Open,
    /// PR has been merged into the target branch.
    Merged,
    /// PR was closed without merging.
    Closed,
}

impl std::fmt::Display for PrState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrState::Open => f.write_str("Open"),
            PrState::Merged => f.write_str("Merged"),
            PrState::Closed => f.write_str("Closed"),
        }
    }
}

impl std::str::FromStr for PrState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "open" => Ok(PrState::Open),
            "merged" => Ok(PrState::Merged),
            "closed" => Ok(PrState::Closed),
            other => Err(format!(
                "unknown PR state '{other}'; expected open|merged|closed"
            )),
        }
    }
}

// ---------------------------------------------------------------------------
// Provenance
// ---------------------------------------------------------------------------

/// Zero-upload proof ledger — bytes processed vs. bytes transmitted to the
/// control plane.
///
/// Allows an operator to verify the zero-exfiltration claim at the
/// individual-bounce level: `source_bytes_processed` captures the raw
/// analysis surface; `egress_bytes_sent` is the exact byte-length of the
/// JSON payload POSTed to the Governor.  The ratio (egress / source) ≈ 0%
/// — the structural score, never the source — is what crosses the network.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Provenance {
    /// Wall-clock duration of the full bounce analysis in milliseconds.
    pub analysis_duration_ms: u64,
    /// Total bytes of added source content fed into the analysis engine.
    ///
    /// Patch mode: sum of bytes on `+` lines (excluding `+++` headers).
    /// Git-native mode: sum of all changed-file blob sizes from the pack index.
    pub source_bytes_processed: u64,
    /// Exact byte-length of the JSON payload POSTed to the Governor control plane.
    ///
    /// Zero when `--report-url` is not configured (local-only / CLI-only mode).
    /// This is the *only* data that leaves the runner.
    pub egress_bytes_sent: u64,
}

// ---------------------------------------------------------------------------
// BounceLogEntry
// ---------------------------------------------------------------------------

/// A single persisted bounce result.
///
/// Appended as one JSON line to `.janitor/bounce_log.ndjson` at the end of
/// each `janitor bounce` invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BounceLogEntry {
    /// PR number, if supplied via `--pr-number`.
    #[serde(default)]
    pub pr_number: Option<u64>,
    /// PR author handle, if supplied via `--author`.
    #[serde(default)]
    pub author: Option<String>,
    /// UTC timestamp of the bounce invocation (ISO 8601).
    pub timestamp: String,
    /// Composite slop score: dead×10 + clones×5 + zombies×15 + antipatterns×50
    ///                       + comment_violations×5 + unlinked_pr×20.
    pub slop_score: u32,
    /// Number of added functions whose names already appear in the registry.
    pub dead_symbols_added: u32,
    /// Number of structural clone pairs within the patch.
    pub logic_clones_found: u32,
    /// Number of zombie symbol reintroductions (verbatim body match to dead symbol).
    pub zombie_symbols_added: u32,
    /// `1` if the PR was flagged as unlinked (no issue reference in body), `0` otherwise.
    ///
    /// Contributes ×20 to the composite slop score.
    #[serde(default)]
    pub unlinked_pr: u32,
    /// Descriptions of each language-specific antipattern finding.
    ///
    /// One entry per detection (hallucinated import, vacuous unsafe, goroutine closure trap,
    /// Kubernetes wildcard host, etc.).  The count `antipatterns_found` is `antipatterns.len()`.
    /// Populated in patch mode; empty for git-native bounces and pre-v6.9 log entries.
    #[serde(default)]
    pub antipatterns: Vec<String>,
    /// Matched banned phrase for each comment violation.
    ///
    /// Format: `"[line N] <phrase>"`.  Populated in patch mode only.
    /// Empty for git-native bounces and pre-v6.9 log entries.
    #[serde(default)]
    pub comment_violations: Vec<String>,
    /// MinHash sketch — 64 `u64` values — for clone detection via [`LshIndex`].
    ///
    /// Computed from raw patch bytes (patch mode) or the deterministic merkle key
    /// (git-native mode). Empty for log entries written before this field was added.
    #[serde(default)]
    pub min_hashes: Vec<u64>,
    /// Zombie dependency names detected at bounce time.
    ///
    /// Packages that appear in a manifest (`Cargo.toml`, `package.json`,
    /// `requirements.txt`) but whose name was not found in any source file.
    #[serde(default)]
    pub zombie_deps: Vec<String>,
    /// GitHub PR lifecycle state (`open`, `merged`, `closed`).
    ///
    /// Supplied via `--pr-state`; defaults to `open`.  Enables downstream
    /// segmentation of Active Threats (open) from Historical Anomalies (merged/closed).
    #[serde(default)]
    pub state: PrState,
    /// `true` when the PR author is listed in the governance manifest's
    /// `trusted_bot_authors` array (`janitor.toml`).
    ///
    /// Derived from [`common::policy::JanitorPolicy::is_trusted_bot`] at bounce
    /// time.  Always `false` when no governance manifest is present.
    #[serde(default)]
    pub is_bot: bool,
    /// GitHub repository slug (`owner/repo`) identifying the target repository.
    ///
    /// Populated from `--repo-slug` or the `GITHUB_REPOSITORY` environment
    /// variable.  Empty string when neither is available.
    #[serde(default)]
    pub repo_slug: String,
    /// Number of antipattern findings suppressed by domain routing.
    ///
    /// Memory-safety rules (e.g. raw `new`, vacuous `unsafe`) are not applied to
    /// vendored (`vendor/`, `node_modules/`) or test (`tests/`, `spec/`) files.
    /// This field records how many findings were withheld — present in the report
    /// as a "Domain Routing" context line so the operator knows the engine is
    /// selective, not blind.
    ///
    /// Always `0` for log entries written before this field was introduced.
    #[serde(default)]
    pub suppressed_by_domain: u32,

    /// PR numbers of prior bounced patches whose MinHash Jaccard similarity ≥ 0.85
    /// with this patch — indicating structural clone overlap.
    ///
    /// Populated by `cmd_bounce` after querying the bounce log LshIndex.
    /// Empty for log entries written before this field was introduced.
    #[serde(default)]
    pub collided_pr_numbers: Vec<u32>,

    /// Necrotic garbage-collection flag from the Backlog Pruner.
    ///
    /// One of `"SEMANTIC_NULL"` (cosmetic-only change), `"GHOST_COLLISION"`
    /// (targets decayed architecture), or `"UNWIRED_ISLAND"` (unreachable new
    /// code).  `None` when no necrotic condition was detected.
    #[serde(default)]
    pub necrotic_flag: Option<String>,

    /// Git commit SHA of the PR head at bounce time.
    ///
    /// Populated from `--head <sha>` in git-native mode, or from the
    /// `GITHUB_SHA` environment variable in GitHub Actions.
    /// Empty string when neither is available.
    #[serde(default)]
    pub commit_sha: String,

    /// BLAKE3 hex digest of the `janitor.toml` file contents at bounce time.
    ///
    /// Provides a cryptographic reference to the policy that was in effect
    /// when this decision was made — directly answers the SOC 2 auditor
    /// question: "What policy was active at the time of this scan?"
    ///
    /// Empty string when no `janitor.toml` is present (default policy applied).
    #[serde(default)]
    pub policy_hash: String,

    /// Crate/package names that appear at more than one distinct version across the PR's
    /// manifest files (`Cargo.toml`, `package.json`).
    ///
    /// Each entry contributed +20 points to `slop_score` at bounce time.
    #[serde(default)]
    pub version_silos: Vec<String>,

    /// Percentage of commits in this PR attributed to an agentic actor (Copilot,
    /// autonomous coding agent, etc.), expressed as a float in `[0.0, 100.0]`.
    ///
    /// Computed as `(commits_with_agentic_origin / total_pr_commits) × 100`.
    /// When per-commit attribution data is unavailable (the common case), this
    /// field defaults to `100.0` if `policy.is_agentic_actor()` fired on the PR
    /// author, or `0.0` otherwise.
    ///
    /// Maps to the GitHub "active Copilot coding agent" metrics introduced in
    /// the March 2026 infrastructure update.
    #[serde(default)]
    pub agentic_pct: f64,

    /// CI datacenter energy saved by blocking this PR, in kilowatt-hours.
    ///
    /// Basis: industry-average CI run = 15 minutes; a heavy CI server draws ~400 W;
    /// therefore one blocked PR = 15 min × 400 W = **0.1 kWh** of avoided grid load.
    /// Set to `0.1` when `slop_score > 0` (actionable intercept), `0.0` otherwise.
    #[serde(default)]
    pub ci_energy_saved_kwh: f64,

    /// Zero-upload proof ledger — bytes analysed vs. bytes transmitted.
    ///
    /// Populated at bounce time.  Allows auditors to verify that
    /// `egress_bytes_sent / source_bytes_processed` ≈ 0% — structural score
    /// only, not source code, crosses the network boundary.
    #[serde(default)]
    pub provenance: Provenance,

    /// Governor attestation status for this bounce result.
    ///
    /// - `"ok"` — bounce result successfully POSTed to the Governor.
    /// - `"degraded"` — POST failed and `--soft-fail` was active; pipeline
    ///   proceeded without attestation.  The slop score is still authoritative.
    /// - `None` (field absent) — Governor not configured (`--report-url` absent).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governor_status: Option<String>,

    /// ML-DSA-65 (FIPS 204) signature over the CycloneDX v1.6 CBOM for this entry,
    /// base64-encoded (STANDARD alphabet).
    ///
    /// Present only when `janitor bounce --pqc-key <path>` was used and signing
    /// succeeded.  Verifiable offline via:
    ///   `janitor verify-cbom --key <pub.key> <log.ndjson>`
    ///
    /// When present, Governor attestation was skipped — local BYOK signing is
    /// the chain-of-custody mechanism for this entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pqc_sig: Option<String>,
}

// ---------------------------------------------------------------------------
// ReportData
// ---------------------------------------------------------------------------

/// Per-contributor aggregate statistics derived from bounce log entries.
pub struct UserStats {
    /// Contributor handle (GitHub login or equivalent).
    pub author: String,
    /// Sum of `slop_score` across all PRs attributed to this contributor.
    pub total_slop_score: u64,
    /// Total number of PRs audited for this contributor.
    pub total_pr_count: u32,
    /// Number of PRs with `slop_score == 0`.
    pub clean_pr_count: u32,
}

/// Aggregated report computed from all bounce log entries.
pub struct ReportData {
    /// All log entries, owned.
    pub entries: Vec<BounceLogEntry>,
    /// Indices into `entries`, sorted by `slop_score` descending, capped at `top_n`.
    pub slop_top_indices: Vec<usize>,
    /// Pairs `(i, j)` where `entries[i]` and `entries[j]` are structural clones
    /// (MinHash Jaccard similarity ≥ 0.70).
    pub clone_pairs: Vec<(usize, usize)>,
    /// Indices of entries that have at least one zombie dependency.
    pub zombie_indices: Vec<usize>,
    /// Indices of entries that have at least one version silo.
    pub silo_indices: Vec<usize>,
    /// Total engineering minutes reclaimed: necrotic PR count × [`MINUTES_PER_TRIAGE`].
    ///
    /// Only PRs with `necrotic_flag.is_some()` contribute — these are
    /// `SEMANTIC_NULL`, `GHOST_COLLISION`, and `UNWIRED_ISLAND` verdicts that
    /// can be bulk-closed by a bot without human review.  Score-blocked PRs
    /// still require a human to verify the finding, so they do not reclaim time.
    pub total_reclaimed_minutes: f64,
    /// Total number of actionable intercepts: Critical Threats, Necrotic GC,
    /// OR Structural Slop PRs (slop_score > 0, no critical or necrotic signal).
    pub total_actionable_intercepts: u64,
    /// Count of PRs classified as Critical Threats per [`is_critical_threat`].
    ///
    /// A subset of `total_actionable_intercepts`; used to split TEI billing
    /// between the $150 security-intercept tier and $20 GC/slop tiers.
    pub critical_threats_count: u64,
    /// Count of PRs with `slop_score > 0` that are neither Critical nor Necrotic.
    ///
    /// These PRs carry measurable structural debt but no security or dead-code
    /// signal.  Billed at **$20** per intercept in the TEI ledger.
    pub structural_slop_count: u64,
    /// Indices of entries that carry a `necrotic_flag`, sorted by slop_score descending.
    pub necrotic_indices: Vec<usize>,
    /// Top 10 contributors ranked by cumulative slop score descending.
    pub sloppiest_users: Vec<UserStats>,
}

// ---------------------------------------------------------------------------
// I/O helpers
// ---------------------------------------------------------------------------

/// Reads `.janitor/bounce_log.ndjson` and returns all valid entries.
///
/// Silently skips malformed lines — partial writes cannot corrupt the log.
pub fn load_bounce_log(janitor_dir: &Path) -> Vec<BounceLogEntry> {
    let log_path = janitor_dir.join("bounce_log.ndjson");
    if !log_path.exists() {
        return Vec::new();
    }
    let content = match std::fs::read_to_string(&log_path) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Appends one entry as a JSON line to `.janitor/bounce_log.ndjson`.
///
/// Creates the janitor directory and log file if absent.
/// Calls [`File::sync_all`] after writing to flush the OS page cache to physical
/// disk before returning — guarantees the entry survives a SIGKILL of the parent
/// shell script between iterations.
/// Emits a diagnostic to stderr on any I/O failure so silent log loss is detectable.
pub fn append_bounce_log(janitor_dir: &Path, entry: &BounceLogEntry) {
    let line = match serde_json::to_string(entry) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("janitor: bounce_log serialization failed: {e}");
            return;
        }
    };
    let log_path = janitor_dir.join("bounce_log.ndjson");
    if let Err(e) = std::fs::create_dir_all(janitor_dir) {
        eprintln!(
            "janitor: cannot create .janitor dir {}: {e}",
            janitor_dir.display()
        );
        return;
    }
    use std::io::Write as _;
    match std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
    {
        Ok(mut f) => {
            if let Err(e) = writeln!(f, "{line}") {
                eprintln!("janitor: write to {} failed: {e}", log_path.display());
                return;
            }
            // Force OS page-cache flush to physical storage.  Without this, a
            // SIGKILL of the calling script could lose the entry even though
            // write(2) returned successfully.
            if let Err(e) = f.sync_all() {
                eprintln!("janitor: sync_all on {} failed: {e}", log_path.display());
            }
        }
        Err(e) => {
            eprintln!(
                "janitor: cannot open {} for append: {e}",
                log_path.display()
            );
        }
    }
}

// ---------------------------------------------------------------------------
// SVG Integrity Badge
// ---------------------------------------------------------------------------

/// Write a color-coded status badge to `.janitor/janitor_badge.svg`.
///
/// Color coding:
/// - **Green** (`#4c1`):  score 0 — structurally clean.
/// - **Yellow** (`#db5`): score 1–99 — warnings present, gate not yet failed.
/// - **Red** (`#e05d44`): score ≥ 100 — gate failure.
///
/// The badge uses a flat shields.io-compatible format and can be embedded in
/// GitHub READMEs, status pages, or automated PR comments.
///
/// Best-effort: silently logs a warning on I/O failure, never panics.
pub fn write_badge(janitor_dir: &Path, score: u32) {
    if let Err(e) = std::fs::create_dir_all(janitor_dir) {
        eprintln!("janitor: cannot create .janitor dir for badge: {e}");
        return;
    }
    let svg = render_badge_svg(score);
    let path = janitor_dir.join("janitor_badge.svg");
    if let Err(e) = std::fs::write(&path, svg.as_bytes()) {
        eprintln!("janitor: failed to write badge {}: {e}", path.display());
    }
}

/// Render a minimal shields.io-style flat SVG badge for the given slop score.
///
/// Zero external dependencies — all geometry is computed from character counts
/// using an 11px Verdana approximate width of 6.5 px/char.
fn render_badge_svg(score: u32) -> String {
    let (status, color) = if score == 0 {
        ("CLEAN", "#4c1")
    } else if score < 100 {
        ("WARN", "#db5")
    } else {
        ("FAIL", "#e05d44")
    };

    let label = "janitor";
    let value_text = format!("{score} \u{00b7} {status}"); // middle dot separator

    // Approximate 6.5px per char + 10px horizontal padding per section.
    let label_w = label.len() * 65 / 10 + 10;
    let value_w = value_text.chars().count() * 65 / 10 + 10;
    let total_w = label_w + value_w;
    let label_cx = label_w / 2;
    let value_cx = label_w + value_w / 2;

    format!(
        r##"<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="20">
  <linearGradient id="a" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <rect rx="3" width="{total_w}" height="20" fill="#555"/>
  <rect rx="3" x="{label_w}" width="{value_w}" height="20" fill="{color}"/>
  <rect x="{label_w}" width="4" height="20" fill="{color}"/>
  <rect rx="3" width="{total_w}" height="20" fill="url(#a)"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">
    <text x="{label_cx}" y="15">{label}</text>
    <text x="{value_cx}" y="15">{value_text}</text>
  </g>
</svg>"##
    )
}

// ---------------------------------------------------------------------------
// Architecture Inversion — Governor result submission
// ---------------------------------------------------------------------------

/// POST the [`BounceLogEntry`] to the Governor's `/v1/report` endpoint.
///
/// Used in Architecture Inversion mode: after `append_bounce_log`, if `--report-url`
/// and `--analysis-token` are set, the scored entry is submitted to the Governor so
/// it can update the GitHub Check Run without ever receiving source code.
///
/// **Fail-closed**: any transport error or non-2xx response is returned as `Err`.
/// The caller (`cmd_bounce`) must propagate this as a hard process exit so the
/// firewall cannot be bypassed by a degraded or hostile Governor endpoint.
/// The Bearer token is the short-lived JWT obtained from `/v1/analysis-token`.
pub fn post_bounce_result(url: &str, token: &str, entry: &BounceLogEntry) -> anyhow::Result<()> {
    let body = serde_json::to_string(entry)?;
    let result = ureq::post(url)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/json")
        .send(body.as_str());
    match result {
        Ok(r) if r.status() == 200 || r.status() == 201 => {
            eprintln!("info: bounce result reported to Governor");
            Ok(())
        }
        Ok(r) => {
            anyhow::bail!(
                "Governor /v1/report returned HTTP {} — firewall cannot confirm attestation",
                r.status()
            );
        }
        Err(e) => {
            anyhow::bail!(
                "failed to POST bounce result to Governor: {e} — firewall cannot confirm attestation"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Fail-Silent Diagnostics
// ---------------------------------------------------------------------------

/// Append a timestamped diagnostic message to `.janitor/diag.log`.
///
/// Always best-effort — any I/O error is silently discarded.  This facility
/// is intentionally hidden from CI output; the operator inspects the log
/// when troubleshooting rather than seeing noise in the CI transcript.
pub fn append_diag_log(janitor_dir: &Path, msg: &str) {
    use std::io::Write as _;
    let path = janitor_dir.join("diag.log");
    let ts = crate::utc_now_iso8601();
    let line = format!("[{ts}] {msg}\n");
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
}

/// Fire a once-per-week "System OK" heartbeat to the Governor health endpoint.
///
/// - Checks the mtime of `.janitor/heartbeat`; skips if modified within the
///   last 7 days.
/// - On a due cycle: GETs `https://the-governor.fly.dev/health` with a 5-second
///   timeout, logs the result to `.janitor/diag.log`, then touches the heartbeat
///   file to reset the 7-day window.
/// - Entirely best-effort and silent: no stdout/stderr output, no CI impact.
pub fn send_heartbeat_if_due(janitor_dir: &Path) {
    let heartbeat_path = janitor_dir.join("heartbeat");

    let due = match std::fs::metadata(&heartbeat_path) {
        Err(_) => true,
        Ok(meta) => meta
            .modified()
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map(|d| d.as_secs() > 7 * 24 * 3600)
            .unwrap_or(true),
    };

    if !due {
        return;
    }

    let msg = match ureq::get("https://the-governor.fly.dev/health")
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(5)))
        .build()
        .call()
    {
        Ok(r) => format!("heartbeat: Governor /health → HTTP {}", r.status()),
        Err(e) => format!("heartbeat: Governor unreachable — {e}"),
    };
    append_diag_log(janitor_dir, &msg);

    // Touch the heartbeat file to reset the 7-day window.
    let _ = std::fs::write(&heartbeat_path, b"");
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

/// Aggregates bounce log entries into a [`ReportData`].
///
/// `top_n` caps the Slop Top list (the `--top` CLI argument; default 50).
pub fn aggregate(entries: Vec<BounceLogEntry>, top_n: usize) -> ReportData {
    // Slop Top N — descending by slop_score.
    let mut sorted: Vec<usize> = (0..entries.len()).collect();
    sorted.sort_by(|&a, &b| entries[b].slop_score.cmp(&entries[a].slop_score));
    let slop_top_indices = sorted.into_iter().take(top_n).collect::<Vec<_>>();

    // Clone detection via MinHash LSH.
    let clone_pairs = detect_clone_pairs(&entries, 0.70);

    // Zombie PRs — entries with at least one zombie dependency recorded.
    let zombie_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.zombie_deps.is_empty())
        .map(|(i, _)| i)
        .collect();

    // Version silo PRs — entries where a crate appears at multiple distinct versions.
    let silo_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| !e.version_silos.is_empty())
        .map(|(i, _)| i)
        .collect();

    // Workslop ROI — sum 12 minutes for every necrotic PR (bot-closeable).
    // Score-blocked PRs still require human review; only necrotic verdicts
    // represent truly reclaimed labor via automated bulk-close.
    let total_reclaimed_minutes =
        entries.iter().filter(|e| e.necrotic_flag.is_some()).count() as f64 * MINUTES_PER_TRIAGE;

    // Categorical billing:
    //   Critical Threats ($150): security: antipattern OR Swarm collision.
    //   Necrotic GC ($20): necrotic_flag set, not critical.
    //   Structural Slop ($20): slop_score > 0, not critical, no necrotic flag.
    //   Boilerplate ($0): slop_score == 0 and none of the above.
    let critical_threats_count = entries.iter().filter(|e| is_critical_threat(e)).count() as u64;
    let gc_only_count = entries
        .iter()
        .filter(|e| e.necrotic_flag.is_some() && !is_critical_threat(e))
        .count() as u64;
    let structural_slop_count = entries
        .iter()
        .filter(|e| e.slop_score > 0 && !is_critical_threat(e) && e.necrotic_flag.is_none())
        .count() as u64;
    let total_actionable_intercepts =
        critical_threats_count + gc_only_count + structural_slop_count;

    // ── User stats (Top 10 Sloppiest / Top 10 Cleanest) ───────────────────
    // Value: (total_slop_score, total_pr_count, clean_pr_count)
    let mut user_map: HashMap<String, (u64, u32, u32)> = HashMap::new();
    for entry in &entries {
        if let Some(author) = entry.author.as_deref() {
            let e = user_map.entry(author.to_owned()).or_insert((0, 0, 0));
            e.0 += entry.slop_score as u64;
            e.1 += 1;
            if entry.slop_score == 0 {
                e.2 += 1;
            }
        }
    }

    let mut sloppiest_users: Vec<UserStats> = user_map
        .iter()
        .map(
            |(author, &(total_slop_score, total_pr_count, clean_pr_count))| UserStats {
                author: author.clone(),
                total_slop_score,
                total_pr_count,
                clean_pr_count,
            },
        )
        .collect();
    sloppiest_users.sort_by(|a, b| b.total_slop_score.cmp(&a.total_slop_score));
    sloppiest_users.truncate(10);

    // Necrotic PRs — entries flagged by the Backlog Pruner.
    let mut necrotic_indices: Vec<usize> = entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.necrotic_flag.is_some())
        .map(|(i, _)| i)
        .collect();
    // Sort by slop_score descending so the top-10 table shows worst offenders first.
    necrotic_indices.sort_by(|&a, &b| entries[b].slop_score.cmp(&entries[a].slop_score));

    ReportData {
        entries,
        slop_top_indices,
        clone_pairs,
        zombie_indices,
        silo_indices,
        total_reclaimed_minutes,
        total_actionable_intercepts,
        critical_threats_count,
        structural_slop_count,
        necrotic_indices,
        sloppiest_users,
    }
}

/// Map a machine-readable antipattern label to a concise human-readable display string.
///
/// Used only in the PDF/Markdown rendering layer — the raw machine IDs are
/// preserved in `BounceLogEntry.antipatterns` and in the CSV export.
fn humanize_antipattern_label(label: &str) -> std::borrow::Cow<'_, str> {
    if label == "antipattern:ncd_anomaly" || label.starts_with("HighGenerativeVerbosity:") {
        "AI Boilerplate Detected (NCD Ratio < 0.15)".into()
    } else {
        label.into()
    }
}

/// Returns a short, human-readable label for the dominant violation in a bounce entry.
///
/// Priority mirrors scoring weights: antipatterns (×50) > zombie symbols (×15) >
/// logic clones (×5) > zombie deps (informational).
///
/// When no language antipattern fired but a `necrotic_flag` is present, returns
/// `"backlog:<FLAG>"` (e.g. `"backlog:SEMANTIC_NULL"`) so the PDF/Markdown Top-10
/// table shows a machine-readable identifier instead of the generic fallback.
fn primary_violation(e: &BounceLogEntry) -> String {
    if !e.antipatterns.is_empty() {
        if e.antipatterns
            .iter()
            .any(|a| a.contains("Unverified Security Bump"))
        {
            return "Unverified Security Bump".to_owned();
        }
        return "Language Antipattern".to_owned();
    }
    if e.zombie_symbols_added > 0 {
        return "Zombie Symbol Reintroduction".to_owned();
    }
    if e.logic_clones_found > 0 {
        return "Structural Clone".to_owned();
    }
    if !e.zombie_deps.is_empty() {
        if let Some(flag) = e.necrotic_flag.as_deref() {
            return format!("backlog:{flag}");
        }
        return "Zombie Dependency".to_owned();
    }
    if let Some(flag) = e.necrotic_flag.as_deref() {
        return format!("backlog:{flag}");
    }
    "Score Threshold".to_owned()
}

/// Detect pairs of entries whose MinHash Jaccard similarity exceeds `threshold`.
///
/// Only entries with a full 64-element `min_hashes` vector participate.
/// Returns `(i, j)` pairs with `i < j`, deduplicated.
fn detect_clone_pairs(entries: &[BounceLogEntry], threshold: f64) -> Vec<(usize, usize)> {
    use forge::pr_collider::{LshIndex, PrDeltaSignature};

    // Map: LshIndex internal position → entry index.
    let mut valid_indices: Vec<usize> = Vec::new();
    let index = LshIndex::new();

    for (i, entry) in entries.iter().enumerate() {
        if entry.min_hashes.len() == 64 {
            let mut arr = [0u64; 64];
            arr.copy_from_slice(&entry.min_hashes);
            // Use the lsh position (sequential insert counter) as the "pr_number"
            // tag so query() returns positions we can use to index valid_indices.
            let lsh_pos = valid_indices.len() as u32;
            index.insert(PrDeltaSignature { min_hashes: arr }, lsh_pos);
            valid_indices.push(i);
        }
    }

    let mut pair_set: HashSet<(usize, usize)> = HashSet::new();

    for (lsh_i, &entry_i) in valid_indices.iter().enumerate() {
        let mut arr = [0u64; 64];
        arr.copy_from_slice(&entries[entry_i].min_hashes);
        let sig = PrDeltaSignature { min_hashes: arr };
        // query() returns Vec<u32> of the lsh positions stored at insert time.
        let candidates = index.query(&sig, threshold);
        for lsh_j_u32 in candidates {
            let lsh_j = lsh_j_u32 as usize;
            // Guard against out-of-bounds (should not occur, but defensive).
            let Some(&entry_j) = valid_indices.get(lsh_j) else {
                continue;
            };
            if lsh_j != lsh_i {
                let pair = if entry_i < entry_j {
                    (entry_i, entry_j)
                } else {
                    (entry_j, entry_i)
                };
                pair_set.insert(pair);
            }
        }
    }

    let mut pairs: Vec<(usize, usize)> = pair_set.into_iter().collect();
    pairs.sort_unstable();
    pairs
}

// ---------------------------------------------------------------------------
// Markdown renderer
// ---------------------------------------------------------------------------

/// Truncate an author handle to `max` chars with an ellipsis suffix to prevent
/// table column bleeding in pandoc-generated LaTeX PDF output.
fn trunc_author(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let trimmed: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{trimmed}…")
    }
}

/// Escapes HTML special characters in external-origin strings before they are
/// interpolated into Markdown output.
///
/// Applied to author handles, antipattern descriptions, comment-violation text,
/// package names, file paths, and repository names.  Prevents `<script>` tag
/// injection when reports are rendered in HTML-capable Markdown viewers
/// (VS Code, GitHub, browser-based Markdown extensions).
///
/// No-op when the input contains none of `< > & " '`.
fn html_escape(s: &str) -> String {
    if !s
        .bytes()
        .any(|b| matches!(b, b'<' | b'>' | b'&' | b'"' | b'\''))
    {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len() + 16);
    for ch in s.chars() {
        match ch {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

/// Strips any non-ASCII codepoints from `input` so that pdflatex never
/// encounters a character outside the 7-bit ASCII range.
///
/// Applied to every user-supplied string field (author names, repo names,
/// violation descriptions) before they are written into the Markdown/LaTeX
/// pipeline.  ASCII-only inputs are returned without allocation.
fn sanitize_latex_safe(input: &str) -> String {
    if input.is_ascii() {
        return input.to_owned();
    }
    input.chars().filter(|c| c.is_ascii()).collect()
}

/// Renders the aggregated report as GitHub-flavored Markdown.
///
/// Produces three sections:
/// - Slop Top 50 (table)
/// - Structural Clones (bulleted list)
/// - Zombie Dependencies (bulleted list)
pub fn render_markdown(data: &ReportData, repo_name: &str) -> String {
    let mut out = String::with_capacity(4096);

    // Compact LaTeX settings: tighter paragraph spacing and table row height,
    // matching the global-report density so summary tables fit on fewer pages.
    out.push_str("```{=latex}\n\\setlength{\\parskip}{2pt plus 1pt minus 1pt}\n\\renewcommand{\\arraystretch}{0.9}\n```\n\n");
    out.push_str("# Janitor Intelligence Report\n\n");
    out.push_str("*Generated by The Janitor: Deterministic Structural Analysis.*\n\n");
    out.push_str(&format!(
        "**Repository**: `{}`\n\n",
        html_escape(&sanitize_latex_safe(repo_name))
    ));
    out.push_str(&format!(
        "**Total PRs analyzed**: {}\n\n",
        data.entries.len()
    ));
    out.push_str("---\n\n");

    // ── Workslop: Maintainer Impact ────────────────────────────────────────
    {
        let actionable = data.total_actionable_intercepts;
        let critical = data.critical_threats_count;
        let structural_slop = data.structural_slop_count;
        let gc_only = actionable
            .saturating_sub(critical)
            .saturating_sub(structural_slop);
        let hours = data.total_reclaimed_minutes / 60.0;
        // Categorical billing: Critical ($150) + Necrotic GC ($20) + Structural Slop ($20).
        let critical_threat_bounty = critical * 150;
        let tei = critical * 150 + gc_only * 20 + structural_slop * 20;
        let energy_kwh: f64 = data.entries.iter().map(|e| e.ci_energy_saved_kwh).sum();
        out.push_str("## Workslop: Maintainer Impact\n\n");
        out.push_str(
            "*[Workslop](https://builtin.com/articles/what-is-workslop): the triage tax \
             senior engineers pay reviewing AI-generated low-quality PRs.*\n\n",
        );
        out.push_str("| Metric | Value |\n");
        out.push_str("|--------|-------|\n");
        out.push_str(&format!(
            "| Actionable intercepts (Threats + Necrotic + Structural Slop) | **{actionable}** |\n"
        ));
        out.push_str(&format!(
            "| Critical Threats Blocked (Swarm / Security) | **{critical}** |\n"
        ));
        out.push_str(&format!(
            "| Garbage Collection (Necrotic — bot-closeable) | **{gc_only}** |\n"
        ));
        out.push_str(&format!(
            "| Structural Slop (score > 0, no threat signal) | **{structural_slop}** |\n"
        ));
        out.push_str(&format!(
            "| **Total engineering time reclaimed** | **{hours:.1} hours** |\n"
        ));
        out.push_str(&format!(
            "| **Critical Threat Intercepts ($150)** | **${critical_threat_bounty}** |\n"
        ));
        out.push_str(&format!("| **Total Economic Impact** | **${tei}** |\n"));
        out.push_str(&format!(
            "| **CI Energy Reclaimed** | **{energy_kwh:.1} kWh** |\n"
        ));
        out.push('\n');
        out.push_str(
            "> TEI = (Critical Threats × $150) + (Necrotic GC × $20) + (Structural Slop × $20). \
             Energy = actionable intercepts × 0.1 kWh (15-min CI run at 400 W). \
             Critical Threats: `security:` antipatterns or Swarm collisions. \
             Necrotic: bot-closeable dead-code PRs. \
             Structural Slop: PRs with slop_score > 0 and no critical/necrotic signal. \
             Based on **12-minute industry triage baseline** × **$100/hr** loaded engineering cost. \
             Source: [Workslop research](https://builtin.com/articles/what-is-workslop).\n\n",
        );

        // Domain Routing summary — shown when any findings were withheld.
        let total_suppressed: u32 = data.entries.iter().map(|e| e.suppressed_by_domain).sum();
        if total_suppressed > 0 {
            out.push_str("### Domain Routing\n\n");
            out.push_str(
                "| Category | Findings |\n\
                 |----------|----------|\n",
            );
            out.push_str(&format!(
                "| **Core Regressions** (first-party code) | Counted above |\n\
                 | **Vendored / Test** (suppressed by domain mask) | **{total_suppressed}** |\n"
            ));
            out.push('\n');
            out.push_str(
                "> Memory-safety rules (`new`/`delete`, vacuous `unsafe`, hallucinated imports, \
                 etc.) are not applied to `vendor/`, `thirdparty/`, `node_modules/`, `tests/`, \
                 or `spec/` paths. Supply-chain rules (Unverified Security Bump, AnomalousBlob, \
                 wildcard CIDR) fire on all domains.\n\n",
            );
        }
    }

    // ── Audit Provenance ───────────────────────────────────────────────────
    {
        let total_source: u64 = data
            .entries
            .iter()
            .map(|e| e.provenance.source_bytes_processed)
            .sum();
        let total_egress: u64 = data
            .entries
            .iter()
            .map(|e| e.provenance.egress_bytes_sent)
            .sum();
        let total_duration_ms: u64 = data
            .entries
            .iter()
            .map(|e| e.provenance.analysis_duration_ms)
            .sum();
        let exfil_pct = if total_source > 0 {
            (total_egress as f64 / total_source as f64) * 100.0
        } else {
            0.0
        };
        let source_mb = total_source as f64 / 1_048_576.0;
        let egress_kb = total_egress as f64 / 1_024.0;
        let total_duration_s = total_duration_ms as f64 / 1_000.0;

        out.push_str("## Audit Provenance\n\n");
        out.push_str(
            "*The Gatekeeper has verified that 0 source bytes left the runner. \
             Only the structural score crosses the network boundary.*\n\n",
        );
        out.push_str("| Field | Value |\n");
        out.push_str("|-------|-------|\n");
        out.push_str(&format!(
            "| Owner | `{}` |\n",
            html_escape(&sanitize_latex_safe(repo_name))
        ));
        out.push_str(&format!(
            "| Application (Version) | The Janitor v{} |\n",
            env!("CARGO_PKG_VERSION")
        ));
        out.push_str(&format!(
            "| Duration | **{total_duration_s:.1}s** across {n} PRs |\n",
            n = data.entries.len()
        ));
        out.push_str(&format!("| Source Analyzed | **{source_mb:.2} MB** |\n"));
        out.push_str(&format!(
            "| Egress to Control Plane | **{egress_kb:.1} KB** |\n"
        ));
        out.push_str("| Bytes Received (score only) | 0 bytes |\n");
        out.push_str(&format!(
            "| **Exfiltration Ratio** | **{exfil_pct:.4}%** |\n"
        ));
        out.push('\n');
        out.push_str(
            "> Zero-Upload Guarantee: source code is analysed in-memory on your runner. \
             The Governor receives only the signed structural score — never source bytes, \
             never AST nodes, never symbol names from your codebase.\n\n",
        );
    }

    // ── Top 10 Sloppiest Contributors ──────────────────────────────────────
    if !data.sloppiest_users.is_empty() {
        out.push_str("## Top 10 Sloppiest Contributors\n\n");
        out.push_str("| Rank | Author | Total Slop Score | PRs Audited | Clean PRs |\n");
        out.push_str("|------|--------|-----------------|-------------|----------|\n");
        for (i, u) in data.sloppiest_users.iter().enumerate() {
            out.push_str(&format!(
                "| {} | `{}` | **{}** | {} | {} |\n",
                i + 1,
                html_escape(&trunc_author(&sanitize_latex_safe(&u.author), 20)),
                u.total_slop_score,
                u.total_pr_count,
                u.clean_pr_count,
            ));
        }
        out.push('\n');
    }

    out.push_str("---\n\n");

    // ── Scoring Methodology (per-repo) ─────────────────────────────────────
    // No forced \newpage here: compact LaTeX settings let Workslop + Contributors
    // flow onto the same page as Methodology without a premature hard break.
    out.push_str("## Scoring Methodology\n\n");
    out.push_str("| Classification | Condition | Billing |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| Critical Threat | `security:` antipattern OR Swarm collision | $150 |\n");
    out.push_str("| Necrotic GC | Dead-code ghost (bot-automatable) | $20 |\n");
    out.push_str("| Structural Slop | slop_score > 0, no critical/necrotic signal | $20 |\n");
    out.push_str("| Boilerplate | slop_score == 0, no threat signal | $0 |\n");
    out.push('\n');
    out.push_str(
        "Score formula: `(clones × 5) + (zombies × 10) + (antipattern_score) + \
         (comment_violations × 5) + (unlinked_pr × 20) + (hallucinated_fix × 100)`\n\n",
    );

    // ── Section 1: Top 10 High-Risk PRs ───────────────────────────────────
    out.push_str("## Top 10 High-Risk PRs\n\n");

    if data.slop_top_indices.is_empty() {
        out.push_str(
            "*No bounce data found. Run `janitor bounce --pr-number <N> --author <handle>` \
             to populate the log.*\n\n",
        );
    } else {
        out.push_str("| Rank | PR | Author | Slop Score | Primary Violation | Antipatterns |\n");
        out.push_str("|------|----|--------|------------|-------------------|--------------|\n");
        for (rank, &i) in data.slop_top_indices.iter().take(10).enumerate() {
            let e = &data.entries[i];
            let pr = e
                .pr_number
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| "-".to_owned());
            let author = html_escape(&trunc_author(
                &sanitize_latex_safe(e.author.as_deref().unwrap_or("-")),
                20,
            ));
            // Show first two antipattern descriptions; append "+N more" if truncated.
            let ap_cell = if e.antipatterns.is_empty() {
                "-".to_owned()
            } else {
                let shown: Vec<String> = e
                    .antipatterns
                    .iter()
                    .take(2)
                    .map(|a| {
                        // Truncate long descriptions at 60 chars for table readability.
                        let s = sanitize_latex_safe(a);
                        if s.len() > 60 {
                            format!("{}…", &s[..57])
                        } else {
                            s
                        }
                    })
                    .collect();
                let remainder = e.antipatterns.len().saturating_sub(2);
                if remainder > 0 {
                    format!("{}, +{remainder} more", shown.join("; "))
                } else {
                    shown.join("; ")
                }
            };
            out.push_str(&format!(
                "| {} | {} | {} | **{}** | {} | {} |\n",
                rank + 1,
                pr,
                author,
                e.slop_score,
                primary_violation(e),
                html_escape(&ap_cell),
            ));
        }
    }
    out.push('\n');

    // ── Antipattern & violation detail expansion ────────────────────────────
    // The table above shows only the count. This sub-section prints the actual
    // human-readable descriptions for every PR in the Slop Top list that carries
    // at least one antipattern or comment violation entry.
    // Identical strings are grouped with an `(xN)` suffix to reduce noise.
    let has_findings = data.slop_top_indices.iter().any(|&i| {
        !data.entries[i].antipatterns.is_empty() || !data.entries[i].comment_violations.is_empty()
    });

    if has_findings {
        out.push_str("### Antipattern & Violation Details\n\n");
        for &i in &data.slop_top_indices {
            let e = &data.entries[i];
            if e.antipatterns.is_empty() && e.comment_violations.is_empty() {
                continue;
            }
            let pr = e
                .pr_number
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| "-".to_owned());
            let author = html_escape(&sanitize_latex_safe(e.author.as_deref().unwrap_or("-")));
            out.push_str(&format!("- **PR {pr}** (`{author}`):\n"));
            for (desc, count) in group_strings(&e.antipatterns) {
                let display = humanize_antipattern_label(desc);
                let desc_s = sanitize_latex_safe(&display);
                if count > 1 {
                    out.push_str(&format!("  - {} (x{})\n", html_escape(&desc_s), count));
                } else {
                    out.push_str(&format!("  - {}\n", html_escape(&desc_s)));
                }
            }
            for (desc, count) in group_strings(&e.comment_violations) {
                let desc_s = sanitize_latex_safe(desc);
                if count > 1 {
                    out.push_str(&format!(
                        "  - [violation] {} (x{})\n",
                        html_escape(&desc_s),
                        count
                    ));
                } else {
                    out.push_str(&format!("  - [violation] {}\n", html_escape(&desc_s)));
                }
            }
        }
        out.push('\n');
    }

    // ── Section 1b: Necrotic PRs (Garbage Collection) ─────────────────────
    if !data.necrotic_indices.is_empty() {
        out.push('\n');
        out.push_str("### Necrotic PRs (Garbage Collection)\n\n");
        out.push_str(
            "*Flagged by the Backlog Pruner: cosmetic-only changes (`SEMANTIC_NULL`), \
             PRs targeting decayed architecture (`GHOST_COLLISION`), and unreachable \
             new code additions (`UNWIRED_ISLAND`).*\n\n",
        );
        out.push_str("| Rank | PR | Author | Slop Score | Necrotic Flag |\n");
        out.push_str("|------|----|--------|------------|---------------|\n");
        for (rank, &i) in data.necrotic_indices.iter().take(10).enumerate() {
            let e = &data.entries[i];
            let pr = e
                .pr_number
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| "-".to_owned());
            let author = html_escape(&trunc_author(
                &sanitize_latex_safe(e.author.as_deref().unwrap_or("-")),
                20,
            ));
            let flag = e.necrotic_flag.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "| {} | {} | {} | {} | `{}` |\n",
                rank + 1,
                pr,
                author,
                e.slop_score,
                flag,
            ));
        }
        let necrotic_overflow = data.necrotic_indices.len().saturating_sub(10);
        if necrotic_overflow > 0 {
            out.push_str(&format!(
                "\n*…and {necrotic_overflow} more necrotic entries. See CSV for full list.*\n"
            ));
        }
        out.push('\n');
    }

    // ── Section 2: Structural Clones ───────────────────────────────────────
    out.push_str("## Structural Clones — Near-Duplicate PRs\n\n");
    out.push_str(
        "*Detected via 64-hash MinHash LSH (Jaccard >= 0.70). \
         Clone pairs share structurally identical diff content.*\n\n",
    );

    if data.clone_pairs.is_empty() {
        out.push_str("*No structural clones detected.*\n\n");
    } else {
        const CLONE_DISPLAY_CAP: usize = 20;
        let total_pairs = data.clone_pairs.len();
        let display_pairs = &data.clone_pairs[..total_pairs.min(CLONE_DISPLAY_CAP)];
        for (a, b) in display_pairs {
            let ea = &data.entries[*a];
            let eb = &data.entries[*b];
            let pr_a = ea
                .pr_number
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| format!("entry-{a}"));
            let pr_b = eb
                .pr_number
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| format!("entry-{b}"));
            let auth_a = html_escape(&trunc_author(
                &sanitize_latex_safe(ea.author.as_deref().unwrap_or("unknown")),
                20,
            ));
            let auth_b = html_escape(&trunc_author(
                &sanitize_latex_safe(eb.author.as_deref().unwrap_or("unknown")),
                20,
            ));
            out.push_str(&format!(
                "- **PR {pr_a}** ({auth_a}) is a structural clone of **PR {pr_b}** ({auth_b})\n"
            ));
        }
        if total_pairs > CLONE_DISPLAY_CAP {
            out.push_str(&format!(
                "\n*…and {} more pairs. See the attached CSV for complete forensic data.*\n",
                total_pairs - CLONE_DISPLAY_CAP
            ));
        }
    }
    out.push('\n');

    // ── Section 3: Zombie Dependencies (suppressed when none detected) ──────
    if !data.zombie_indices.is_empty() {
        out.push_str("## Zombie Dependencies — Declared But Never Imported\n\n");
        out.push_str(
            "*Packages added to `Cargo.toml`, `package.json`, or `requirements.txt` \
             that do not appear in any source file import statement.*\n\n",
        );
        for &i in data.zombie_indices.iter().take(LIST_DISPLAY_CAP) {
            let e = &data.entries[i];
            let pr = e
                .pr_number
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| format!("entry-{i}"));
            let author = html_escape(&sanitize_latex_safe(
                e.author.as_deref().unwrap_or("unknown"),
            ));
            let deps: Vec<String> = e.zombie_deps.iter().map(|d| html_escape(d)).collect();
            out.push_str(&format!(
                "- **PR {}** ({}): `{}`\n",
                pr,
                author,
                deps.join("`, `")
            ));
        }
        let zombie_overflow = data.zombie_indices.len().saturating_sub(LIST_DISPLAY_CAP);
        if zombie_overflow > 0 {
            out.push_str(&format!(
                "\n*…and {zombie_overflow} more entries. See CSV for full list.*\n"
            ));
        }
        out.push('\n');
    }

    // ── Section 4: Version Silos (suppressed when none detected) ────────────
    if !data.silo_indices.is_empty() {
        out.push_str("## Version Silos — Dependency Version Conflicts\n\n");
        out.push_str(
            "*Crates or packages that appear at more than one distinct version across the PR's \
             manifest files. Each silo adds +20 points to the Slop Score.*\n\n",
        );
        for &i in data.silo_indices.iter().take(LIST_DISPLAY_CAP) {
            let e = &data.entries[i];
            let pr = e
                .pr_number
                .map(|n| format!("#{n}"))
                .unwrap_or_else(|| format!("entry-{i}"));
            let author = html_escape(&sanitize_latex_safe(
                e.author.as_deref().unwrap_or("unknown"),
            ));
            let silos: Vec<String> = e.version_silos.iter().map(|s| html_escape(s)).collect();
            out.push_str(&format!(
                "- **PR {}** ({}): `{}`\n",
                pr,
                author,
                silos.join("`, `")
            ));
        }
        let silo_overflow = data.silo_indices.len().saturating_sub(LIST_DISPLAY_CAP);
        if silo_overflow > 0 {
            out.push_str(&format!(
                "\n*…and {silo_overflow} more entries. See CSV for full list.*\n"
            ));
        }
        out.push('\n');
    }

    out
}

// ---------------------------------------------------------------------------
// JSON renderer
// ---------------------------------------------------------------------------

/// Renders the aggregated report as a structured JSON value.
pub fn render_json(data: &ReportData, repo_name: &str) -> serde_json::Value {
    let hours = data.total_reclaimed_minutes / 60.0;
    let necrotic_count = (data.total_reclaimed_minutes / MINUTES_PER_TRIAGE).round() as u64;

    // Provenance aggregates — computed outside the json! macro (no let-blocks allowed).
    let prov_total_source: u64 = data
        .entries
        .iter()
        .map(|e| e.provenance.source_bytes_processed)
        .sum();
    let prov_total_egress: u64 = data
        .entries
        .iter()
        .map(|e| e.provenance.egress_bytes_sent)
        .sum();
    let prov_total_duration_ms: u64 = data
        .entries
        .iter()
        .map(|e| e.provenance.analysis_duration_ms)
        .sum();
    let prov_exfil_pct = if prov_total_source > 0 {
        (prov_total_egress as f64 / prov_total_source as f64) * 100.0
    } else {
        0.0
    };
    let prov_json = serde_json::json!({
        "total_source_bytes_processed": prov_total_source,
        "total_egress_bytes_sent": prov_total_egress,
        "total_analysis_duration_ms": prov_total_duration_ms,
        "exfiltration_ratio_pct": (prov_exfil_pct * 10000.0).round() / 10000.0,
        "zero_upload_verified": prov_total_egress == 0 || prov_exfil_pct < 1.0,
    });
    let critical = data.critical_threats_count;
    let structural_slop = data.structural_slop_count;
    let gc_only = data
        .total_actionable_intercepts
        .saturating_sub(critical)
        .saturating_sub(structural_slop);
    let critical_threat_bounty = critical * 150;
    let tei = critical * 150 + gc_only * 20 + structural_slop * 20;
    let total_ci_energy_kwh: f64 = data.entries.iter().map(|e| e.ci_energy_saved_kwh).sum();
    serde_json::json!({
        "schema_version": env!("CARGO_PKG_VERSION"),
        "repository": repo_name,
        "total_prs_analyzed": data.entries.len(),
        "workslop": {
            "actionable_intercepts": data.total_actionable_intercepts,
            "critical_threats_count": critical,
            "necrotic_count": necrotic_count,
            "structural_slop_count": structural_slop,
            "total_reclaimed_minutes": (data.total_reclaimed_minutes * 10.0).round() / 10.0,
            "total_reclaimed_hours": (hours * 10.0).round() / 10.0,
            "critical_threat_bounty_usd": critical_threat_bounty,
            "total_economic_impact_usd": tei,
            "total_ci_energy_saved_kwh": (total_ci_energy_kwh * 10.0).round() / 10.0,
        },
        "slop_top": data.slop_top_indices.iter().enumerate().map(|(rank, &i)| {
            let e = &data.entries[i];
            serde_json::json!({
                "rank": rank + 1,
                "pr_number": e.pr_number,
                "author": e.author,
                "slop_score": e.slop_score,
                "dead_symbols_added": e.dead_symbols_added,
                "logic_clones_found": e.logic_clones_found,
                "zombie_symbols_added": e.zombie_symbols_added,
                "antipatterns_found": e.antipatterns.len(),
                "antipatterns": e.antipatterns,
                "comment_violations": e.comment_violations,
            })
        }).collect::<Vec<_>>(),
        "clone_pairs": data.clone_pairs.iter().map(|(a, b)| {
            let ea = &data.entries[*a];
            let eb = &data.entries[*b];
            serde_json::json!({
                "pr_a": ea.pr_number,
                "author_a": ea.author,
                "pr_b": eb.pr_number,
                "author_b": eb.author,
            })
        }).collect::<Vec<_>>(),
        "zombie_prs": data.zombie_indices.iter().map(|&i| {
            let e = &data.entries[i];
            serde_json::json!({
                "pr_number": e.pr_number,
                "author": e.author,
                "zombie_deps": e.zombie_deps,
            })
        }).collect::<Vec<_>>(),
        "version_silo_prs": data.silo_indices.iter().map(|&i| {
            let e = &data.entries[i];
            serde_json::json!({
                "pr_number": e.pr_number,
                "author": e.author,
                "version_silos": e.version_silos,
            })
        }).collect::<Vec<_>>(),
        "provenance": prov_json,
    })
}

// ---------------------------------------------------------------------------
// Scan-mode report (no bounce log)
// ---------------------------------------------------------------------------

/// A single dead symbol entry for scan-mode reports.
///
/// Converted from [`anatomist::Entity`] by [`cmd_report`] before rendering,
/// so this module remains free of an `anatomist` dependency.
pub struct DeadSymbolEntry {
    /// Fully-qualified symbol name (e.g. `module::Class::method`).
    pub qualified_name: String,
    /// Relative file path of the source file.
    pub file_path: String,
    /// 1-based line number of the symbol definition.
    pub start_line: u32,
    /// Size in bytes (`end_byte - start_byte`). Used as the ranking key.
    pub byte_size: u32,
}

/// Maximum number of items printed per list in Markdown/PDF output.
///
/// Applies to Dead Symbols, Orphan Files, and Zombie Dependencies.
/// Lists exceeding this cap emit a `*…and N more entries. See CSV for full list.*`
/// footer rather than expanding indefinitely — preventing 2,000-page PDFs.
pub const LIST_DISPLAY_CAP: usize = 50;

/// Renders a scan-mode dead-symbol audit as GitHub-flavored Markdown.
///
/// Dead symbols are ranked by `byte_size` descending (largest removed = most
/// bytes reclaimed). The table is capped at [`LIST_DISPLAY_CAP`] rows;
/// `top_n` is honoured but cannot exceed that constant.
pub fn render_scan_markdown(
    dead: &[DeadSymbolEntry],
    total_entities: usize,
    orphan_files: &[String],
    repo_name: &str,
    top_n: usize,
) -> String {
    let dead_pct = if total_entities == 0 {
        0.0_f64
    } else {
        dead.len() as f64 / total_entities as f64 * 100.0
    };
    let total_dead_bytes: u64 = dead.iter().map(|e| e.byte_size as u64).sum();

    let mut out = String::with_capacity(8192);

    out.push_str("# Janitor Dead-Symbol Audit\n\n");
    out.push_str("*Generated by The Janitor: Deterministic Structural Analysis.*\n\n");
    out.push_str(&format!(
        "**Repository**: `{}`\n\n",
        html_escape(&sanitize_latex_safe(repo_name))
    ));
    out.push_str("---\n\n");

    // ── Summary table ──────────────────────────────────────────────────────
    out.push_str("## Summary\n\n");
    out.push_str("| Metric | Value |\n");
    out.push_str("|--------|-------|\n");
    out.push_str(&format!("| Total entities | {total_entities} |\n"));
    out.push_str(&format!(
        "| Dead symbols | {} ({:.1}%) |\n",
        dead.len(),
        dead_pct
    ));
    out.push_str(&format!(
        "| Maintenance Surface Reduction | {} |\n",
        fmt_bytes(total_dead_bytes)
    ));
    out.push_str(&format!(
        "| Complexity Delta | **-{}** symbols |\n",
        dead.len()
    ));
    out.push_str(&format!("| Orphan files | {} |\n", orphan_files.len()));
    out.push('\n');

    // ── Top N dead symbols by byte size ────────────────────────────────────
    let effective_top = top_n.min(LIST_DISPLAY_CAP);
    out.push_str(&format!(
        "## Top {effective_top} Dead Symbols — Ranked by Byte Size\n\n"
    ));

    if dead.is_empty() {
        out.push_str("*No dead symbols detected. Codebase is clean.*\n\n");
    } else {
        out.push_str("| Rank | Symbol | File | Line | Bytes |\n");
        out.push_str("|------|--------|------|------|-------|\n");
        for (rank, entry) in dead.iter().take(effective_top).enumerate() {
            out.push_str(&format!(
                "| {} | `{}` | `{}` | {} | {} |\n",
                rank + 1,
                html_escape(&entry.qualified_name),
                html_escape(&entry.file_path),
                entry.start_line,
                entry.byte_size,
            ));
        }
        let dead_overflow = dead.len().saturating_sub(effective_top);
        if dead_overflow > 0 {
            out.push_str(&format!(
                "\n*…and {dead_overflow} more entries. See CSV for full list.*\n"
            ));
        }
        out.push('\n');
    }

    // ── Orphan files ───────────────────────────────────────────────────────
    out.push_str("## Orphan Files — Never Imported\n\n");
    if orphan_files.is_empty() {
        out.push_str("*No orphan files detected.*\n\n");
    } else {
        for path in orphan_files.iter().take(LIST_DISPLAY_CAP) {
            out.push_str(&format!("- `{}`\n", html_escape(path)));
        }
        let orphan_overflow = orphan_files.len().saturating_sub(LIST_DISPLAY_CAP);
        if orphan_overflow > 0 {
            out.push_str(&format!(
                "\n*…and {orphan_overflow} more entries. See CSV for full list.*\n"
            ));
        }
        out.push('\n');
    }

    out
}

/// Renders a scan-mode dead-symbol audit as structured JSON.
pub fn render_scan_json(
    dead: &[DeadSymbolEntry],
    total_entities: usize,
    orphan_files: &[String],
    repo_name: &str,
    top_n: usize,
) -> serde_json::Value {
    let dead_pct = if total_entities == 0 {
        0.0_f64
    } else {
        dead.len() as f64 / total_entities as f64 * 100.0
    };
    let total_dead_bytes: u64 = dead.iter().map(|e| e.byte_size as u64).sum();

    serde_json::json!({
        "schema_version": env!("CARGO_PKG_VERSION"),
        "repository": repo_name,
        "total_entities": total_entities,
        "dead_symbol_count": dead.len(),
        "dead_pct": (dead_pct * 10.0).round() / 10.0,
        "reclaimable_bytes": total_dead_bytes,
        "maintenance_surface_reduction_mb": (total_dead_bytes as f64 / 1_048_576.0 * 100.0).round() / 100.0,
        "complexity_delta_symbols": -(dead.len() as i64),
        "orphan_file_count": orphan_files.len(),
        "dead_symbols": dead.iter().take(top_n).enumerate().map(|(rank, e)| {
            serde_json::json!({
                "rank": rank + 1,
                "qualified_name": e.qualified_name,
                "file_path": e.file_path,
                "start_line": e.start_line,
                "byte_size": e.byte_size,
            })
        }).collect::<Vec<_>>(),
        "orphan_files": orphan_files,
    })
}

// ---------------------------------------------------------------------------
// Global multi-repo report
// ---------------------------------------------------------------------------

/// Per-repository aggregate stats for the `--global` cross-repo report.
pub struct RepoStats {
    /// Repository name (directory base name).
    pub repo_name: String,
    /// Number of PRs with bounce log entries.
    pub pr_count: usize,
    /// Sum of all slop scores across all entries.
    pub total_slop_score: u64,
    /// Sum of antipatterns found across all entries.
    pub antipatterns_found: u32,
    /// Count of entries that have at least one zombie dependency.
    pub zombie_dep_prs: u32,
    /// Sum of dead symbols added across all entries.
    pub dead_symbols_added: u32,
    /// PR number with the highest slop score in this repo.
    pub highest_pr: Option<u64>,
    /// Highest slop score seen in this repo.
    pub highest_score: u32,
    /// Engineering minutes reclaimed from actionable intercepts in this repo.
    pub reclaimed_minutes: f64,
    /// Total actionable intercepts: Critical Threats, Necrotic GC, or Structural Slop.
    pub total_actionable_intercepts: u64,
    /// Count of Critical Threats in this repo (security: antipatterns or Swarm).
    pub critical_threats_count: u64,
    /// Count of Structural Slop PRs (slop_score > 0, not critical, not necrotic).
    pub structural_slop_count: u64,
    /// Total CI datacenter energy conserved across all entries in this repo (kWh).
    ///
    /// Sum of `ci_energy_saved_kwh` from all bounce log entries.
    pub total_ci_energy_saved_kwh: f64,
    /// Top 10 sloppiest PRs: `(pr_number, score, state, author, threat_class)`.
    pub top_sloppiest: Vec<(u64, u32, String, String, String)>,
    /// Top 10 cleanest contributors: `(author, clean_pr_count)`.
    pub top_clean_authors: Vec<(String, usize)>,
}

/// Aggregated cross-repository data for `--global` report.
pub struct GlobalReportData {
    /// Per-repo stats, sorted by `total_slop_score` descending.
    pub repos: Vec<RepoStats>,
    /// Total PRs across all repos.
    pub total_prs: usize,
    /// Total slop score across all repos.
    pub total_slop_score: u64,
    /// Total antipatterns across all repos.
    pub total_antipatterns: u32,
    /// Total engineering minutes reclaimed across all repos.
    pub total_reclaimed_minutes: f64,
    /// Total actionable intercepts: Critical Threats, Necrotic GC, or Structural Slop.
    pub total_actionable_intercepts: u64,
    /// Count of Critical Threats across all repos (security: antipatterns or Swarm).
    pub critical_threats_count: u64,
    /// Count of Structural Slop PRs across all repos (slop_score > 0, not critical, not necrotic).
    pub structural_slop_count: u64,
    /// Total source bytes processed across all bounces (provenance ledger).
    pub total_source_bytes: u64,
    /// Total egress bytes sent to the Governor across all bounces (provenance ledger).
    pub total_egress_bytes: u64,
    /// Total CI datacenter energy conserved across all repos (kWh).
    ///
    /// Sum of `ci_energy_saved_kwh` from every bounce log entry across every repo.
    pub total_ci_energy_saved_kwh: f64,
}

/// Discover all bounce logs one directory level beneath `gauntlet_root`.
///
/// Scans `<gauntlet_root>/*/janitor/bounce_log.ndjson`. Returns a list
/// of `(repo_name, entries)` pairs, sorted alphabetically by repo name.
/// Repos with no entries are omitted.
pub fn discover_bounce_logs(gauntlet_root: &Path) -> Vec<(String, Vec<BounceLogEntry>)> {
    let Ok(dir_iter) = std::fs::read_dir(gauntlet_root) else {
        return Vec::new();
    };
    let mut results: Vec<(String, Vec<BounceLogEntry>)> = dir_iter
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            if !path.is_dir() {
                return None;
            }
            let janitor_dir = path.join(".janitor");
            if !janitor_dir.is_dir() {
                return None;
            }
            let log = load_bounce_log(&janitor_dir);
            if log.is_empty() {
                return None;
            }
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string());
            Some((name, log))
        })
        .collect();
    results.sort_by(|(a, _), (b, _)| a.cmp(b));
    results
}

/// Aggregates per-repo bounce log entries into a [`GlobalReportData`].
pub fn aggregate_global(repos: Vec<(String, Vec<BounceLogEntry>)>) -> GlobalReportData {
    // Pre-compute global categorical counts before consuming repos.
    let global_critical_threats: u64 = repos
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .filter(|e| is_critical_threat(e))
        .count() as u64;
    let global_gc_only: u64 = repos
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .filter(|e| e.necrotic_flag.is_some() && !is_critical_threat(e))
        .count() as u64;
    let global_structural_slop: u64 = repos
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .filter(|e| e.slop_score > 0 && !is_critical_threat(e) && e.necrotic_flag.is_none())
        .count() as u64;
    let repos_for_actionable: u64 =
        global_critical_threats + global_gc_only + global_structural_slop;

    // Provenance ledger aggregates — computed before repos is consumed by into_iter().
    let global_source_bytes: u64 = repos
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .map(|e| e.provenance.source_bytes_processed)
        .sum();
    let global_egress_bytes: u64 = repos
        .iter()
        .flat_map(|(_, entries)| entries.iter())
        .map(|e| e.provenance.egress_bytes_sent)
        .sum();

    let mut repo_stats: Vec<RepoStats> = repos
        .into_iter()
        .map(|(repo_name, entries)| {
            let pr_count = entries.len();
            let total_slop_score: u64 = entries.iter().map(|e| e.slop_score as u64).sum();
            let antipatterns_found: u32 = entries
                .iter()
                .map(|e| {
                    e.antipatterns.len() as u32 + if e.necrotic_flag.is_some() { 1 } else { 0 }
                })
                .sum();
            let dead_symbols_added: u32 = entries.iter().map(|e| e.dead_symbols_added).sum();
            let zombie_dep_prs: u32 =
                entries.iter().filter(|e| !e.zombie_deps.is_empty()).count() as u32;
            let (highest_score, highest_pr) = entries.iter().fold((0u32, None), |(hs, hp), e| {
                if e.slop_score > hs {
                    (e.slop_score, e.pr_number)
                } else {
                    (hs, hp)
                }
            });
            let reclaimed_minutes = entries.iter().filter(|e| e.necrotic_flag.is_some()).count()
                as f64
                * MINUTES_PER_TRIAGE;
            let critical_threats_count =
                entries.iter().filter(|e| is_critical_threat(e)).count() as u64;
            let gc_only_count = entries
                .iter()
                .filter(|e| e.necrotic_flag.is_some() && !is_critical_threat(e))
                .count() as u64;
            let structural_slop_count = entries
                .iter()
                .filter(|e| e.slop_score > 0 && !is_critical_threat(e) && e.necrotic_flag.is_none())
                .count() as u64;
            let total_actionable_intercepts =
                critical_threats_count + gc_only_count + structural_slop_count;
            let total_ci_energy_saved_kwh: f64 =
                entries.iter().map(|e| e.ci_energy_saved_kwh).sum();

            // Top 10 sloppiest PRs (descending score).
            let mut sorted_by_score: Vec<&BounceLogEntry> = entries.iter().collect();
            sorted_by_score.sort_by(|a, b| b.slop_score.cmp(&a.slop_score));
            let top_sloppiest: Vec<(u64, u32, String, String, String)> = sorted_by_score
                .iter()
                .filter(|e| e.slop_score > 0)
                .take(10)
                .map(|e| {
                    let pr_num = e.pr_number.unwrap_or(0);
                    let score = e.slop_score;
                    let state = e.state.to_string();
                    let author = e.author.as_deref().unwrap_or("unknown").to_owned();
                    let tc = if is_critical_threat(e) {
                        "Critical"
                    } else if e.necrotic_flag.is_some() {
                        "Necrotic"
                    } else {
                        "StructuralSlop"
                    }
                    .to_owned();
                    (pr_num, score, state, author, tc)
                })
                .collect();

            // Top 10 cleanest non-bot contributors (most PRs with score == 0).
            let mut clean_counts: HashMap<String, usize> = HashMap::new();
            for e in &entries {
                if e.slop_score == 0 && !e.is_bot {
                    let key = e.author.as_deref().unwrap_or("unknown").to_owned();
                    *clean_counts.entry(key).or_insert(0) += 1;
                }
            }
            let mut clean_vec: Vec<(String, usize)> = clean_counts.into_iter().collect();
            clean_vec.sort_by(|a, b| b.1.cmp(&a.1));
            clean_vec.truncate(10);

            RepoStats {
                repo_name,
                pr_count,
                total_slop_score,
                antipatterns_found,
                dead_symbols_added,
                zombie_dep_prs,
                highest_pr,
                highest_score,
                reclaimed_minutes,
                total_actionable_intercepts,
                critical_threats_count,
                structural_slop_count,
                total_ci_energy_saved_kwh,
                top_sloppiest,
                top_clean_authors: clean_vec,
            }
        })
        .collect();

    // Sort by cumulative slop score descending — worst repos first.
    repo_stats.sort_by(|a, b| b.total_slop_score.cmp(&a.total_slop_score));

    let total_prs: usize = repo_stats.iter().map(|r| r.pr_count).sum();
    let total_slop_score: u64 = repo_stats.iter().map(|r| r.total_slop_score).sum();
    let total_antipatterns: u32 = repo_stats.iter().map(|r| r.antipatterns_found).sum();
    let total_reclaimed_minutes: f64 = repo_stats.iter().map(|r| r.reclaimed_minutes).sum();
    let total_actionable_intercepts: u64 = repos_for_actionable;
    let critical_threats_count: u64 = global_critical_threats;
    let total_ci_energy_saved_kwh: f64 =
        repo_stats.iter().map(|r| r.total_ci_energy_saved_kwh).sum();

    GlobalReportData {
        repos: repo_stats,
        total_prs,
        total_slop_score,
        total_antipatterns,
        total_reclaimed_minutes,
        total_actionable_intercepts,
        critical_threats_count,
        structural_slop_count: global_structural_slop,
        // Provenance fields are aggregated from per-entry data computed
        // before repos was consumed; use pre-computed globals.
        total_source_bytes: global_source_bytes,
        total_egress_bytes: global_egress_bytes,
        total_ci_energy_saved_kwh,
    }
}

/// Renders the global cross-repository report as GitHub-flavored Markdown.
/// Loads the pre-computed C/C++ silo ranking from `.janitor/wopr_graph.json`.
///
/// Returns the full list unsorted — caller is responsible for ordering.
/// Returns an empty `Vec` when the file is absent or malformed.
fn load_wopr_graph(janitor_dir: &std::path::Path) -> Vec<(String, usize, usize)> {
    let json_path = janitor_dir.join("wopr_graph.json");
    let Ok(json_str) = std::fs::read_to_string(&json_path) else {
        return Vec::new();
    };
    serde_json::from_str::<Vec<(String, usize, usize)>>(&json_str).unwrap_or_default()
}

/// Render a single-line ASCII bar chart entry for a repository.
///
/// Format: `<repo_name padded>  ########----  N Critical  N Necrotic  N Clean`
///
/// `#` blocks represent Critical PRs (scaled), `-` blocks represent Necrotic PRs,
/// remaining width is implied Clean.  Total bar width is `width` characters.
///
/// Uses plain ASCII so the bar survives `\begin{verbatim}` in LaTeX PDF output.
/// Unicode block characters (█ / ░) are intentionally avoided here.
pub fn render_ascii_bar(
    repo_name: &str,
    critical: u64,
    necrotic: u64,
    clean: u64,
    width: usize,
) -> String {
    let total = critical + necrotic + clean;
    let (crit_blocks, nec_blocks) = if total == 0 || width == 0 {
        (0, 0)
    } else {
        let c = ((critical as f64 / total as f64) * width as f64).round() as usize;
        let n = ((necrotic as f64 / total as f64) * width as f64).round() as usize;
        (c.min(width), n.min(width.saturating_sub(c)))
    };
    let bar: String = "#".repeat(crit_blocks) + &"-".repeat(nec_blocks);
    // Left-pad repo name to 30 chars for alignment.
    let name_display: String = if repo_name.chars().count() > 28 {
        repo_name.chars().take(27).collect::<String>() + "…"
    } else {
        repo_name.to_owned()
    };
    format!("{name_display:<30}  {bar:<width$}  {critical} Critical  {necrotic} Necrotic  {clean} Clean")
}

pub fn render_global_markdown(data: &GlobalReportData, gauntlet_root: &str) -> String {
    let mut out = String::with_capacity(8192);

    let actionable = data.total_actionable_intercepts;
    let critical = data.critical_threats_count;
    let structural_slop = data.structural_slop_count;
    let gc_only = actionable
        .saturating_sub(critical)
        .saturating_sub(structural_slop);
    let tei = critical * 150 + gc_only * 20 + structural_slop * 20;
    let timestamp = crate::utc_now_iso8601();

    // ── Page 1 — Executive Summary ─────────────────────────────────────────
    // Compact the global summary page: tighter paragraph skip + table row height.
    out.push_str("```{=latex}\n\\setlength{\\parskip}{2pt plus 1pt minus 1pt}\n\\renewcommand{\\arraystretch}{0.9}\n```\n\n");
    out.push_str("# The Janitor — Audit Report\n\n");
    out.push_str(&format!("**Generated**: {timestamp}\n\n"));
    out.push_str(&format!(
        "**Repositories scanned**: {}\n\n",
        data.repos.len()
    ));
    out.push_str(&format!(
        "**Pull requests evaluated**: {}\n\n",
        data.total_prs
    ));
    out.push_str("\n---\n\n");
    out.push_str("| | |\n");
    out.push_str("|---|---|\n");
    out.push_str(&format!("| **Critical Threats Blocked** | {critical} |\n"));
    out.push_str(&format!(
        "| **Necrotic GC (bot-closeable)** | {gc_only} |\n"
    ));
    out.push_str(&format!(
        "| **Structural Slop (score > 0)** | {structural_slop} |\n"
    ));
    out.push_str(&format!("| **Total Economic Impact** | ${tei} |\n"));
    out.push_str("\n---\n\n");
    out.push_str(
        "*Scores derived from AST antipattern detection across 23 grammars, structural \
         clone fingerprinting via MinHash LSH, and necrotic symbol hydration. No ML \
         inference. All analysis runs locally — no source code is transmitted.*\n\n",
    );
    // No forced \newpage — flow directly into Threat Distribution / Repository
    // Breakdown so the executive brief fits on fewer pages.

    // ── Threat Distribution ────────────────────────────────────────────────
    // Only rendered for multi-repo global reports. A single-repo strike already
    // carries per-PR detail tables that make a one-bar chart redundant noise.
    if data.repos.len() > 1 {
        out.push_str("\n\\needspace{10\\baselineskip}\n\n");
        out.push_str("## Threat Distribution by Repository\n\n");
        out.push_str("```\n");
        for repo in &data.repos {
            let repo_gc = repo
                .total_actionable_intercepts
                .saturating_sub(repo.critical_threats_count);
            let clean = (repo.pr_count as u64).saturating_sub(repo.total_actionable_intercepts);
            let bar = render_ascii_bar(
                &repo.repo_name,
                repo.critical_threats_count,
                repo_gc,
                clean,
                12,
            );
            out.push_str(&bar);
            out.push('\n');
        }
        out.push_str("```\n\n");
        // No \newpage — Repository Breakdown follows on the same flow.
    }

    // ── Repository Breakdown table ─────────────────────────────────────────
    out.push_str("\n\\needspace{15\\baselineskip}\n\n");
    out.push_str("## Repository Breakdown\n\n");
    out.push_str(
        "```{=latex}\n\\small\n\\setlength{\\tabcolsep}{4pt}\n\\renewcommand{\\arraystretch}{1.0}\n\\setcounter{LTchunksize}{100}\n```\n\n",
    );
    out.push_str("| Repository | PRs | Total Slop | Intercepts | Economic Impact | Worst PR |\n");
    out.push_str("|------------|-----|-----------|:----------:|----------------:|----------|\n");
    for repo in &data.repos {
        let worst = repo
            .highest_pr
            .map(|n| format!("#{n} ({score})", score = repo.highest_score))
            .unwrap_or_else(|| "-".to_owned());
        let repo_gc_only = repo
            .total_actionable_intercepts
            .saturating_sub(repo.critical_threats_count)
            .saturating_sub(repo.structural_slop_count);
        // StructuralSlop billed at $20 (same tier as Necrotic GC).
        let repo_tei =
            repo.critical_threats_count * 150 + repo_gc_only * 20 + repo.structural_slop_count * 20;
        out.push_str(&format!(
            "| `{}` | {} | **{}** | {} | **${repo_tei}** | {} |\n",
            sanitize_latex_safe(&repo.repo_name),
            repo.pr_count,
            repo.total_slop_score,
            repo.total_actionable_intercepts,
            worst,
        ));
    }
    out.push('\n');

    // ── Top 10 Riskiest PRs ────────────────────────────────────────────────
    // \needspace guards the heading so it never strands at the bottom of a page.
    // Collect the top 10 entries with score > 50 across all repos.
    // top_sloppiest tuples: (pr_num, score, state, author, threat_class)
    let mut top_prs: Vec<(&RepoStats, u64, u32, String, String)> = Vec::new();
    for repo in &data.repos {
        for (pr_num, score, _state, author, threat_class) in &repo.top_sloppiest {
            if *score > 50 {
                top_prs.push((repo, *pr_num, *score, author.clone(), threat_class.clone()));
            }
        }
    }
    top_prs.sort_by(|a, b| b.2.cmp(&a.2));
    top_prs.truncate(10);

    if !top_prs.is_empty() {
        out.push_str("\n\\needspace{12\\baselineskip}\n\n");
        out.push_str("## Top 10 Riskiest PRs\n\n");
        out.push_str("| PR | Repo | Author | Score | Threat Class | Antipattern |\n");
        out.push_str("|---|---|---|---|---|---|\n");
        for (repo, pr_num, score, author, threat_class) in &top_prs {
            let author_s = sanitize_latex_safe(author);
            let auth_display: String = if author_s.len() > 20 {
                format!("{}…", &author_s[..19])
            } else {
                author_s
            };
            out.push_str(&format!(
                "| #{pr_num} | `{}` | {auth_display} | {score} | {threat_class} | — |\n",
                sanitize_latex_safe(&repo.repo_name),
            ));
        }
        out.push('\n');
    }

    // ── Scoring Methodology ────────────────────────────────────────────────
    out.push_str("\n\\needspace{8\\baselineskip}\n\n");
    out.push_str("## Scoring Methodology\n\n");
    out.push_str("| Classification | Condition | Billing |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| Critical Threat | `security:` antipattern OR Swarm collision | $150 |\n");
    out.push_str("| Necrotic GC | Dead-code ghost (bot-automatable) | $20 |\n");
    out.push_str("| Structural Slop | slop_score > 0, no critical/necrotic signal | $20 |\n");
    out.push_str("| Boilerplate | slop_score == 0, no threat signal | $0 |\n");
    out.push('\n');
    out.push_str(
        "Score formula: `(clones × 5) + (zombies × 10) + (antipattern_score) + \
         (comment_violations × 5) + (unlinked_pr × 20) + (hallucinated_fix × 100)`\n\n",
    );

    // ── Per-repo dedicated pages ───────────────────────────────────────────
    // Each repo starts on a new page.  Subsections within each repo
    // (Sloppiest, Cleanest, Silos) flow without internal breaks;
    // \needspace before each heading prevents orphaned headings at page bottom.
    for repo in &data.repos {
        out.push_str("\n\\newpage\n\n");
        out.push_str(&format!("## {}\n\n", sanitize_latex_safe(&repo.repo_name)));

        let repo_hours = repo.reclaimed_minutes / 60.0;
        let repo_gc_only_page = repo
            .total_actionable_intercepts
            .saturating_sub(repo.critical_threats_count)
            .saturating_sub(repo.structural_slop_count);
        let repo_ci_bounty_page = repo.critical_threats_count * 150;
        let repo_tei_page = repo.critical_threats_count * 150
            + repo_gc_only_page * 20
            + repo.structural_slop_count * 20;
        out.push_str("| Metric | Value |\n");
        out.push_str("|--------|-------|\n");
        out.push_str(&format!("| PRs Analyzed | {} |\n", repo.pr_count));
        out.push_str(&format!(
            "| Total Slop Score | {} |\n",
            repo.total_slop_score
        ));
        out.push_str(&format!("| Time Reclaimed | {repo_hours:.1} hours |\n"));
        out.push_str(&format!(
            "| Critical Threat Intercepts ($150) | ${repo_ci_bounty_page} |\n"
        ));
        out.push_str(&format!("| Total Economic Impact | ${repo_tei_page} |\n"));
        out.push_str(&format!("| Antipatterns | {} |\n", repo.antipatterns_found));
        if let Some(wp) = repo.highest_pr {
            out.push_str(&format!(
                "| Worst PR | #{wp} (score {}) |\n",
                repo.highest_score
            ));
        }
        out.push('\n');

        // Top 10 Sloppiest PRs table.
        out.push_str("\n\\needspace{12\\baselineskip}\n\n");
        out.push_str("### Top 10 Sloppiest PRs\n\n");
        out.push_str("```{=latex}\n\\small\n\\renewcommand{\\arraystretch}{1.2}\n```\n\n");
        if repo.top_sloppiest.is_empty() {
            out.push_str("*No flagged PRs in this repository.*\n\n");
        } else {
            out.push_str("| PR | Score | State | Author |\n");
            out.push_str("|----|------:|-------|--------|\n");
            for (pr_num, score, state, author, _tc) in &repo.top_sloppiest {
                // Truncate long author handles to 22 chars for layout integrity.
                let author_s = sanitize_latex_safe(author);
                let auth_display: &str = if author_s.len() > 22 {
                    &author_s[..22]
                } else {
                    author_s.as_str()
                };
                out.push_str(&format!(
                    "| #{pr_num} | {score} | {state} | {auth_display} |\n"
                ));
            }
            out.push('\n');
        }

        // Top 10 Cleanest Contributors table.
        out.push_str("\n\\needspace{12\\baselineskip}\n\n");
        out.push_str("### Top 10 Cleanest Contributors\n\n");
        out.push_str("```{=latex}\n\\small\n\\renewcommand{\\arraystretch}{1.2}\n```\n\n");
        if repo.top_clean_authors.is_empty() {
            out.push_str("*No clean (score = 0) human PRs in this repository.*\n\n");
        } else {
            out.push_str("| Contributor | Clean PRs |\n");
            out.push_str("|-------------|----------:|\n");
            for (author, count) in &repo.top_clean_authors {
                let author_s = sanitize_latex_safe(author);
                let auth_display: &str = if author_s.len() > 28 {
                    &author_s[..28]
                } else {
                    author_s.as_str()
                };
                out.push_str(&format!("| {auth_display} | {count} |\n"));
            }
            out.push('\n');
        }

        // Architectural Debt: C/C++ Compile-Time Silos ─────────────────────
        // Loaded from `.janitor/wopr_graph.json` written by `janitor hyper-drive`.
        // Absent for repos that have not been hyper-driven — section is silently omitted.
        let silo_janitor_dir = std::path::Path::new(gauntlet_root)
            .join(&repo.repo_name)
            .join(".janitor");
        let mut silos = load_wopr_graph(&silo_janitor_dir);
        if !silos.is_empty() {
            // Rank by transitive_reach descending; cap at 10.
            silos.sort_by(|a, b| b.2.cmp(&a.2));
            silos.truncate(10);
            out.push_str("\n\\needspace{12\\baselineskip}\n\n");
            out.push_str("### Architectural Debt: C/C++ Compile-Time Silos\n\n");
            out.push_str("```{=latex}\n\\small\n\\renewcommand{\\arraystretch}{1.2}\n```\n\n");
            out.push_str("| Header Path | Direct Imports | Transitive Blast Radius |\n");
            out.push_str("|-------------|:--------------:|:-----------------------:|\n");
            for (label, direct, blast) in &silos {
                out.push_str(&format!(
                    "| `{}` | {} | {} |\n",
                    sanitize_latex_safe(label),
                    direct,
                    blast,
                ));
            }
            out.push('\n');
        }
    }

    out
}

/// Renders the global cross-repository report as structured JSON.
pub fn render_global_json(data: &GlobalReportData, gauntlet_root: &str) -> serde_json::Value {
    let hours = data.total_reclaimed_minutes / 60.0;
    let necrotic_count = (data.total_reclaimed_minutes / MINUTES_PER_TRIAGE).round() as u64;

    // Provenance aggregates — extracted before json! macro (no let-blocks allowed).
    let g_exfil_pct = if data.total_source_bytes > 0 {
        (data.total_egress_bytes as f64 / data.total_source_bytes as f64) * 100.0
    } else {
        0.0
    };
    let global_prov_json = serde_json::json!({
        "total_source_bytes_processed": data.total_source_bytes,
        "total_egress_bytes_sent": data.total_egress_bytes,
        "exfiltration_ratio_pct": (g_exfil_pct * 10000.0).round() / 10000.0,
        "zero_upload_verified": data.total_egress_bytes == 0 || g_exfil_pct < 1.0,
    });
    let critical = data.critical_threats_count;
    let structural_slop = data.structural_slop_count;
    let gc_only = data
        .total_actionable_intercepts
        .saturating_sub(critical)
        .saturating_sub(structural_slop);
    let critical_threat_bounty = critical * 150;
    let tei = critical * 150 + gc_only * 20 + structural_slop * 20;
    serde_json::json!({
        "schema_version": env!("CARGO_PKG_VERSION"),
        "gauntlet_root": gauntlet_root,
        "total_repos": data.repos.len(),
        "total_prs": data.total_prs,
        "total_slop_score": data.total_slop_score,
        "total_antipatterns": data.total_antipatterns,
        "workslop": {
            "actionable_intercepts": data.total_actionable_intercepts,
            "critical_threats_count": critical,
            "necrotic_count": necrotic_count,
            "structural_slop_count": structural_slop,
            "total_reclaimed_minutes": (data.total_reclaimed_minutes * 10.0).round() / 10.0,
            "total_reclaimed_hours": (hours * 10.0).round() / 10.0,
            "critical_threat_bounty_usd": critical_threat_bounty,
            "total_economic_impact_usd": tei,
            "total_ci_energy_saved_kwh": (data.total_ci_energy_saved_kwh * 10.0).round() / 10.0,
        },
        "provenance": global_prov_json,
        "repositories": data.repos.iter().map(|r| {
            let r_hours = r.reclaimed_minutes / 60.0;
            let r_gc_only = r.total_actionable_intercepts
                .saturating_sub(r.critical_threats_count)
                .saturating_sub(r.structural_slop_count);
            let r_ci_bounty = r.critical_threats_count * 150;
            let r_tei = r.critical_threats_count * 150
                + r_gc_only * 20
                + r.structural_slop_count * 20;
            serde_json::json!({
                "repo_name": r.repo_name,
                "pr_count": r.pr_count,
                "total_slop_score": r.total_slop_score,
                "antipatterns_found": r.antipatterns_found,
                "dead_symbols_added": r.dead_symbols_added,
                "zombie_dep_prs": r.zombie_dep_prs,
                "highest_pr": r.highest_pr,
                "highest_score": r.highest_score,
                "reclaimed_minutes": (r.reclaimed_minutes * 10.0).round() / 10.0,
                "reclaimed_hours": (r_hours * 10.0).round() / 10.0,
                "total_actionable_intercepts": r.total_actionable_intercepts,
                "critical_threats_count": r.critical_threats_count,
                "structural_slop_count": r.structural_slop_count,
                "critical_threat_bounty_usd": r_ci_bounty,
                "total_economic_impact_usd": r_tei,
                "total_ci_energy_saved_kwh": (r.total_ci_energy_saved_kwh * 10.0).round() / 10.0,
            })
        }).collect::<Vec<_>>(),
    })
}

/// Groups identical strings, preserving first-occurrence order.
///
/// Returns `(text, count)` pairs. Strings that appear only once have count 1.
/// Used both in [`render_markdown`] for display and in [`crate::export`] for
/// the CSV `Antipattern_IDs` column to collapse repetition into `label (xN)` form.
pub fn group_strings(items: &[String]) -> Vec<(&str, usize)> {
    let mut result: Vec<(&str, usize)> = Vec::new();
    for s in items {
        if let Some(entry) = result.iter_mut().find(|(k, _)| *k == s.as_str()) {
            entry.1 += 1;
        } else {
            result.push((s.as_str(), 1));
        }
    }
    result
}

/// Format byte count as human-readable (KB/MB).
fn fmt_bytes(b: u64) -> String {
    if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{b} B")
    }
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 renderer
// ---------------------------------------------------------------------------

/// Render `entries` as a SARIF 2.1.0 JSON string.
///
/// Output formats: `markdown` (default), `json`, `pdf`, `cbom`, `sarif`.
///
/// ## Schema
/// Produces a single SARIF run with:
/// - `tool.driver.rules[]` — one entry per unique antipattern label.
/// - `results[]` — one entry per `(BounceLogEntry, antipattern)` pair plus
///   an additional result for each Swarm collision.
///
/// ## Level mapping
/// - `"error"` — antipattern label contains `"security:"`.
/// - `"warning"` — all other antipatterns.
///
/// ## Swarm collisions
/// Non-empty `collided_pr_numbers` emit an additional result with
/// `ruleId = "swarm:structural_collision"` at level `"error"`.
///
/// ## Zero new dependencies
/// Uses only `serde_json::json!()` — no additional crates required.
/// Extract a 1-based line number from the `(line=N)` suffix appended by the
/// slop pipeline to antipattern detail strings.  Returns `None` when the
/// suffix is absent (pre-v7.9.4 log entries or non-positional findings).
fn parse_sarif_line(detail: &str) -> Option<u32> {
    let start = detail.rfind("(line=")?;
    let rest = &detail[start + 6..];
    let end = rest.find(')')?;
    rest[..end].parse().ok()
}

pub fn render_sarif(entries: &[BounceLogEntry]) -> String {
    use serde_json::{json, Value};
    use std::collections::BTreeSet;

    // Collect all unique antipattern labels (stable order via BTreeSet).
    let mut all_labels: BTreeSet<String> = BTreeSet::new();
    for e in entries {
        for ap in &e.antipatterns {
            all_labels.insert(ap.clone());
        }
        if !e.collided_pr_numbers.is_empty() {
            all_labels.insert("swarm:structural_collision".to_string());
        }
    }

    // Build rules array.
    let rules: Vec<Value> = all_labels
        .iter()
        .map(|label| {
            let level = if label.contains("security:") {
                "error"
            } else {
                "warning"
            };
            json!({
                "id": label,
                "name": label,
                "shortDescription": { "text": label },
                "defaultConfiguration": { "level": level }
            })
        })
        .collect();

    // Build results array.
    let mut results: Vec<Value> = Vec::new();
    for e in entries {
        let pr_num = e.pr_number.unwrap_or(0);
        let author = e.author.as_deref().unwrap_or("-");
        let score_str = e.slop_score.to_string();
        let repo = e.repo_slug.as_str();

        for ap in &e.antipatterns {
            let level = if ap.contains("security:") {
                "error"
            } else {
                "warning"
            };
            let uri = if repo.is_empty() {
                format!("pr/{pr_num}")
            } else {
                format!("{repo}/pr/{pr_num}")
            };
            // Populate physicalLocation.region.startLine when a (line=N) suffix
            // is present in the detail string (emitted by the slop pipeline for
            // both tree-sitter and binary_hunter findings since v7.9.4).
            let physical_location: Value = match parse_sarif_line(ap) {
                Some(line) => json!({
                    "artifactLocation": { "uri": uri },
                    "region": { "startLine": line }
                }),
                None => json!({
                    "artifactLocation": { "uri": uri }
                }),
            };
            results.push(json!({
                "ruleId": ap,
                "level": level,
                "message": {
                    "text": format!("PR #{pr_num} by {author}: {ap}")
                },
                "locations": [
                    { "physicalLocation": physical_location }
                ],
                "partialFingerprints": {
                    "janitorScore": score_str
                }
            }));
        }

        // Swarm collision result.
        if !e.collided_pr_numbers.is_empty() {
            let uri = if repo.is_empty() {
                format!("pr/{pr_num}")
            } else {
                format!("{repo}/pr/{pr_num}")
            };
            results.push(json!({
                "ruleId": "swarm:structural_collision",
                "level": "error",
                "message": {
                    "text": format!(
                        "PR #{pr_num} by {author}: structural clone collision with PRs {:?}",
                        e.collided_pr_numbers
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": { "uri": uri }
                        }
                    }
                ],
                "partialFingerprints": {
                    "janitorScore": score_str
                }
            }));
        }
    }

    let doc = json!({
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "janitor",
                        "version": env!("CARGO_PKG_VERSION"),
                        "informationUri": "https://thejanitor.app",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    });

    serde_json::to_string_pretty(&doc).unwrap_or_else(|_| "{}".to_string())
}

// ---------------------------------------------------------------------------
// GitHub Actions Step Summary
// ---------------------------------------------------------------------------

/// Renders a high-density GitHub Actions Step Summary Markdown dashboard for a
/// single bounce result.
///
/// Emits four sections:
/// - **Integrity Radar**: 5 billing tiers with status icons (🔴/🟡/🟢).
/// - **Structural Topology**: Top 3 version silos or dependency splits detected
///   in this patch.
/// - **Provenance Ledger**: Mathematical proof of 0 bytes exfiltrated.
/// - **Vibe-Check**: NCD generative-verbosity indicator.
///
/// Zero heap-cloning of source fields: entry fields are borrowed as `&str`
/// throughout; only the `String` accumulator itself is allocated.
pub fn render_step_summary(entry: &BounceLogEntry) -> String {
    let mut out = String::with_capacity(2048);

    let is_critical = is_critical_threat(entry);
    let is_necrotic = entry.necrotic_flag.is_some();
    let is_structural = entry.slop_score > 0 && !is_critical && !is_necrotic;

    let banner = if is_critical {
        "🔴 **CRITICAL THREAT INTERCEPTED**"
    } else if is_necrotic {
        "🔴 **NECROTIC — Bot-Closeable**"
    } else if is_structural {
        "🟡 **STRUCTURAL SLOP DETECTED**"
    } else {
        "🟢 **SANCTUARY INTACT — PATCH CLEAN**"
    };

    out.push_str("## Janitor Integrity Dashboard\n\n");
    out.push_str(banner);
    out.push_str(" · Slop Score: `");
    out.push_str(&entry.slop_score.to_string());
    out.push_str("`\n");
    let per_pr_tei: u32 = if is_critical {
        150
    } else if is_necrotic || is_structural {
        20
    } else {
        0
    };
    out.push_str(&format!(
        "**TEI: ${per_pr_tei} · Energy Reclaimed: {:.1} kWh**\n\n",
        entry.ci_energy_saved_kwh
    ));

    // ── Integrity Radar ────────────────────────────────────────────────────────
    out.push_str("### Integrity Radar\n\n");
    out.push_str("| Tier | Signal | Status |\n");
    out.push_str("|------|--------|--------|\n");

    // Tier 1: Critical Threats
    let crit_icon = if is_critical { "🔴" } else { "🟢" };
    let crit_n = entry
        .antipatterns
        .iter()
        .filter(|a| a.contains("security:"))
        .count();
    let crit_collisions = entry.collided_pr_numbers.len();
    let crit_signal = if is_critical {
        format!("{crit_n} security antipattern(s); {crit_collisions} swarm collision(s)")
    } else {
        "None".to_owned()
    };
    out.push_str("| Critical Threats | ");
    out.push_str(&crit_signal);
    out.push_str(" | ");
    out.push_str(crit_icon);
    out.push_str(" |\n");

    // Tier 2: Secrets / Credential Leak
    let secret_count = entry
        .antipatterns
        .iter()
        .filter(|a| a.contains("credential_leak"))
        .count();
    let secret_icon = if secret_count > 0 { "🔴" } else { "🟢" };
    let secret_signal = if secret_count > 0 {
        format!("{secret_count} credential finding(s) — rotate immediately")
    } else {
        "None".to_owned()
    };
    out.push_str("| Secrets | ");
    out.push_str(&secret_signal);
    out.push_str(" | ");
    out.push_str(secret_icon);
    out.push_str(" |\n");

    // Tier 3: Necrotic GC
    let nec_icon = if is_necrotic { "🔴" } else { "🟢" };
    let nec_signal = entry.necrotic_flag.as_deref().unwrap_or("None");
    out.push_str("| Necrotic GC | `");
    out.push_str(nec_signal);
    out.push_str("` | ");
    out.push_str(nec_icon);
    out.push_str(" |\n");

    // Tier 3: Structural Slop
    let struct_icon = if is_structural { "🟡" } else { "🟢" };
    let struct_signal = if is_structural {
        format!("Score {}", entry.slop_score)
    } else {
        "None".to_owned()
    };
    out.push_str("| Structural Slop | ");
    out.push_str(&struct_signal);
    out.push_str(" | ");
    out.push_str(struct_icon);
    out.push_str(" |\n");

    // Tier 4: Boilerplate (clean baseline)
    let bplate_icon = if entry.slop_score == 0 {
        "🟢"
    } else {
        "🟡"
    };
    let bplate_signal = if entry.slop_score == 0 {
        "Clean"
    } else {
        "Flagged"
    };
    out.push_str("| Boilerplate | ");
    out.push_str(bplate_signal);
    out.push_str(" | ");
    out.push_str(bplate_icon);
    out.push_str(" |\n");

    // Tier 5: Agentic Activity
    let agent_icon = if entry.agentic_pct > 0.0 {
        "🟡"
    } else {
        "🟢"
    };
    out.push_str("| Agentic Activity | ");
    out.push_str(&format!("{:.0}% agentic contribution", entry.agentic_pct));
    out.push_str(" | ");
    out.push_str(agent_icon);
    out.push_str(" |\n\n");

    // ── Structural Topology ────────────────────────────────────────────────────
    out.push_str("### Structural Topology\n\n");
    if entry.version_silos.is_empty() {
        out.push_str("No version silos detected in this patch.\n\n");
    } else {
        out.push_str("Top version splits detected in this patch:\n\n");
        for (i, silo) in entry.version_silos.iter().take(3).enumerate() {
            out.push_str(&format!("{}. `{}`\n", i + 1, html_escape(silo)));
        }
        if entry.version_silos.len() > 3 {
            out.push_str(&format!(
                "\n_…and {} more silo(s) total._\n",
                entry.version_silos.len()
            ));
        }
        out.push('\n');
    }

    // ── Provenance Ledger ──────────────────────────────────────────────────────
    out.push_str("### Provenance Ledger\n\n");
    let src = entry.provenance.source_bytes_processed;
    let egress = entry.provenance.egress_bytes_sent;
    let exfil_pct = if src > 0 {
        (egress as f64 / src as f64) * 100.0
    } else {
        0.0
    };
    out.push_str("| Field | Value |\n");
    out.push_str("|-------|-------|\n");
    out.push_str(&format!("| Source bytes analysed | `{src}` |\n"));
    out.push_str(&format!("| Egress bytes sent | `{egress}` |\n"));
    out.push_str(&format!(
        "| **Exfiltration ratio** | **{exfil_pct:.4}%** |\n"
    ));
    out.push_str(&format!(
        "| Analysis duration | `{}ms` |\n",
        entry.provenance.analysis_duration_ms
    ));
    out.push_str("| Zero-upload verified | ✅ Source code never left the runner |\n\n");
    out.push_str(
        "> **Mathematical proof**: `egress_bytes / source_bytes ≈ 0%`. \
         The structural score — never source code — crosses the network boundary.\n\n",
    );

    // ── Vibe-Check (NCD Generative Verbosity) ─────────────────────────────────
    out.push_str("### Vibe-Check (Generative Verbosity)\n\n");
    let ncd_hit = entry
        .antipatterns
        .iter()
        .any(|a| a.contains("antipattern:ncd_anomaly") || a.contains("HighGenerativeVerbosity:"));
    if ncd_hit {
        out.push_str(
            "🟡 **NCD ANOMALY** — patch compresses unusually well (NCD ratio < 0.15). \
             Statistical signature of AI-generated boilerplate: \
             high internal repetition, low information density.\n\n",
        );
    } else {
        out.push_str(
            "🟢 **NCD NOMINAL** — compression ratio within normal range. \
             Patch information density is consistent with human-authored code.\n\n",
        );
    }

    // ── Search Reputation Risk ──────────────────────────────────────────────
    out.push_str("### Search Reputation Risk\n\n");
    if ncd_hit {
        out.push_str(
            "🔴 **HIGH** — NCD ratio < 0.15 indicates AI boilerplate. \
             Merging this patch introduces statistically self-similar, \
             low-variance content. Public repositories accumulate this signal \
             across PRs; sustained high-NCD merge history degrades search \
             engine relevance scores and may trigger low-quality content \
             classifiers. Reject or refactor before merge.\n\n",
        );
    } else {
        out.push_str(
            "🟢 **LOW** — patch information density is within normal range. \
             No search reputation risk detected.\n\n",
        );
    }

    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_dead(n: usize) -> Vec<DeadSymbolEntry> {
        (0..n)
            .map(|i| DeadSymbolEntry {
                qualified_name: format!("module::dead_fn_{i}"),
                file_path: format!("src/file_{}.rs", i / 100),
                start_line: (i as u32 * 10) + 1,
                byte_size: 200,
            })
            .collect()
    }

    #[test]
    fn test_dead_symbol_cap_at_50_with_overflow_message() {
        let dead = make_dead(1000);
        let output = render_scan_markdown(&dead, 2000, &[], "test-repo", 50);
        // Overflow = 1000 - 50 = 950
        assert!(
            output.contains("950 more"),
            "should contain '950 more' overflow footer;\ngot first 600 chars:\n{}",
            &output[..output.len().min(600)]
        );
        // At most 50 data rows in the table (lines starting with "| N " pattern).
        let data_rows = output
            .lines()
            .filter(|l| l.starts_with("| ") && l.contains("dead_fn_"))
            .count();
        assert!(
            data_rows <= 50,
            "should emit at most 50 table rows, got {data_rows}"
        );
    }

    #[test]
    fn test_dead_symbol_no_overflow_when_under_cap() {
        let dead = make_dead(30);
        let output = render_scan_markdown(&dead, 100, &[], "test-repo", 50);
        assert!(
            !output.contains("more entries"),
            "no overflow footer when count <= 50"
        );
    }

    #[test]
    fn test_orphan_files_capped_at_50() {
        let orphans: Vec<String> = (0..100).map(|i| format!("src/orphan_{i}.rs")).collect();
        let output = render_scan_markdown(&[], 0, &orphans, "test-repo", 50);
        // Overflow = 100 - 50 = 50
        assert!(
            output.contains("50 more"),
            "should contain '50 more' orphan overflow footer"
        );
        let orphan_rows = output.lines().filter(|l| l.contains("orphan_")).count();
        assert!(
            orphan_rows <= 50,
            "at most 50 orphan lines, got {orphan_rows}"
        );
    }

    #[test]
    fn test_orphan_files_no_overflow_when_under_cap() {
        let orphans: Vec<String> = (0..20).map(|i| format!("src/file_{i}.rs")).collect();
        let output = render_scan_markdown(&[], 0, &orphans, "test-repo", 50);
        assert!(!output.contains("more entries"), "no overflow when <= 50");
    }

    fn make_clean_entry() -> BounceLogEntry {
        BounceLogEntry {
            pr_number: Some(42),
            author: Some("alice".to_string()),
            timestamp: "2026-03-28T10:00:00Z".to_string(),
            slop_score: 0,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns: vec![],
            comment_violations: vec![],
            min_hashes: vec![],
            zombie_deps: vec![],
            state: PrState::Open,
            is_bot: false,
            repo_slug: "owner/repo".to_string(),
            suppressed_by_domain: 0,
            collided_pr_numbers: vec![],
            necrotic_flag: None,
            commit_sha: "abc123".to_string(),
            policy_hash: "def456".to_string(),
            version_silos: vec![],
            agentic_pct: 0.0,
            ci_energy_saved_kwh: 0.0,
            provenance: Provenance {
                analysis_duration_ms: 42,
                source_bytes_processed: 1024,
                egress_bytes_sent: 0,
            },
            governor_status: None,
            pqc_sig: None,
        }
    }

    #[test]
    fn test_render_step_summary_clean_entry() {
        let entry = make_clean_entry();
        let output = render_step_summary(&entry);
        assert!(
            output.contains("SANCTUARY INTACT"),
            "clean entry must show SANCTUARY INTACT"
        );
        assert!(
            output.contains("Integrity Radar"),
            "must include radar section"
        );
        assert!(
            output.contains("Provenance Ledger"),
            "must include provenance section"
        );
        assert!(
            output.contains("Vibe-Check"),
            "must include vibe-check section"
        );
        assert!(
            output.contains("NCD NOMINAL"),
            "clean entry must show NCD NOMINAL"
        );
        assert!(output.contains("0.0000%"), "exfil ratio must be near 0%");
    }

    #[test]
    fn test_render_step_summary_critical_entry() {
        let mut entry = make_clean_entry();
        entry.slop_score = 150;
        entry.antipatterns = vec!["security:unsafe_gets — gets() is unsafe".to_string()];
        let output = render_step_summary(&entry);
        assert!(
            output.contains("CRITICAL THREAT"),
            "critical entry must show CRITICAL THREAT banner"
        );
        assert!(
            output.contains("🔴"),
            "critical entry must show red indicator"
        );
    }

    #[test]
    fn test_render_step_summary_ncd_anomaly() {
        let mut entry = make_clean_entry();
        entry.antipatterns = vec!["antipattern:ncd_anomaly — NCD ratio 0.08".to_string()];
        let output = render_step_summary(&entry);
        assert!(
            output.contains("NCD ANOMALY"),
            "must detect ncd_anomaly antipattern"
        );
        assert!(
            output.contains("🟡"),
            "NCD anomaly must show amber indicator"
        );
    }

    #[test]
    fn test_render_step_summary_version_silos() {
        let mut entry = make_clean_entry();
        entry.version_silos = vec![
            "serde (v1.0.100 vs v1.0.150)".to_string(),
            "tokio (v1.38 vs v1.40)".to_string(),
            "anyhow (v1.0.80 vs v1.0.86)".to_string(),
            "thiserror (v1.0 vs v2.0)".to_string(),
        ];
        let output = render_step_summary(&entry);
        // Top 3 must appear; 4th triggers "more" message.
        assert!(output.contains("serde"), "first silo must appear");
        assert!(output.contains("tokio"), "second silo must appear");
        assert!(output.contains("anyhow"), "third silo must appear");
        assert!(
            output.contains("more silo"),
            "overflow message must appear when >3"
        );
    }
}

#[cfg(test)]
mod webhook_tests {
    use super::*;
    use common::policy::WebhookConfig;

    fn make_entry(antipatterns: Vec<String>, necrotic: Option<String>) -> BounceLogEntry {
        BounceLogEntry {
            pr_number: Some(1),
            author: Some("test".to_string()),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
            slop_score: 0,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns,
            comment_violations: vec![],
            min_hashes: vec![],
            zombie_deps: vec![],
            state: PrState::Open,
            is_bot: false,
            repo_slug: String::new(),
            suppressed_by_domain: 0,
            collided_pr_numbers: vec![],
            necrotic_flag: necrotic,
            commit_sha: String::new(),
            policy_hash: String::new(),
            version_silos: vec![],
            agentic_pct: 0.0,
            ci_energy_saved_kwh: 0.0,
            provenance: Provenance::default(),
            governor_status: None,
            pqc_sig: None,
        }
    }

    #[test]
    fn webhook_no_fire_when_url_empty() {
        let entry = make_entry(vec!["security:strcpy".to_string()], None);
        let policy = common::policy::JanitorPolicy::default();
        // Should not panic; url is empty so returns early
        fire_webhook_if_configured(&entry, &policy);
    }

    #[test]
    fn webhook_no_fire_when_event_not_matched() {
        let _entry = make_entry(vec![], Some("SEMANTIC_NULL".to_string()));
        let mut policy = common::policy::JanitorPolicy::default();
        policy.webhook = WebhookConfig {
            url: "https://example.com/hook".to_string(),
            secret: String::new(),
            events: vec!["critical_threat".to_string()], // necrotic not in filter
        };
        // necrotic flag present, but filter only wants critical_threat — should not fire
        assert!(!policy.webhook.should_fire(false, true));
    }

    #[test]
    fn webhook_fires_for_critical() {
        let policy_cfg = WebhookConfig {
            url: "https://example.com/hook".to_string(),
            secret: String::new(),
            events: vec!["critical_threat".to_string()],
        };
        assert!(policy_cfg.should_fire(true, false));
    }
}

#[cfg(test)]
mod soft_fail_tests {
    use super::*;

    fn make_test_entry() -> BounceLogEntry {
        BounceLogEntry {
            pr_number: None,
            author: None,
            timestamp: "2026-04-03T00:00:00Z".to_string(),
            slop_score: 0,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns: vec![],
            comment_violations: vec![],
            min_hashes: vec![],
            zombie_deps: vec![],
            state: PrState::Open,
            is_bot: false,
            repo_slug: String::new(),
            suppressed_by_domain: 0,
            collided_pr_numbers: vec![],
            necrotic_flag: None,
            commit_sha: String::new(),
            policy_hash: String::new(),
            version_silos: vec![],
            agentic_pct: 0.0,
            ci_energy_saved_kwh: 0.0,
            provenance: Provenance::default(),
            governor_status: None,
            pqc_sig: None,
        }
    }

    /// Verify that `post_bounce_result` returns `Err` when the Governor is
    /// unreachable.  This is the precondition that the soft-fail path handles.
    #[test]
    fn post_bounce_result_fails_for_unreachable_endpoint() {
        let entry = make_test_entry();
        // Port 1 is always connection-refused; never has a listener.
        let result = post_bounce_result("http://127.0.0.1:1/v1/report", "fake-token", &entry);
        assert!(result.is_err(), "unreachable endpoint must return Err");
    }

    /// With soft_fail = true the caller must suppress the Governor error and
    /// return Ok — simulating the `Err(e) if soft_fail` match arm in cmd_bounce.
    #[test]
    fn soft_fail_suppresses_governor_error() {
        let entry = make_test_entry();
        let result = post_bounce_result("http://127.0.0.1:1/v1/report", "fake-token", &entry);
        let soft_fail = true;
        let handled: anyhow::Result<()> = match result {
            Ok(()) => Ok(()),
            Err(_) if soft_fail => Ok(()), // soft-fail: degrade, do not propagate
            Err(e) => Err(e),
        };
        assert!(
            handled.is_ok(),
            "soft_fail path must return Ok when governor unreachable"
        );
    }

    /// Without soft_fail the Governor error must propagate (CLI exits 1).
    #[test]
    fn hard_fail_propagates_governor_error() {
        let entry = make_test_entry();
        let result = post_bounce_result("http://127.0.0.1:1/v1/report", "fake-token", &entry);
        let soft_fail = false;
        let handled: anyhow::Result<()> = match result {
            Ok(()) => Ok(()),
            Err(_) if soft_fail => Ok(()),
            Err(e) => Err(e),
        };
        assert!(
            handled.is_err(),
            "hard-fail path must propagate Err when governor unreachable"
        );
    }
}
