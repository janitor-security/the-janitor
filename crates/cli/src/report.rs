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
                    "warning: webhook secret env var '{var_name}' not set — delivering unsigned"
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
            .set("Content-Type", "application/json")
            .set("X-Janitor-Event", event_name);
        if !sig_header.is_empty() {
            builder = builder.set("X-Janitor-Signature-256", &sig_header);
        }
        match builder.send_string(&payload) {
            Ok(_) => {}
            Err(e) => eprintln!("warning: webhook delivery failed: {e}"),
        }
    });
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
    /// Total engineering minutes reclaimed: necrotic PR count × [`MINUTES_PER_TRIAGE`].
    ///
    /// Only PRs with `necrotic_flag.is_some()` contribute — these are
    /// `SEMANTIC_NULL`, `GHOST_COLLISION`, and `UNWIRED_ISLAND` verdicts that
    /// can be bulk-closed by a bot without human review.  Score-blocked PRs
    /// still require a human to verify the finding, so they do not reclaim time.
    pub total_reclaimed_minutes: f64,
    /// Total number of actionable intercepts: Critical Threats OR Garbage
    /// Collection (Necrotic) PRs.  Does NOT count PRs whose score is elevated
    /// purely by `logic_clones_found` — clone boilerplate inflates score but
    /// does not represent a billable security event.
    pub total_actionable_intercepts: u64,
    /// Count of PRs classified as Critical Threats per [`is_critical_threat`].
    ///
    /// A subset of `total_actionable_intercepts`; used to split TEI billing
    /// between the $150 security-intercept tier and $20 GC tier.
    pub critical_threats_count: u64,
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
// Architecture Inversion — Governor result submission
// ---------------------------------------------------------------------------

/// POST the [`BounceLogEntry`] to the Governor's `/v1/report` endpoint.
///
/// Used in Architecture Inversion mode: after `append_bounce_log`, if `--report-url`
/// and `--analysis-token` are set, the scored entry is submitted to the Governor so
/// it can update the GitHub Check Run without ever receiving source code.
///
/// Non-fatal: logs a warning on failure so local analysis still succeeds.
/// The Bearer token is the short-lived JWT obtained from `/v1/analysis-token`.
pub fn post_bounce_result(url: &str, token: &str, entry: &BounceLogEntry) -> anyhow::Result<()> {
    let body = serde_json::to_string(entry)?;
    let result = ureq::post(url)
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .send_string(&body);
    match result {
        Ok(r) if r.status() == 200 || r.status() == 201 => {
            eprintln!("info: bounce result reported to Governor");
        }
        Ok(r) => {
            eprintln!("warning: Governor /v1/report returned {}", r.status());
        }
        Err(e) => {
            eprintln!("warning: failed to POST bounce result to Governor: {e}");
        }
    }
    Ok(())
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

    // Workslop ROI — sum 12 minutes for every necrotic PR (bot-closeable).
    // Score-blocked PRs still require human review; only necrotic verdicts
    // represent truly reclaimed labor via automated bulk-close.
    let total_reclaimed_minutes =
        entries.iter().filter(|e| e.necrotic_flag.is_some()).count() as f64 * MINUTES_PER_TRIAGE;

    // Categorical billing: Critical Threats ($150) + Garbage Collection / Necrotic ($20).
    // PRs elevated purely by logic_clones_found contribute $0 — boilerplate clone
    // scores do not represent a billable security event.
    let critical_threats_count = entries.iter().filter(|e| is_critical_threat(e)).count() as u64;
    let gc_only_count = entries
        .iter()
        .filter(|e| e.necrotic_flag.is_some() && !is_critical_threat(e))
        .count() as u64;
    let total_actionable_intercepts = critical_threats_count + gc_only_count;

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
        total_reclaimed_minutes,
        total_actionable_intercepts,
        critical_threats_count,
        necrotic_indices,
        sloppiest_users,
    }
}

/// Returns a short, human-readable label for the dominant violation in a bounce entry.
///
/// Priority mirrors scoring weights: antipatterns (×50) > zombie symbols (×15) >
/// logic clones (×5) > zombie deps (informational).
fn primary_violation(e: &BounceLogEntry) -> &'static str {
    if !e.antipatterns.is_empty() {
        if e.antipatterns
            .iter()
            .any(|a| a.contains("Unverified Security Bump"))
        {
            return "Unverified Security Bump";
        }
        return "Language Antipattern";
    }
    if e.zombie_symbols_added > 0 {
        return "Zombie Symbol Reintroduction";
    }
    if e.logic_clones_found > 0 {
        return "Structural Clone";
    }
    if !e.zombie_deps.is_empty() {
        return "Zombie Dependency";
    }
    "Score Threshold"
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
        let gc_only = actionable.saturating_sub(critical);
        let hours = data.total_reclaimed_minutes / 60.0;
        // Categorical billing: Critical Threats ($150) + GC-only Necrotic ($20).
        let ci_compute_saved = critical * 150;
        let tei = critical * 150 + gc_only * 20;
        out.push_str("## Workslop: Maintainer Impact\n\n");
        out.push_str(
            "*[Workslop](https://builtin.com/articles/what-is-workslop): the triage tax \
             senior engineers pay reviewing AI-generated low-quality PRs.*\n\n",
        );
        out.push_str("| Metric | Value |\n");
        out.push_str("|--------|-------|\n");
        out.push_str(&format!(
            "| Actionable intercepts (Threats + Necrotic) | **{actionable}** |\n"
        ));
        out.push_str(&format!(
            "| Critical Threats Blocked (Swarm / Security) | **{critical}** |\n"
        ));
        out.push_str(&format!(
            "| Garbage Collection (Necrotic — bot-closeable) | **{gc_only}** |\n"
        ));
        out.push_str(&format!(
            "| **Total engineering time reclaimed** | **{hours:.1} hours** |\n"
        ));
        out.push_str(&format!(
            "| **CI & Review Compute Saved** | **${ci_compute_saved}** |\n"
        ));
        out.push_str(&format!("| **Total Economic Impact** | **${tei}** |\n"));
        out.push('\n');
        out.push_str(
            "> TEI = (Critical Threats × $150) + (Garbage Collection × $20). \
             Critical Threats: `security:` antipatterns or Swarm collisions. \
             GC: Necrotic (bot-closeable) PRs not already classified as Critical. \
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
    out.push_str("\n\\newpage\n\n");

    // ── Scoring Methodology (per-repo) ─────────────────────────────────────
    out.push_str("## Scoring Methodology\n\n");
    out.push_str("| Classification | Condition | Billing |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| Critical Threat | `security:` antipattern OR Swarm collision | $150 |\n");
    out.push_str("| Necrotic GC | Dead-code ghost (bot-automatable) | $20 |\n");
    out.push_str("| Boilerplate | Clone-only, no threat signal | $0 |\n");
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
        out.push_str("| Rank | PR | Author | Slop Score | Primary Violation |\n");
        out.push_str("|------|----|--------|------------|-------------------|\n");
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
            out.push_str(&format!(
                "| {} | {} | {} | **{}** | {} |\n",
                rank + 1,
                pr,
                author,
                e.slop_score,
                primary_violation(e),
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
                let desc_s = sanitize_latex_safe(desc);
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

    out
}

// ---------------------------------------------------------------------------
// JSON renderer
// ---------------------------------------------------------------------------

/// Renders the aggregated report as a structured JSON value.
pub fn render_json(data: &ReportData, repo_name: &str) -> serde_json::Value {
    let hours = data.total_reclaimed_minutes / 60.0;
    let necrotic_count = (data.total_reclaimed_minutes / MINUTES_PER_TRIAGE).round() as u64;
    let critical = data.critical_threats_count;
    let gc_only = data.total_actionable_intercepts.saturating_sub(critical);
    let ci_compute_saved = critical * 150;
    let tei = critical * 150 + gc_only * 20;
    serde_json::json!({
        "schema_version": "7.0.0",
        "repository": repo_name,
        "total_prs_analyzed": data.entries.len(),
        "workslop": {
            "actionable_intercepts": data.total_actionable_intercepts,
            "critical_threats_count": critical,
            "necrotic_count": necrotic_count,
            "total_reclaimed_minutes": (data.total_reclaimed_minutes * 10.0).round() / 10.0,
            "total_reclaimed_hours": (hours * 10.0).round() / 10.0,
            "ci_compute_saved_usd": ci_compute_saved,
            "total_economic_impact_usd": tei,
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
        "schema_version": "7.0.0",
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
    /// Total actionable intercepts: Critical Threats OR Garbage Collection (Necrotic).
    pub total_actionable_intercepts: u64,
    /// Count of Critical Threats in this repo (security: antipatterns or Swarm).
    pub critical_threats_count: u64,
    /// Top 10 sloppiest PRs: `(pr_number, score, state, author)`.
    pub top_sloppiest: Vec<(u64, u32, String, String)>,
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
    /// Total actionable intercepts: Critical Threats OR Garbage Collection (Necrotic).
    pub total_actionable_intercepts: u64,
    /// Count of Critical Threats across all repos (security: antipatterns or Swarm).
    pub critical_threats_count: u64,
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
    let repos_for_actionable: u64 = global_critical_threats + global_gc_only;

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
            let total_actionable_intercepts = critical_threats_count + gc_only_count;

            // Top 10 sloppiest PRs (descending score).
            let mut sorted_by_score: Vec<&BounceLogEntry> = entries.iter().collect();
            sorted_by_score.sort_by(|a, b| b.slop_score.cmp(&a.slop_score));
            let top_sloppiest: Vec<(u64, u32, String, String)> = sorted_by_score
                .iter()
                .filter(|e| e.slop_score > 0)
                .take(10)
                .map(|e| {
                    let pr_num = e.pr_number.unwrap_or(0);
                    let score = e.slop_score;
                    let state = e.state.to_string();
                    let author = e.author.as_deref().unwrap_or("unknown").to_owned();
                    (pr_num, score, state, author)
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

    GlobalReportData {
        repos: repo_stats,
        total_prs,
        total_slop_score,
        total_antipatterns,
        total_reclaimed_minutes,
        total_actionable_intercepts,
        critical_threats_count,
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
/// Format: `<repo_name padded>  ████████░░░░  N Critical  N Necrotic  N Clean`
///
/// `█` blocks represent Critical PRs (scaled), `░` blocks represent Necrotic PRs,
/// remaining width is implied Clean.  Total bar width is `width` characters.
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
    let bar: String = "█".repeat(crit_blocks) + &"░".repeat(nec_blocks);
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
    let gc_only = actionable.saturating_sub(critical);
    let tei = critical * 150 + gc_only * 20;
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
    out.push_str(&format!("| **Total Economic Impact** | ${tei} |\n"));
    out.push_str("\n---\n\n");
    out.push_str(
        "*Scores derived from AST antipattern detection across 23 grammars, structural \
         clone fingerprinting via MinHash LSH, and necrotic symbol hydration. No ML \
         inference. All analysis runs locally — no source code is transmitted.*\n\n",
    );
    out.push_str("\n\\newpage\n\n");

    // ── Page 2 — Threat Distribution ──────────────────────────────────────
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
    out.push_str("\n\\newpage\n\n");

    // ── Page 3 — Repository Breakdown table ───────────────────────────────
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
            .saturating_sub(repo.critical_threats_count);
        let repo_tei = repo.critical_threats_count * 150 + repo_gc_only * 20;
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
    out.push_str("\n\\newpage\n\n");

    // ── Page 4 — Top 10 Riskiest PRs ──────────────────────────────────────
    // Collect the top 10 entries with score > 50 across all repos.
    let mut top_prs: Vec<(&RepoStats, u64, u32, String, String)> = Vec::new();
    for repo in &data.repos {
        for (pr_num, score, _state, author) in &repo.top_sloppiest {
            if *score > 50 {
                let first_ap = String::new(); // will be filled below
                top_prs.push((repo, *pr_num, *score, author.clone(), first_ap));
            }
        }
    }
    top_prs.sort_by(|a, b| b.2.cmp(&a.2));
    top_prs.truncate(10);

    if !top_prs.is_empty() {
        out.push_str("## Top 10 Riskiest PRs\n\n");
        out.push_str("| PR | Repo | Author | Score | Threat Class | Antipattern |\n");
        out.push_str("|---|---|---|---|---|---|\n");
        for (repo, pr_num, score, author, _) in &top_prs {
            // Derive threat class from score and repo critical count heuristic.
            let threat_class = if repo.critical_threats_count > 0 {
                "Critical"
            } else {
                "Necrotic"
            };
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
        out.push_str("\n\\newpage\n\n");
    }

    // ── Scoring Methodology ────────────────────────────────────────────────
    out.push_str("## Scoring Methodology\n\n");
    out.push_str("| Classification | Condition | Billing |\n");
    out.push_str("|---|---|---|\n");
    out.push_str("| Critical Threat | `security:` antipattern OR Swarm collision | $150 |\n");
    out.push_str("| Necrotic GC | Dead-code ghost (bot-automatable) | $20 |\n");
    out.push_str("| Boilerplate | Clone-only, no threat signal | $0 |\n");
    out.push('\n');
    out.push_str(
        "Score formula: `(clones × 5) + (zombies × 10) + (antipattern_score) + \
         (comment_violations × 5) + (unlinked_pr × 20) + (hallucinated_fix × 100)`\n\n",
    );

    // ── Appendix: Full Audit Log ───────────────────────────────────────────
    out.push_str("## Appendix: Full Audit Log\n\n");

    // ── Per-repo dedicated pages ───────────────────────────────────────────
    // Each repo gets a \newpage (raw LaTeX — pandoc passes it through to pdflatex)
    // followed by Top 10 Sloppiest PRs and Top 10 Cleanest Contributors tables.
    for repo in &data.repos {
        out.push_str("\n\\newpage\n\n");
        out.push_str(&format!("## {}\n\n", sanitize_latex_safe(&repo.repo_name)));

        let repo_hours = repo.reclaimed_minutes / 60.0;
        let repo_gc_only_page = repo
            .total_actionable_intercepts
            .saturating_sub(repo.critical_threats_count);
        let repo_ci_saved_page = repo.critical_threats_count * 150;
        let repo_tei_page = repo.critical_threats_count * 150 + repo_gc_only_page * 20;
        out.push_str("| Metric | Value |\n");
        out.push_str("|--------|-------|\n");
        out.push_str(&format!("| PRs Analyzed | {} |\n", repo.pr_count));
        out.push_str(&format!(
            "| Total Slop Score | {} |\n",
            repo.total_slop_score
        ));
        out.push_str(&format!("| Time Reclaimed | {repo_hours:.1} hours |\n"));
        out.push_str(&format!(
            "| CI & Review Compute Saved | ${repo_ci_saved_page} |\n"
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
        out.push_str("### Top 10 Sloppiest PRs\n\n");
        out.push_str("```{=latex}\n\\small\n\\renewcommand{\\arraystretch}{1.2}\n```\n\n");
        if repo.top_sloppiest.is_empty() {
            out.push_str("*No flagged PRs in this repository.*\n\n");
        } else {
            out.push_str("| PR | Score | State | Author |\n");
            out.push_str("|----|------:|-------|--------|\n");
            for (pr_num, score, state, author) in &repo.top_sloppiest {
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
    let critical = data.critical_threats_count;
    let gc_only = data.total_actionable_intercepts.saturating_sub(critical);
    let ci_compute_saved = critical * 150;
    let tei = critical * 150 + gc_only * 20;
    serde_json::json!({
        "schema_version": "7.0.0",
        "gauntlet_root": gauntlet_root,
        "total_repos": data.repos.len(),
        "total_prs": data.total_prs,
        "total_slop_score": data.total_slop_score,
        "total_antipatterns": data.total_antipatterns,
        "workslop": {
            "actionable_intercepts": data.total_actionable_intercepts,
            "critical_threats_count": critical,
            "necrotic_count": necrotic_count,
            "total_reclaimed_minutes": (data.total_reclaimed_minutes * 10.0).round() / 10.0,
            "total_reclaimed_hours": (hours * 10.0).round() / 10.0,
            "ci_compute_saved_usd": ci_compute_saved,
            "total_economic_impact_usd": tei,
        },
        "repositories": data.repos.iter().map(|r| {
            let r_hours = r.reclaimed_minutes / 60.0;
            let r_gc_only = r.total_actionable_intercepts.saturating_sub(r.critical_threats_count);
            let r_ci_saved = r.critical_threats_count * 150;
            let r_tei = r.critical_threats_count * 150 + r_gc_only * 20;
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
                "ci_compute_saved_usd": r_ci_saved,
                "total_economic_impact_usd": r_tei,
            })
        }).collect::<Vec<_>>(),
    })
}

/// Groups identical strings, preserving first-occurrence order.
///
/// Returns `(text, count)` pairs. Strings that appear only once have count 1.
fn group_strings(items: &[String]) -> Vec<(&str, usize)> {
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
        let entry = make_entry(vec![], Some("SEMANTIC_NULL".to_string()));
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
