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

use serde::{Deserialize, Serialize};
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

/// Loaded hourly engineering cost assumed for ROI calculations (USD).
const HOURLY_COST_USD: f64 = 100.0;

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
    /// Total engineering minutes reclaimed: actionable PR count × [`MINUTES_PER_TRIAGE`].
    ///
    /// An "actionable" PR is one that meets at least one of:
    /// - `slop_score >= 100` (Blocked)
    /// - `zombie_symbols_added > 0` (Shotgun re-injection)
    /// - an antipattern description containing "Unverified Security Bump"
    /// - `necrotic_flag.is_some()` (Garbage Collection verdict)
    pub total_reclaimed_minutes: f64,
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

    // Workslop ROI — sum 12 minutes for every actionable intercept.
    let total_reclaimed_minutes =
        entries.iter().filter(|e| is_actionable(e)).count() as f64 * MINUTES_PER_TRIAGE;

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
        necrotic_indices,
        sloppiest_users,
    }
}

/// Returns `true` if the entry represents a PR that required active triage.
///
/// Criteria (any one sufficient):
/// - **Blocked**: `slop_score >= 100` (gate threshold reached)
/// - **Shotgun**: `zombie_symbols_added > 0` — re-introduction of previously dead symbols;
///   contributes ×15 to the score and signals adversarial or AI-generated content
/// - **Unverified Security Bump**: an antipattern description contains "Unverified Security Bump" —
///   PR body claims a security fix but diff only touches non-code files
///
/// Note: `zombie_deps` (manifest-level zombie dependencies) is intentionally excluded.
/// It is informational metadata that may reflect false positives from base-manifest packages
/// (e.g., shared toolchain deps that appear in every PR diff).  Score-affecting zombie dep
/// violations are captured by the `slop_score >= 100` branch once their ×15 contributions
/// push the PR over the gate.
fn is_actionable(e: &BounceLogEntry) -> bool {
    e.slop_score >= 100
        || e.zombie_symbols_added > 0
        || e.antipatterns
            .iter()
            .any(|a| a.contains("Unverified Security Bump"))
        || e.necrotic_flag.is_some()
}

/// Returns a short, human-readable label for the dominant violation in a bounce entry.
///
/// Priority mirrors scoring weights: antipatterns (×50) > zombie symbols (×15) >
/// dead symbols (×10) > logic clones (×5) > zombie deps (informational).
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
    if e.dead_symbols_added > 0 {
        return "Dead Symbol Added";
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
    out.push_str(&format!("**Repository**: `{}`\n\n", html_escape(repo_name)));
    out.push_str(&format!(
        "**Total PRs analyzed**: {}\n\n",
        data.entries.len()
    ));
    out.push_str("---\n\n");

    // ── Workslop: Maintainer Impact ────────────────────────────────────────
    {
        let actionable = (data.total_reclaimed_minutes / MINUTES_PER_TRIAGE).round() as u64;
        let hours = data.total_reclaimed_minutes / 60.0;
        let savings = hours * HOURLY_COST_USD;
        out.push_str("## Workslop: Maintainer Impact\n\n");
        out.push_str(
            "*[Workslop](https://builtin.com/articles/what-is-workslop): the triage tax \
             senior engineers pay reviewing AI-generated low-quality PRs.*\n\n",
        );
        out.push_str("| Metric | Value |\n");
        out.push_str("|--------|-------|\n");
        out.push_str(&format!(
            "| Actionable intercepts (Blocked / Zombie / Hallucination / Necrotic) | **{actionable}** |\n"
        ));
        out.push_str(&format!(
            "| **Total engineering time reclaimed** | **{hours:.1} hours** |\n"
        ));
        out.push_str(&format!(
            "| **Estimated operational savings** | **${savings:.0}** |\n"
        ));
        out.push('\n');
        out.push_str(
            "> Based on **12-minute industry triage baseline** × **$100/hr** loaded engineering cost. \
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
                html_escape(&trunc_author(&u.author, 20)),
                u.total_slop_score,
                u.total_pr_count,
                u.clean_pr_count,
            ));
        }
        out.push('\n');
    }

    out.push_str("---\n\n");

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
            let author = html_escape(&trunc_author(e.author.as_deref().unwrap_or("-"), 20));
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
            let author = html_escape(e.author.as_deref().unwrap_or("-"));
            out.push_str(&format!("- **PR {pr}** (`{author}`):\n"));
            for (desc, count) in group_strings(&e.antipatterns) {
                if count > 1 {
                    out.push_str(&format!("  - {} (x{})\n", html_escape(desc), count));
                } else {
                    out.push_str(&format!("  - {}\n", html_escape(desc)));
                }
            }
            for (desc, count) in group_strings(&e.comment_violations) {
                if count > 1 {
                    out.push_str(&format!(
                        "  - [violation] {} (x{})\n",
                        html_escape(desc),
                        count
                    ));
                } else {
                    out.push_str(&format!("  - [violation] {}\n", html_escape(desc)));
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
            let author = html_escape(&trunc_author(e.author.as_deref().unwrap_or("-"), 20));
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
            let auth_a = html_escape(&trunc_author(ea.author.as_deref().unwrap_or("unknown"), 20));
            let auth_b = html_escape(&trunc_author(eb.author.as_deref().unwrap_or("unknown"), 20));
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
            let author = html_escape(e.author.as_deref().unwrap_or("unknown"));
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
    serde_json::json!({
        "schema_version": "7.0.0",
        "repository": repo_name,
        "total_prs_analyzed": data.entries.len(),
        "workslop": {
            "actionable_intercepts": (data.total_reclaimed_minutes / MINUTES_PER_TRIAGE).round() as u64,
            "total_reclaimed_minutes": (data.total_reclaimed_minutes * 10.0).round() / 10.0,
            "total_reclaimed_hours": (hours * 10.0).round() / 10.0,
            "estimated_savings_usd": (hours * HOURLY_COST_USD).round() as u64,
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
    out.push_str(&format!("**Repository**: `{}`\n\n", html_escape(repo_name)));
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
    let mut repo_stats: Vec<RepoStats> = repos
        .into_iter()
        .map(|(repo_name, entries)| {
            let pr_count = entries.len();
            let total_slop_score: u64 = entries.iter().map(|e| e.slop_score as u64).sum();
            let antipatterns_found: u32 = entries.iter().map(|e| e.antipatterns.len() as u32).sum();
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
            let reclaimed_minutes =
                entries.iter().filter(|e| is_actionable(e)).count() as f64 * MINUTES_PER_TRIAGE;

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

    GlobalReportData {
        repos: repo_stats,
        total_prs,
        total_slop_score,
        total_antipatterns,
        total_reclaimed_minutes,
    }
}

/// Renders the global cross-repository report as GitHub-flavored Markdown.
pub fn render_global_markdown(data: &GlobalReportData, _gauntlet_root: &str) -> String {
    let mut out = String::with_capacity(8192);

    // Compact the global summary page: tighter paragraph skip + table row height.
    out.push_str("```{=latex}\n\\setlength{\\parskip}{2pt plus 1pt minus 1pt}\n\\renewcommand{\\arraystretch}{0.9}\n```\n\n");
    out.push_str("# Janitor Global Intelligence Report\n\n");
    out.push_str(
        "*Cross-repository structural debt aggregation. \
         Generated by The Janitor: Deterministic Structural Analysis.*\n\n",
    );
    // ── Global summary table (ROI + coverage metrics) ─────────────────────
    {
        let actionable = (data.total_reclaimed_minutes / MINUTES_PER_TRIAGE).round() as u64;
        let hours = data.total_reclaimed_minutes / 60.0;
        let savings = hours * HOURLY_COST_USD;
        out.push_str("## Global Summary\n\n");
        out.push_str("| Metric | Value |\n");
        out.push_str("|--------|-------|\n");
        out.push_str(&format!(
            "| Repositories analyzed | {} |\n",
            data.repos.len()
        ));
        out.push_str(&format!("| Total PRs analyzed | {} |\n", data.total_prs));
        out.push_str(&format!(
            "| Total slop score | {} |\n",
            data.total_slop_score
        ));
        out.push_str(&format!(
            "| Total antipatterns | {} |\n",
            data.total_antipatterns
        ));
        out.push_str(&format!("| Actionable intercepts | **{actionable}** |\n"));
        out.push_str(&format!(
            "| **Engineering time reclaimed** | **{hours:.1} hours** |\n"
        ));
        out.push_str(&format!("| **Estimated savings** | **${savings:.0}** |\n"));
        out.push('\n');
    }

    // ── Per-repo summary breakdown ─────────────────────────────────────────
    out.push_str("## Repository Breakdown\n\n");
    out.push_str(
        "```{=latex}\n\\small\n\\setlength{\\tabcolsep}{4pt}\n\\renewcommand{\\arraystretch}{1.0}\n\\setcounter{LTchunksize}{100}\n```\n\n",
    );
    out.push_str("| Repository | PRs | Total Slop | Antipatterns | Zombies | Worst PR |\n");
    out.push_str("|------------|-----|-----------|--------------|---------|----------|\n");
    for repo in &data.repos {
        let worst = repo
            .highest_pr
            .map(|n| format!("#{n} ({score})", score = repo.highest_score))
            .unwrap_or_else(|| "-".to_owned());
        out.push_str(&format!(
            "| `{}` | {} | **{}** | {} | {} | {} |\n",
            repo.repo_name,
            repo.pr_count,
            repo.total_slop_score,
            repo.antipatterns_found,
            repo.zombie_dep_prs,
            worst,
        ));
    }
    out.push('\n');

    // ── Per-repo dedicated pages ───────────────────────────────────────────
    // Each repo gets a \newpage (raw LaTeX — pandoc passes it through to pdflatex)
    // followed by Top 10 Sloppiest PRs and Top 10 Cleanest Contributors tables.
    for repo in &data.repos {
        out.push_str("\n\\newpage\n\n");
        out.push_str(&format!("## {}\n\n", repo.repo_name));

        let repo_hours = repo.reclaimed_minutes / 60.0;
        let repo_savings = repo_hours * HOURLY_COST_USD;
        out.push_str("| Metric | Value |\n");
        out.push_str("|--------|-------|\n");
        out.push_str(&format!("| PRs Analyzed | {} |\n", repo.pr_count));
        out.push_str(&format!(
            "| Total Slop Score | {} |\n",
            repo.total_slop_score
        ));
        out.push_str(&format!("| Time Reclaimed | {repo_hours:.1} hours |\n"));
        out.push_str(&format!("| Operational Savings | ${repo_savings:.0} |\n"));
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
                let auth_display: &str = if author.len() > 22 {
                    &author[..22]
                } else {
                    author.as_str()
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
                let auth_display: &str = if author.len() > 28 {
                    &author[..28]
                } else {
                    author.as_str()
                };
                out.push_str(&format!("| {auth_display} | {count} |\n"));
            }
            out.push('\n');
        }
    }

    out
}

/// Renders the global cross-repository report as structured JSON.
pub fn render_global_json(data: &GlobalReportData, gauntlet_root: &str) -> serde_json::Value {
    let hours = data.total_reclaimed_minutes / 60.0;
    serde_json::json!({
        "schema_version": "7.0.0",
        "gauntlet_root": gauntlet_root,
        "total_repos": data.repos.len(),
        "total_prs": data.total_prs,
        "total_slop_score": data.total_slop_score,
        "total_antipatterns": data.total_antipatterns,
        "workslop": {
            "actionable_intercepts": (data.total_reclaimed_minutes / MINUTES_PER_TRIAGE).round() as u64,
            "total_reclaimed_minutes": (data.total_reclaimed_minutes * 10.0).round() / 10.0,
            "total_reclaimed_hours": (hours * 10.0).round() / 10.0,
            "estimated_savings_usd": (hours * HOURLY_COST_USD).round() as u64,
        },
        "repositories": data.repos.iter().map(|r| {
            let r_hours = r.reclaimed_minutes / 60.0;
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
