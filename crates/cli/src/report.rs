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
use std::collections::HashSet;
use std::path::Path;

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
    /// Composite slop score: dead×10 + clones×5 + zombies×15 + antipatterns×50.
    pub slop_score: u32,
    /// Number of added functions whose names already appear in the registry.
    pub dead_symbols_added: u32,
    /// Number of structural clone pairs within the patch.
    pub logic_clones_found: u32,
    /// Number of zombie symbol reintroductions (verbatim body match to dead symbol).
    pub zombie_symbols_added: u32,
    /// Number of language-specific antipatterns (hallucinated imports, vacuous unsafe, etc.).
    pub antipatterns_found: u32,
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
}

// ---------------------------------------------------------------------------
// ReportData
// ---------------------------------------------------------------------------

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
/// Ignores I/O errors — log persistence is best-effort; analysis still proceeds.
pub fn append_bounce_log(janitor_dir: &Path, entry: &BounceLogEntry) {
    let Ok(line) = serde_json::to_string(entry) else {
        return;
    };
    let log_path = janitor_dir.join("bounce_log.ndjson");
    let _ = std::fs::create_dir_all(janitor_dir);
    use std::io::Write as _;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(&log_path)
    {
        let _ = writeln!(f, "{}", line);
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

    ReportData {
        entries,
        slop_top_indices,
        clone_pairs,
        zombie_indices,
    }
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
            index.insert(PrDeltaSignature { min_hashes: arr });
            valid_indices.push(i);
        }
    }

    let mut pair_set: HashSet<(usize, usize)> = HashSet::new();

    for (lsh_i, &entry_i) in valid_indices.iter().enumerate() {
        let mut arr = [0u64; 64];
        arr.copy_from_slice(&entries[entry_i].min_hashes);
        let sig = PrDeltaSignature { min_hashes: arr };
        let candidates = index.query(&sig, threshold);
        for lsh_j in candidates {
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
    out.push_str(&format!("**Repository**: `{}`\n\n", repo_name));
    out.push_str(&format!(
        "**Total PRs analyzed**: {}\n\n",
        data.entries.len()
    ));
    out.push_str("---\n\n");

    // ── Section 1: Slop Top ────────────────────────────────────────────────
    out.push_str("## Slop Top 50 — PRs by Structural Debt Score\n\n");

    if data.slop_top_indices.is_empty() {
        out.push_str(
            "*No bounce data found. Run `janitor bounce --pr-number <N> --author <handle>` \
             to populate the log.*\n\n",
        );
    } else {
        out.push_str(
            "| Rank | PR | Author | Slop Score | Dead Added \
             | Clones | Zombie Syms | Antipatterns |\n",
        );
        out.push_str(
            "|------|----|--------|------------|------------\
             |--------|-------------|---------------|\n",
        );
        for (rank, &i) in data.slop_top_indices.iter().enumerate() {
            let e = &data.entries[i];
            let pr = e
                .pr_number
                .map(|n| format!("#{}", n))
                .unwrap_or_else(|| "-".to_owned());
            let author = e.author.as_deref().unwrap_or("-");
            out.push_str(&format!(
                "| {} | {} | {} | **{}** | {} | {} | {} | {} |\n",
                rank + 1,
                pr,
                author,
                e.slop_score,
                e.dead_symbols_added,
                e.logic_clones_found,
                e.zombie_symbols_added,
                e.antipatterns_found,
            ));
        }
    }
    out.push('\n');

    // ── Section 2: Structural Clones ───────────────────────────────────────
    out.push_str("## Structural Clones — Near-Duplicate PRs\n\n");
    out.push_str(
        "*Detected via 64-hash MinHash LSH (Jaccard ≥ 0.70). \
         Clone pairs share structurally identical diff content.*\n\n",
    );

    if data.clone_pairs.is_empty() {
        out.push_str("*No structural clones detected.*\n\n");
    } else {
        for (a, b) in &data.clone_pairs {
            let ea = &data.entries[*a];
            let eb = &data.entries[*b];
            let pr_a = ea
                .pr_number
                .map(|n| format!("#{}", n))
                .unwrap_or_else(|| format!("entry-{}", a));
            let pr_b = eb
                .pr_number
                .map(|n| format!("#{}", n))
                .unwrap_or_else(|| format!("entry-{}", b));
            let auth_a = ea.author.as_deref().unwrap_or("unknown");
            let auth_b = eb.author.as_deref().unwrap_or("unknown");
            out.push_str(&format!(
                "- **PR {}** ({}) is a structural clone of **PR {}** ({})\n",
                pr_a, auth_a, pr_b, auth_b
            ));
        }
    }
    out.push('\n');

    // ── Section 3: Zombie Dependencies ─────────────────────────────────────
    out.push_str("## Zombie Dependencies — Declared But Never Imported\n\n");
    out.push_str(
        "*Packages added to `Cargo.toml`, `package.json`, or `requirements.txt` \
         that do not appear in any source file import statement.*\n\n",
    );

    if data.zombie_indices.is_empty() {
        out.push_str("*No zombie dependencies detected.*\n\n");
    } else {
        for &i in &data.zombie_indices {
            let e = &data.entries[i];
            let pr = e
                .pr_number
                .map(|n| format!("#{}", n))
                .unwrap_or_else(|| format!("entry-{}", i));
            let author = e.author.as_deref().unwrap_or("unknown");
            out.push_str(&format!(
                "- **PR {}** ({}): `{}`\n",
                pr,
                author,
                e.zombie_deps.join("`, `")
            ));
        }
    }
    out.push('\n');

    out
}

// ---------------------------------------------------------------------------
// JSON renderer
// ---------------------------------------------------------------------------

/// Renders the aggregated report as a structured JSON value.
pub fn render_json(data: &ReportData, repo_name: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "6.6.0",
        "repository": repo_name,
        "total_prs_analyzed": data.entries.len(),
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
                "antipatterns_found": e.antipatterns_found,
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

/// Renders a scan-mode dead-symbol audit as GitHub-flavored Markdown.
///
/// Dead symbols are ranked by `byte_size` descending (largest removed = most
/// bytes reclaimed). The table is capped at `top_n` rows.
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
    out.push_str(&format!("**Repository**: `{}`\n\n", repo_name));
    out.push_str("---\n\n");

    // ── Summary table ──────────────────────────────────────────────────────
    out.push_str("## Summary\n\n");
    out.push_str("| Metric | Value |\n");
    out.push_str("|--------|-------|\n");
    out.push_str(&format!("| Total entities | {} |\n", total_entities));
    out.push_str(&format!(
        "| Dead symbols | {} ({:.1}%) |\n",
        dead.len(),
        dead_pct
    ));
    out.push_str(&format!(
        "| Reclaimable bytes | {} |\n",
        fmt_bytes(total_dead_bytes)
    ));
    out.push_str(&format!("| Orphan files | {} |\n", orphan_files.len()));
    out.push('\n');

    // ── Top N dead symbols by byte size ────────────────────────────────────
    out.push_str(&format!(
        "## Top {} Dead Symbols — Ranked by Byte Size\n\n",
        top_n
    ));

    if dead.is_empty() {
        out.push_str("*No dead symbols detected. Codebase is clean.*\n\n");
    } else {
        out.push_str("| Rank | Symbol | File | Line | Bytes |\n");
        out.push_str("|------|--------|------|------|-------|\n");
        for (rank, entry) in dead.iter().take(top_n).enumerate() {
            out.push_str(&format!(
                "| {} | `{}` | `{}` | {} | {} |\n",
                rank + 1,
                entry.qualified_name,
                entry.file_path,
                entry.start_line,
                entry.byte_size,
            ));
        }
        out.push('\n');
    }

    // ── Orphan files ───────────────────────────────────────────────────────
    out.push_str("## Orphan Files — Never Imported\n\n");
    if orphan_files.is_empty() {
        out.push_str("*No orphan files detected.*\n\n");
    } else {
        for path in orphan_files {
            out.push_str(&format!("- `{}`\n", path));
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
        "schema_version": "6.8.0",
        "repository": repo_name,
        "total_entities": total_entities,
        "dead_symbol_count": dead.len(),
        "dead_pct": (dead_pct * 10.0).round() / 10.0,
        "reclaimable_bytes": total_dead_bytes,
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
            let antipatterns_found: u32 = entries.iter().map(|e| e.antipatterns_found).sum();
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
            RepoStats {
                repo_name,
                pr_count,
                total_slop_score,
                antipatterns_found,
                dead_symbols_added,
                zombie_dep_prs,
                highest_pr,
                highest_score,
            }
        })
        .collect();

    // Sort by cumulative slop score descending — worst repos first.
    repo_stats.sort_by(|a, b| b.total_slop_score.cmp(&a.total_slop_score));

    let total_prs: usize = repo_stats.iter().map(|r| r.pr_count).sum();
    let total_slop_score: u64 = repo_stats.iter().map(|r| r.total_slop_score).sum();
    let total_antipatterns: u32 = repo_stats.iter().map(|r| r.antipatterns_found).sum();

    GlobalReportData {
        repos: repo_stats,
        total_prs,
        total_slop_score,
        total_antipatterns,
    }
}

/// Renders the global cross-repository report as GitHub-flavored Markdown.
pub fn render_global_markdown(data: &GlobalReportData, gauntlet_root: &str) -> String {
    let mut out = String::with_capacity(4096);

    out.push_str("# Janitor Global Intelligence Report\n\n");
    out.push_str(
        "*Cross-repository structural debt aggregation. \
         Generated by The Janitor: Deterministic Structural Analysis.*\n\n",
    );
    out.push_str(&format!("**Gauntlet root**: `{}`\n\n", gauntlet_root));
    out.push_str("---\n\n");

    // ── Global summary table ───────────────────────────────────────────────
    out.push_str("## Global Summary\n\n");
    out.push_str("| Metric | Value |\n");
    out.push_str("|--------|-------|\n");
    out.push_str(&format!(
        "| Repositories analyzed | {} |\n",
        data.repos.len()
    ));
    out.push_str(&format!("| Total PRs analyzed | {} |\n", data.total_prs));
    out.push_str(&format!(
        "| Total slop score blocked | {} |\n",
        data.total_slop_score
    ));
    out.push_str(&format!(
        "| Total antipatterns detected | {} |\n",
        data.total_antipatterns
    ));
    out.push('\n');

    // ── Per-repo breakdown ─────────────────────────────────────────────────
    out.push_str("## Repository Breakdown\n\n");
    out.push_str(
        "| Repository | PRs | Total Slop | Antipatterns \
         | Dead Added | Zombie Dep PRs | Worst PR |\n",
    );
    out.push_str(
        "|------------|-----|-----------|--------------|------------|----------------|----------|\n",
    );
    for repo in &data.repos {
        let worst = repo
            .highest_pr
            .map(|n| format!("#{} (score {})", n, repo.highest_score))
            .unwrap_or_else(|| "-".to_owned());
        out.push_str(&format!(
            "| `{}` | {} | **{}** | {} | {} | {} | {} |\n",
            repo.repo_name,
            repo.pr_count,
            repo.total_slop_score,
            repo.antipatterns_found,
            repo.dead_symbols_added,
            repo.zombie_dep_prs,
            worst,
        ));
    }
    out.push('\n');

    out
}

/// Renders the global cross-repository report as structured JSON.
pub fn render_global_json(data: &GlobalReportData, gauntlet_root: &str) -> serde_json::Value {
    serde_json::json!({
        "schema_version": "6.8.0",
        "gauntlet_root": gauntlet_root,
        "total_repos": data.repos.len(),
        "total_prs": data.total_prs,
        "total_slop_score": data.total_slop_score,
        "total_antipatterns": data.total_antipatterns,
        "repositories": data.repos.iter().map(|r| {
            serde_json::json!({
                "repo_name": r.repo_name,
                "pr_count": r.pr_count,
                "total_slop_score": r.total_slop_score,
                "antipatterns_found": r.antipatterns_found,
                "dead_symbols_added": r.dead_symbols_added,
                "zombie_dep_prs": r.zombie_dep_prs,
                "highest_pr": r.highest_pr,
                "highest_score": r.highest_score,
            })
        }).collect::<Vec<_>>(),
    })
}

/// Format byte count as human-readable (KB/MB).
fn fmt_bytes(b: u64) -> String {
    if b >= 1_048_576 {
        format!("{:.1} MB", b as f64 / 1_048_576.0)
    } else if b >= 1024 {
        format!("{:.1} KB", b as f64 / 1024.0)
    } else {
        format!("{} B", b)
    }
}
