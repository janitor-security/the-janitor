//! CSV export for bounce log and static-scan data.
//!
//! Primary path: reads `.janitor/bounce_log.ndjson` and streams each entry as
//! a CSV row, suitable for loading into Excel, Google Sheets, or pandas.
//!
//! Static-scan fallback: when no bounce log exists, loads `.janitor/symbols.rkyv`
//! and emits one CSV row per dead symbol (PR-specific columns left empty).
//!
//! ## Columns (16 total)
//!
//! | # | Column | Notes |
//! |---|--------|-------|
//! | 1 | `PR_Number` | Empty string when absent |
//! | 2 | `Author` | Empty string when absent |
//! | 3 | `Score` | Composite weighted slop score |
//! | 4 | `Threat_Class` | `"Critical"` \| `"Necrotic"` \| `"StructuralSlop"` \| `"Boilerplate"` |
//! | 5 | `Unlinked_PR` | `TRUE` if no issue link detected, else `FALSE` |
//! | 6 | `Logic_Clones` | SimHash clone pairs within the patch |
//! | 7 | `Antipattern_IDs` | Pipe-delimited structured rule labels only (e.g. `security:compiled_payload_anomaly\|antipattern:ncd_anomaly`) |
//! | 8 | `Collided_PRs` | Pipe-delimited collided PR numbers; empty if none |
//! | 9 | `Time_Saved_Hours` | necrotic_count × 12 min ÷ 60; 12 min = conservative senior-engineer triage estimate per Workslop research 2026 |
//! | 10 | `Operational_Savings_USD` | $150 if Critical Threat (security: / Swarm), $20 if Necrotic GC, else $0 |
//! | 11 | `Timestamp` | ISO 8601 UTC |
//! | 12 | `PR_State` | `open`, `merged`, or `closed` |
//! | 13 | `Is_Bot` | `TRUE` when author is in `trusted_bot_authors` (janitor.toml) |
//! | 14 | `Repo_Slug` | GitHub `owner/repo` slug |
//! | 15 | `Commit_SHA` | Git commit SHA of the PR head at bounce time; empty when unavailable |
//! | 16 | `Policy_Hash` | BLAKE3 hex digest of `janitor.toml` at bounce time; empty when no manifest present |

use anyhow::Result;
use std::io::Write as _;
use std::path::Path;

/// Sanitize a free-text field for safe CSV embedding.
///
/// The `csv` crate wraps fields containing newlines in RFC 4180 double-quotes,
/// but many downstream consumers (Excel, pandas `read_csv` without `quoting`
/// option, Looker) treat in-field newlines as row breaks and corrupt the grid.
/// This function normalises all newline sequences to a single space so every
/// cell occupies exactly one logical row.
#[inline]
fn csv_sanitize(s: &str) -> String {
    // Replace every CR and LF character with a space so free-text fields never
    // introduce logical row breaks when the CSV is opened in Excel, pandas, or
    // Looker.  A pattern array in a single `replace` call satisfies clippy's
    // `collapsible_str_replace` lint while handling both bare CR, bare LF, and
    // CRLF sequences (the latter becomes two spaces, which is acceptable for
    // display purposes).
    s.replace(['\r', '\n'], " ")
}

/// UTF-8 Byte Order Mark — prepended to every CSV file so that Microsoft Excel
/// and other enterprise spreadsheet tools auto-detect UTF-8 encoding rather than
/// falling back to the system code page (which renders em-dashes and similar
/// multi-byte characters as `â€"` or similar mojibake).
const UTF8_BOM: &[u8] = b"\xEF\xBB\xBF";

/// Open `path` for writing, write the UTF-8 BOM, and return a `csv::Writer`
/// wrapping the file.  Returns an `anyhow::Error` on any I/O failure.
fn bom_csv_writer(path: &Path) -> Result<csv::Writer<std::io::BufWriter<std::fs::File>>> {
    let file = std::fs::File::create(path)
        .map_err(|e| anyhow::anyhow!("Cannot create CSV file {}: {}", path.display(), e))?;
    let mut buf = std::io::BufWriter::new(file);
    buf.write_all(UTF8_BOM)
        .map_err(|e| anyhow::anyhow!("Writing UTF-8 BOM to {}: {}", path.display(), e))?;
    Ok(csv::Writer::from_writer(buf))
}

/// CSV header row — 16 columns.
const CSV_HEADER: [&str; 16] = [
    "PR_Number",
    "Author",
    "Score",
    "Threat_Class",
    "Unlinked_PR",
    "Logic_Clones",
    "Antipattern_IDs",
    "Collided_PRs",
    "Time_Saved_Hours",
    "Operational_Savings_USD",
    "Timestamp",
    "PR_State",
    "Is_Bot",
    "Repo_Slug",
    "Commit_SHA",
    "Policy_Hash",
];

/// Derive the `Threat_Class` string for a bounce log entry.
///
/// - `"Critical"` — `is_critical_threat` is true (security antipattern or Swarm collision); $150.
/// - `"Necrotic"` — `necrotic_flag` is set, OR zombie deps detected (not critical); $20.
/// - `"StructuralSlop"` — `slop_score > 0`, no critical or necrotic signal; $20.
///   Includes PRs whose score is raised solely by version silos — their
///   `slop_score` is non-zero (`version_silo_details.len() × 20`), which is
///   sufficient to land here without any necrotic or critical signal.
/// - `"Boilerplate"` — `slop_score == 0`, no threat signal; $0.
///
/// Version silos are NOT "Necrotic": they represent architectural debt that
/// requires a human dependency-graph review, not an automated bot-close.  A
/// silo PR has `slop_score >= 20` and therefore can never be `"Boilerplate"`.
fn threat_class(entry: &crate::report::BounceLogEntry) -> &'static str {
    if crate::report::is_critical_threat(entry) {
        "Critical"
    } else if entry.necrotic_flag.is_some() || !entry.zombie_deps.is_empty() {
        "Necrotic"
    } else if entry.slop_score > 0 {
        "StructuralSlop"
    } else {
        "Boilerplate"
    }
}

/// Build the `Antipattern_IDs` field: pipe-delimited structured rule labels.
///
/// When `necrotic_flag` is set, a `backlog:<FLAG>` label is prepended so that
/// Necrotic rows always carry at least one machine-readable identifier even when
/// no language-specific antipattern fired (e.g. pure zombie-dep or dead-symbol GC).
///
/// The structured labels are already in the form `security:compiled_payload_anomaly`
/// or `antipattern:ncd_anomaly`; human-readable text is not included.
fn antipattern_ids(entry: &crate::report::BounceLogEntry) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(flag) = entry.necrotic_flag.as_deref() {
        parts.push(format!("backlog:{flag}"));
    }
    if !entry.zombie_deps.is_empty() {
        parts.push("architecture:zombie_dependency".to_owned());
    }
    // NOTE: version silos are NOT pushed here because the silo detector already
    // injects `architecture:version_silo (...)` into `entry.antipatterns` via
    // `score.antipattern_details`.  Pushing from `entry.version_silos` as well
    // would produce a duplicate `(x2)` entry after `group_strings` collapses.
    parts.extend(entry.antipatterns.iter().cloned());
    // Collapse repeated labels: [A, A, A, B] → "A (x3)|B".
    // Identical structured IDs (e.g. three antipattern:ncd_anomaly hits from
    // the same patch) are merged so the CSV cell stays readable in Excel/pandas.
    let grouped = crate::report::group_strings(&parts)
        .into_iter()
        .map(|(label, count)| {
            if count > 1 {
                format!("{label} (x{count})")
            } else {
                label.to_owned()
            }
        })
        .collect::<Vec<_>>();
    csv_sanitize(&grouped.join("|"))
}

/// Build the `Collided_PRs` field: pipe-delimited PR numbers.
fn collided_prs(entry: &crate::report::BounceLogEntry) -> String {
    if entry.collided_pr_numbers.is_empty() {
        String::new()
    } else {
        entry
            .collided_pr_numbers
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>()
            .join("|")
    }
}

/// Write one CSV row for a bounce log entry.
fn write_entry_row(
    wtr: &mut csv::Writer<impl std::io::Write>,
    entry: &crate::report::BounceLogEntry,
) -> Result<()> {
    let critical = crate::report::is_critical_threat(entry);
    // Necrotic: pruner-flagged dead-code OR zombie dep — bot-automatable closes.
    // Version silos are NOT Necrotic: they require human dependency-graph review,
    // not an automated bulk-close, and they carry slop_score > 0 which places them
    // in the StructuralSlop tier instead.
    let necrotic = entry.necrotic_flag.is_some() || !entry.zombie_deps.is_empty();
    // Structural Slop: slop_score > 0 with no critical or necrotic signal.
    // Includes version-silo PRs (slop_score = version_silo_details.len() × 20).
    let structural_slop = !critical && !necrotic && entry.slop_score > 0;

    // Time_Saved_Hours: necrotic_count × 12 min ÷ 60.
    // Only necrotic (bot-automatable) PRs contribute reclaimed triage minutes.
    // Structural Slop still requires human review — no time credit.
    let time_saved_h: f64 = if necrotic { 12.0 / 60.0 } else { 0.0 };

    // Categorical billing: Critical ($150) > Necrotic GC ($20) > Structural Slop ($20) > $0.
    let savings_usd: u32 = if critical {
        150
    } else if necrotic || structural_slop {
        20
    } else {
        0
    };

    let pr_num_str = entry.pr_number.map(|n| n.to_string()).unwrap_or_default();
    let author_str = csv_sanitize(entry.author.as_deref().unwrap_or(""));
    let score_str = entry.slop_score.to_string();
    let tc = threat_class(entry);
    let unlinked_str = if entry.unlinked_pr > 0 {
        "TRUE"
    } else {
        "FALSE"
    };
    let clones_str = entry.logic_clones_found.min(50).to_string();
    let ap_ids = antipattern_ids(entry);
    let collided = collided_prs(entry);
    let time_str = format!("{time_saved_h:.4}");
    let savings_str = savings_usd.to_string();
    let state_str = entry.state.to_string();
    let is_bot_str = if entry.is_bot { "TRUE" } else { "FALSE" };

    wtr.write_record([
        pr_num_str.as_str(),
        author_str.as_str(),
        score_str.as_str(),
        tc,
        unlinked_str,
        clones_str.as_str(),
        ap_ids.as_str(),
        collided.as_str(),
        time_str.as_str(),
        savings_str.as_str(),
        entry.timestamp.as_str(),
        state_str.as_str(),
        is_bot_str,
        entry.repo_slug.as_str(),
        entry.commit_sha.as_str(),
        entry.policy_hash.as_str(),
    ])?;
    Ok(())
}

/// Export all bounce logs found under `gauntlet_root` to a single aggregate CSV file.
///
/// Discovers every `<gauntlet_root>/*/` sub-directory containing a
/// `.janitor/bounce_log.ndjson` and concatenates their entries into `out`.
/// The `Repo_Slug` column distinguishes rows from different repositories.
///
/// Mirrors the per-repo schema of [`cmd_export`] exactly; the output can be
/// loaded into the same Excel/pandas pipelines as a single-repo CSV.
pub fn cmd_export_global(gauntlet_root: &Path, out: &Path) -> Result<()> {
    use crate::report::discover_bounce_logs;

    let repo_logs = discover_bounce_logs(gauntlet_root);
    if repo_logs.is_empty() {
        anyhow::bail!(
            "No bounce logs found under `{}`. \
             Run `janitor bounce` in each repo to populate logs.",
            gauntlet_root.display()
        );
    }

    let total_entries: usize = repo_logs.iter().map(|(_, v)| v.len()).sum();
    eprintln!(
        "Aggregating {} entries across {} repos → {}",
        total_entries,
        repo_logs.len(),
        out.display()
    );

    let mut wtr = bom_csv_writer(out)?;
    wtr.write_record(CSV_HEADER)?;

    for (_repo_name, entries) in repo_logs {
        for entry in &entries {
            write_entry_row(&mut wtr, entry)?;
        }
    }

    wtr.flush()?;
    println!(
        "Exported {total_entries} entries (global) → {}",
        out.display()
    );
    Ok(())
}

/// Export the bounce log at `<repo>/.janitor/bounce_log.ndjson` to a CSV file.
///
/// Creates or overwrites `out`.  When the bounce log is absent or empty, falls
/// back to loading `.janitor/symbols.rkyv` and exporting one row per dead symbol.
/// PR-specific columns (`PR_Number`, `Author`) are left empty in static-scan rows.
pub fn cmd_export(repo: &Path, out: &Path) -> Result<()> {
    let janitor_dir = repo.join(".janitor");
    let entries = crate::report::load_bounce_log(&janitor_dir);

    if entries.is_empty() {
        return export_static_scan(&janitor_dir, out);
    }

    let mut wtr = bom_csv_writer(out)?;
    wtr.write_record(CSV_HEADER)?;

    for entry in &entries {
        write_entry_row(&mut wtr, entry)?;
    }

    wtr.flush()?;
    println!("Exported {} entries → {}", entries.len(), out.display());
    Ok(())
}

/// Static-scan fallback: load `.janitor/symbols.rkyv` and emit one CSV row per
/// dead symbol.
///
/// Dead symbols are ranked by byte size descending (largest first).
/// PR-specific columns (`PR_Number`, `Author`) are left empty.
/// `Score` is set to `byte_size / 10` — mirroring the dead-symbol scoring weight
/// used in bounce mode — so spreadsheet consumers can rank by the same metric.
fn export_static_scan(janitor_dir: &Path, out: &Path) -> Result<()> {
    use common::registry::{MappedRegistry, SymbolRegistry};

    let rkyv_path = janitor_dir.join("symbols.rkyv");
    if !rkyv_path.exists() {
        anyhow::bail!(
            "No bounce log or symbol registry found under {}.\n\
             Run `janitor scan <path>` or `janitor bounce` first to populate data.",
            janitor_dir.display()
        );
    }

    eprintln!(
        "No bounce log found — falling back to static scan registry ({})",
        rkyv_path.display()
    );

    let mapped = MappedRegistry::open(&rkyv_path)
        .map_err(|e| anyhow::anyhow!("Failed to open symbols.rkyv: {e}"))?;
    let registry: SymbolRegistry =
        rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
            .map_err(|e| anyhow::anyhow!("Failed to deserialize symbols.rkyv: {e}"))?;

    // Collect dead symbols (no protection reason) sorted by byte size descending.
    let mut dead: Vec<&common::registry::SymbolEntry> = registry
        .entries
        .iter()
        .filter(|e| e.protected_by.is_none())
        .collect();
    dead.sort_by(|a, b| {
        b.end_byte
            .saturating_sub(b.start_byte)
            .cmp(&a.end_byte.saturating_sub(a.start_byte))
    });

    let mut wtr = bom_csv_writer(out)?;
    wtr.write_record(CSV_HEADER)?;

    let timestamp = crate::utc_now_iso8601();

    for entry in &dead {
        let byte_size = entry.end_byte.saturating_sub(entry.start_byte);
        // Score proxy: byte size in units of 10 B (informational — dead symbols
        // no longer contribute to the bounce score formula).
        let score = byte_size / 10;
        let score_str = score.to_string();
        let violation = csv_sanitize(&format!(
            "Dead Symbol: {} ({}:{})",
            entry.qualified_name, entry.file_path, entry.start_line
        ));

        wtr.write_record([
            "", // PR_Number — N/A for static scan
            "", // Author — N/A for static scan
            score_str.as_str(),
            "Boilerplate",      // Threat_Class — N/A, default to Boilerplate
            "FALSE",            // Unlinked_PR
            "0",                // Logic_Clones
            violation.as_str(), // Antipattern_IDs — use dead symbol description
            "",                 // Collided_PRs
            "0.0000",           // Time_Saved_Hours
            "0",                // Operational_Savings_USD
            timestamp.as_str(),
            "open",  // PR_State — N/A for static scan
            "FALSE", // Is_Bot — N/A for static scan
            "",      // Repo_Slug — N/A for static scan
            "",      // Commit_SHA — N/A for static scan
            "",      // Policy_Hash — N/A for static scan
        ])?;
    }

    wtr.flush()?;
    println!(
        "Exported {} dead symbols (static scan) → {}",
        dead.len(),
        out.display()
    );
    Ok(())
}
