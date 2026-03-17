//! CSV export for bounce log and static-scan data.
//!
//! Primary path: reads `.janitor/bounce_log.ndjson` and streams each entry as
//! a CSV row, suitable for loading into Excel, Google Sheets, or pandas.
//!
//! Static-scan fallback: when no bounce log exists, loads `.janitor/symbols.rkyv`
//! and emits one CSV row per dead symbol (PR-specific columns left empty).
//!
//! ## Columns (17 total)
//!
//! | # | Column | Notes |
//! |---|--------|-------|
//! | 1 | `PR_Number` | Empty string when absent |
//! | 2 | `Author` | Empty string when absent |
//! | 3 | `Score` | Composite weighted slop score |
//! | 4 | `Mesa_Triggered` | Reserved for SaaS; always `FALSE` in CLI |
//! | 5 | `Trust_Delta` | Reserved for SaaS; always `0` in CLI |
//! | 6 | `Unlinked_PR` | `1` if no issue link detected, else `0` |
//! | 7 | `Dead_Code_Count` | Functions re-added from the dead-symbol registry |
//! | 8 | `Logic_Clones` | SimHash clone pairs within the patch |
//! | 9 | `Zombie_Syms` | Verbatim dead-body reintroductions |
//! | 10 | `Zombie_Deps` | Manifest-declared deps never imported; joined with `\|` |
//! | 11 | `Violation_Reasons` | Human-readable audit trail; all flags joined with `\|` |
//! | 12 | `Time_Saved_Hours` | 0.2 h per actionable intercept |
//! | 13 | `Operational_Savings_USD` | Time × $100/hr loaded engineering cost |
//! | 14 | `Timestamp` | ISO 8601 UTC |
//! | 15 | `PR_State` | `open`, `merged`, or `closed` |
//! | 16 | `Is_Bot` | `TRUE` when author is in `trusted_bot_authors` (janitor.toml) |
//! | 17 | `Repo_Slug` | GitHub `owner/repo` slug |

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

    wtr.write_record([
        "PR_Number",
        "Author",
        "Score",
        "Mesa_Triggered",
        "Trust_Delta",
        "Unlinked_PR",
        "Dead_Code_Count",
        "Logic_Clones",
        "Zombie_Syms",
        "Zombie_Deps",
        "Violation_Reasons",
        "Time_Saved_Hours",
        "Operational_Savings_USD",
        "Timestamp",
        "PR_State",
        "Is_Bot",
        "Repo_Slug",
    ])?;

    const MINUTES_PER_TRIAGE: f64 = 12.0;
    const HOURLY_COST_USD: f64 = 100.0;

    for (_repo_name, entries) in repo_logs {
        for entry in &entries {
            let actionable = entry.slop_score >= 100
                || entry.zombie_symbols_added > 0
                || entry
                    .antipatterns
                    .iter()
                    .any(|a| a.contains("Unverified Security Bump"));

            let time_saved_h = if actionable {
                MINUTES_PER_TRIAGE / 60.0
            } else {
                0.0_f64
            };
            let savings_usd = time_saved_h * HOURLY_COST_USD;

            let pr_num_str = entry.pr_number.map(|n| n.to_string()).unwrap_or_default();
            let author_str = csv_sanitize(entry.author.as_deref().unwrap_or(""));
            let score_str = entry.slop_score.to_string();
            let unlinked_str = entry.unlinked_pr.to_string();
            let dead_str = entry.dead_symbols_added.to_string();
            let clones_str = entry.logic_clones_found.to_string();
            let zombie_syms_str = entry.zombie_symbols_added.to_string();
            let zombie_deps_str = csv_sanitize(&entry.zombie_deps.join(" | "));
            let violation_reasons = csv_sanitize(&build_violation_reasons(entry));
            let time_str = format!("{time_saved_h:.4}");
            let savings_str = format!("{savings_usd:.2}");
            let state_str = entry.state.to_string();
            let is_bot_str = if entry.is_bot { "TRUE" } else { "FALSE" };

            wtr.write_record([
                pr_num_str.as_str(),
                author_str.as_str(),
                score_str.as_str(),
                "FALSE",
                "0",
                unlinked_str.as_str(),
                dead_str.as_str(),
                clones_str.as_str(),
                zombie_syms_str.as_str(),
                zombie_deps_str.as_str(),
                violation_reasons.as_str(),
                time_str.as_str(),
                savings_str.as_str(),
                entry.timestamp.as_str(),
                state_str.as_str(),
                is_bot_str,
                entry.repo_slug.as_str(),
            ])?;
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

    // ROI constants — mirror report.rs values.
    const MINUTES_PER_TRIAGE: f64 = 12.0;
    const HOURLY_COST_USD: f64 = 100.0;

    // Exact 17-column header schema.
    wtr.write_record([
        "PR_Number",
        "Author",
        "Score",
        "Mesa_Triggered",
        "Trust_Delta",
        "Unlinked_PR",
        "Dead_Code_Count",
        "Logic_Clones",
        "Zombie_Syms",
        "Zombie_Deps",
        "Violation_Reasons",
        "Time_Saved_Hours",
        "Operational_Savings_USD",
        "Timestamp",
        "PR_State",
        "Is_Bot",
        "Repo_Slug",
    ])?;

    for entry in &entries {
        // Actionable = any gate criterion met.
        let actionable = entry.slop_score >= 100
            || entry.zombie_symbols_added > 0
            || entry
                .antipatterns
                .iter()
                .any(|a| a.contains("Unverified Security Bump"));

        let time_saved_h = if actionable {
            MINUTES_PER_TRIAGE / 60.0
        } else {
            0.0_f64
        };
        let savings_usd = time_saved_h * HOURLY_COST_USD;

        let pr_num_str = entry.pr_number.map(|n| n.to_string()).unwrap_or_default();
        let author_str = csv_sanitize(entry.author.as_deref().unwrap_or(""));
        let score_str = entry.slop_score.to_string();
        let unlinked_str = entry.unlinked_pr.to_string();
        let dead_str = entry.dead_symbols_added.to_string();
        let clones_str = entry.logic_clones_found.to_string();
        let zombie_syms_str = entry.zombie_symbols_added.to_string();
        let zombie_deps_str = csv_sanitize(&entry.zombie_deps.join(" | "));
        let violation_reasons = csv_sanitize(&build_violation_reasons(entry));
        let time_str = format!("{time_saved_h:.4}");
        let savings_str = format!("{savings_usd:.2}");
        let state_str = entry.state.to_string();
        let is_bot_str = if entry.is_bot { "TRUE" } else { "FALSE" };

        wtr.write_record([
            pr_num_str.as_str(),
            author_str.as_str(),
            score_str.as_str(),
            "FALSE", // Mesa_Triggered — SaaS reserved
            "0",     // Trust_Delta   — SaaS reserved
            unlinked_str.as_str(),
            dead_str.as_str(),
            clones_str.as_str(),
            zombie_syms_str.as_str(),
            zombie_deps_str.as_str(),
            violation_reasons.as_str(),
            time_str.as_str(),
            savings_str.as_str(),
            entry.timestamp.as_str(),
            state_str.as_str(),
            is_bot_str,
            entry.repo_slug.as_str(),
        ])?;
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

    wtr.write_record([
        "PR_Number",
        "Author",
        "Score",
        "Mesa_Triggered",
        "Trust_Delta",
        "Unlinked_PR",
        "Dead_Code_Count",
        "Logic_Clones",
        "Zombie_Syms",
        "Zombie_Deps",
        "Violation_Reasons",
        "Time_Saved_Hours",
        "Operational_Savings_USD",
        "Timestamp",
        "PR_State",
        "Is_Bot",
        "Repo_Slug",
    ])?;

    let timestamp = crate::utc_now_iso8601();

    for entry in &dead {
        let byte_size = entry.end_byte.saturating_sub(entry.start_byte);
        // Score proxy: dead-symbol weight (×10) applied to byte size in units of 100 B.
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
            "FALSE", // Mesa_Triggered
            "0",     // Trust_Delta
            "0",     // Unlinked_PR
            "1",     // Dead_Code_Count — one dead symbol per row
            "0",     // Logic_Clones
            "0",     // Zombie_Syms
            "",      // Zombie_Deps
            violation.as_str(),
            "0.0000", // Time_Saved_Hours
            "0.00",   // Operational_Savings_USD
            timestamp.as_str(),
            "open",  // PR_State — N/A for static scan
            "FALSE", // Is_Bot — N/A for static scan
            "",      // Repo_Slug — N/A for static scan
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

/// Build the `Violation_Reasons` string for one [`BounceLogEntry`].
///
/// Synthesises every flag stored in the entry into a `" | "`-separated list.
/// Ordered by scoring weight (heaviest first) so the dominant reason leads.
///
/// For legacy log entries written before `unlinked_pr`/`antipatterns` were
/// persisted, falls back to a residual-score heuristic: score points not
/// accounted for by the stored numeric fields are labelled as inferred violations.
///
/// [`BounceLogEntry`]: crate::report::BounceLogEntry
fn build_violation_reasons(entry: &crate::report::BounceLogEntry) -> String {
    let mut reasons: Vec<String> = Vec::new();

    // ── Stored antipattern descriptions (×50 each) ─────────────────────────
    for ap in &entry.antipatterns {
        reasons.push(ap.clone());
    }

    // ── Zombie symbol reintroduction (×15 each) ────────────────────────────
    if entry.zombie_symbols_added > 0 {
        reasons.push(format!(
            "Zombie Symbol Reintroduction x{}",
            entry.zombie_symbols_added
        ));
    }

    // ── Dead symbol introduction (×10 each) ───────────────────────────────
    if entry.dead_symbols_added > 0 {
        reasons.push(format!("Dead Symbol Added x{}", entry.dead_symbols_added));
    }

    // ── Structural clones (×5 each) ────────────────────────────────────────
    if entry.logic_clones_found > 0 {
        reasons.push(format!("Structural Clone x{}", entry.logic_clones_found));
    }

    // ── Comment violations (×5 each) ───────────────────────────────────────
    for cv in &entry.comment_violations {
        reasons.push(cv.clone());
    }

    // ── Unlinked PR (×20 flat) ─────────────────────────────────────────────
    if entry.unlinked_pr > 0 {
        reasons.push("Unlinked PR".to_owned());
    }

    // ── Necrotic flag (Backlog Pruner verdict) ─────────────────────────────
    if let Some(ref flag) = entry.necrotic_flag {
        reasons.push(format!("Necrotic: {flag}"));
    }

    // ── Zombie dependencies (informational) ────────────────────────────────
    if !entry.zombie_deps.is_empty() {
        reasons.push(format!(
            "Zombie Dependency: {}",
            entry.zombie_deps.join(", ")
        ));
    }

    // ── Clone collisions (per-PR LSH hit list, informational) ──────────────
    if !entry.collided_pr_numbers.is_empty() {
        let hits: Vec<String> = entry
            .collided_pr_numbers
            .iter()
            .map(|n| format!("#{n}"))
            .collect();
        reasons.push(format!("Clone collision: {}", hits.join(", ")));
    }

    // ── Domain routing suppression (engine transparency) ──────────────────
    if entry.suppressed_by_domain > 0 {
        reasons.push(format!(
            "Domain-suppressed findings: {}",
            entry.suppressed_by_domain
        ));
    }

    // ── Legacy residual heuristic ──────────────────────────────────────────
    // Log entries written before antipattern/unlinked_pr fields were persisted
    // will have all of the above as zero/empty even when slop_score > 0.
    // Compute what score is explained by known fields; label the gap.
    if reasons.is_empty() && entry.slop_score > 0 {
        let known: u32 = entry.dead_symbols_added * 10
            + entry.logic_clones_found * 5
            + entry.zombie_symbols_added * 15
            + entry.unlinked_pr * 20
            + entry.comment_violations.len() as u32 * 5;
        let residual = entry.slop_score.saturating_sub(known);
        if residual > 0 {
            // Attempt to decompose the residual into known scoring units.
            // Priority: antipatterns (50 pts) → unlinked (20 pts).
            let mut rem = residual;
            let inferred_antipatterns = rem / 50;
            rem %= 50;
            let inferred_unlinked = rem / 20;
            rem %= 20;

            if inferred_antipatterns > 0 {
                reasons.push(format!("Language Antipattern x{inferred_antipatterns}"));
            }
            if inferred_unlinked > 0 {
                reasons.push("Unlinked PR".to_owned());
            }
            if rem > 0 {
                reasons.push(format!("Unknown violation (residual: {rem})"));
            }
        }
    }

    reasons.join(" | ")
}
