//! CSV export for bounce log data.
//!
//! Reads `.janitor/bounce_log.ndjson` and streams each entry as a CSV row,
//! suitable for loading into Excel, Google Sheets, or a pandas DataFrame.
//!
//! ## Columns
//!
//! | Column | Source field | Notes |
//! |--------|-------------|-------|
//! | `PR_Number` | `pr_number` | Empty string when absent |
//! | `Author` | `author` | Empty string when absent |
//! | `Score` | `slop_score` | Composite weighted score |
//! | `Dead_Code_Count` | `dead_symbols_added` | Functions re-added from registry |
//! | `Logic_Clones` | `logic_clones_found` | BLAKE3/SimHash clone pairs |
//! | `Zombie_Syms` | `zombie_symbols_added` | Verbatim dead-body reintroductions |
//! | `Zombie_Deps` | `zombie_deps` | Dep names joined with `;` |
//! | `Antipatterns` | `antipatterns` | Violation descriptions joined with `;` |
//! | `Comment_Violations` | `comment_violations` | Phrase + line joined with `;` |
//! | `Timestamp` | `timestamp` | ISO 8601 UTC |

use anyhow::Result;
use std::path::Path;

/// Export the bounce log at `<repo>/.janitor/bounce_log.ndjson` to a CSV file.
///
/// Creates or overwrites `out`.  Returns an error when the bounce log is absent
/// or the output file cannot be written.
pub fn cmd_export(repo: &Path, out: &Path) -> Result<()> {
    let janitor_dir = repo.join(".janitor");
    let entries = crate::report::load_bounce_log(&janitor_dir);

    if entries.is_empty() {
        anyhow::bail!(
            "No bounce log entries found at {}.\n\
             Run `janitor bounce` first to populate the log.",
            janitor_dir.join("bounce_log.ndjson").display()
        );
    }

    let mut wtr = csv::Writer::from_path(out)
        .map_err(|e| anyhow::anyhow!("Cannot create CSV file {}: {}", out.display(), e))?;

    // ROI constants — mirror report.rs values.
    const MINUTES_PER_TRIAGE: f64 = 12.0;
    const HOURLY_COST_USD: f64 = 100.0;

    // Header row.
    wtr.write_record([
        "PR_Number",
        "Author",
        "Score",
        "Dead_Code_Count",
        "Logic_Clones",
        "Zombie_Syms",
        "Zombie_Deps",
        "Antipatterns",
        "Comment_Violations",
        "Time_Saved_Hours",
        "Operational_Savings_USD",
        "Timestamp",
    ])?;

    for entry in &entries {
        // An entry is actionable (triage-taxing) if it meets any gate criterion.
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
        let score_str = entry.slop_score.to_string();
        let dead_str = entry.dead_symbols_added.to_string();
        let clones_str = entry.logic_clones_found.to_string();
        let zombie_str = entry.zombie_symbols_added.to_string();
        let zombie_deps_str = entry.zombie_deps.join("; ");
        let anti_str = if entry.antipatterns.is_empty() {
            String::new()
        } else {
            entry.antipatterns.join("; ")
        };
        let cviol_str = entry.comment_violations.join("; ");
        let time_str = format!("{:.4}", time_saved_h);
        let savings_str = format!("{:.2}", savings_usd);

        wtr.write_record([
            pr_num_str.as_str(),
            entry.author.as_deref().unwrap_or(""),
            score_str.as_str(),
            dead_str.as_str(),
            clones_str.as_str(),
            zombie_str.as_str(),
            zombie_deps_str.as_str(),
            anti_str.as_str(),
            cviol_str.as_str(),
            time_str.as_str(),
            savings_str.as_str(),
            entry.timestamp.as_str(),
        ])?;
    }

    wtr.flush()?;

    println!("Exported {} entries → {}", entries.len(), out.display());
    Ok(())
}
