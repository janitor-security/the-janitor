//! Hyper-Drive batch bouncer — libgit2 O(N) local PR traversal.
//!
//! Replaces the `gh pr diff` + HTTP bottleneck with pure in-memory libgit2
//! traversal.  All paths from the Git packfile to the tree-sitter AST remain
//! in RAM; no subshells, no temp files, no network calls after initial clone.
//!
//! ## Protocol
//! 1. **Ref harvest**: enumerate `refs/remotes/origin/pr/*` via `git2`.
//! 2. **Base detection**: resolve `refs/remotes/origin/master` or `.../main`.
//! 3. **Rayon matrix**: `.par_iter()` over collected PR refs.  Each rayon
//!    task opens its own `git2::Repository` (not `Send`) and calls the
//!    existing [`bounce_git`][forge::slop_filter::bounce_git] engine.
//! 4. **Log flush**: collect results in memory, write sequentially to
//!    `.janitor/bounce_log.ndjson`.
//!
//! ## 8 GB Law compliance
//! Per-PR blobs > 1 MiB are skipped by the `bounce_git` circuit breaker.
//! Peak heap ≈ `rayon_threads × max_blob_size` — well within budget.
//!
//! ## Prerequisite (Phase 1 fetch)
//! Run once before the first hyper-audit to populate the PR ref namespace:
//! ```sh
//! git config --local --add remote.origin.fetch '+refs/pull/*/head:refs/remotes/origin/pr/*'
//! git fetch origin --no-tags --force
//! ```
//! The `just hyper-audit` recipe performs this automatically.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use anyhow::{anyhow, Result};
use git2::{Oid, Repository};
use rayon::prelude::*;

use common::registry::{MappedRegistry, SymbolRegistry};
use forge::slop_filter::bounce_git;

use crate::report::{self, BounceLogEntry, PrState};
use crate::utc_now_iso8601;

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Batch-bounce all `refs/remotes/origin/pr/*` references in `repo_path`.
///
/// Opens the repository with `git2`, enumerates up to `limit` PR refs
/// (0 = unlimited), diffs each against the auto-detected base branch, and
/// runs the full Janitor scoring pipeline in parallel via rayon.
///
/// Results are written to `<repo_path>/.janitor/bounce_log.ndjson`.
///
/// # Errors
/// Returns `Err` if the repository cannot be opened, no PR refs are found,
/// or the base branch cannot be resolved.
pub fn cmd_hyper_drive(
    repo_path: &Path,
    limit: usize,
    base_branch: Option<&str>,
    repo_slug: Option<&str>,
) -> Result<()> {
    let t0 = Instant::now();

    // ── Step 1: collect PR refs ───────────────────────────────────────────
    let pr_entries = collect_pr_refs(repo_path, limit)?;
    if pr_entries.is_empty() {
        eprintln!(
            "janitor hyper-drive: no refs/remotes/origin/pr/* found in {}.\n\
             Run the Phase 1 fetch first:\n\
             \x20 git -C {} config --local --add remote.origin.fetch \
             '+refs/pull/*/head:refs/remotes/origin/pr/*'\n\
             \x20 git -C {} fetch origin --no-tags --force",
            repo_path.display(),
            repo_path.display(),
            repo_path.display(),
        );
        return Ok(());
    }
    eprintln!(
        "janitor hyper-drive: {} PR refs collected ({:.1}ms)",
        pr_entries.len(),
        t0.elapsed().as_secs_f64() * 1000.0
    );

    // ── Step 2: resolve base branch SHA ──────────────────────────────────
    let base_sha = find_base_sha(repo_path, base_branch)?;
    eprintln!("janitor hyper-drive: base SHA = {}", &base_sha[..12]);

    // ── Step 3: load symbol registry ─────────────────────────────────────
    let registry = load_registry(repo_path)?;

    // ── Step 4: rayon parallel bounce ────────────────────────────────────
    let slug = repo_slug.map(str::to_owned).unwrap_or_else(|| {
        repo_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });

    let t1 = Instant::now();
    let repo_path_arc: &Path = repo_path;
    let total_prs = pr_entries.len();
    let processed = AtomicUsize::new(0);

    // Cap at 4 threads — each worker opens its own git2::Repository handle
    // and may buffer up to 1 MiB of blob data.  4 × 1 MiB = 4 MiB peak
    // anonymous heap; well within budget on any target machine.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|i| format!("hyper-drive-{i}"))
        .build()
        .map_err(|e| anyhow!("Cannot build rayon thread pool: {e}"))?;

    let results: Vec<BounceLogEntry> = pool.install(|| {
        pr_entries
            .par_iter()
            .filter_map(|(pr_num, pr_sha)| {
                let entry = bounce_one(repo_path_arc, &base_sha, pr_sha, &registry, *pr_num, &slug);
                let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
                eprintln!(
                    "[{}/{}] PR #{} {}",
                    count,
                    total_prs,
                    pr_num,
                    if entry.is_some() { "OK" } else { "SKIP" }
                );
                entry
            })
            .collect()
    });

    let elapsed_ms = t1.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "janitor hyper-drive: {} PRs bounced in {:.1}ms ({:.1}ms/PR) [{} threads]",
        results.len(),
        elapsed_ms,
        if results.is_empty() {
            0.0
        } else {
            elapsed_ms / results.len() as f64
        },
        rayon::current_num_threads(),
    );

    // ── Step 5: write results ─────────────────────────────────────────────
    let janitor_dir = repo_path.join(".janitor");
    std::fs::create_dir_all(&janitor_dir)
        .map_err(|e| anyhow!("Cannot create .janitor dir: {e}"))?;

    for entry in &results {
        report::append_bounce_log(&janitor_dir, entry);
    }

    eprintln!(
        "janitor hyper-drive: wrote {} entries to {}/bounce_log.ndjson",
        results.len(),
        janitor_dir.display()
    );
    eprintln!(
        "janitor hyper-drive: total wall time = {:.2}s",
        t0.elapsed().as_secs_f64()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Ref harvest
// ---------------------------------------------------------------------------

/// Enumerate `refs/remotes/origin/pr/*` and return `(pr_number, oid_string)` pairs.
///
/// Refs that do not carry a numeric PR number suffix are silently skipped.
/// Pairs are sorted ascending by PR number so the bounce log is in natural order.
fn collect_pr_refs(repo_path: &Path, limit: usize) -> Result<Vec<(u32, String)>> {
    let repo = Repository::open(repo_path)
        .map_err(|e| anyhow!("Cannot open git repository at {}: {e}", repo_path.display()))?;

    let mut entries: Vec<(u32, String)> = Vec::new();

    for reference in repo.references_glob("refs/remotes/origin/pr/*")? {
        let reference = reference?;
        let name = reference.name().unwrap_or("").to_string();

        // Strip prefix to get the PR number string.
        // Refs of the form `refs/remotes/origin/pr/123` or
        // `refs/remotes/origin/pr/123/head` are both handled.
        let suffix = name.strip_prefix("refs/remotes/origin/pr/").unwrap_or("");
        // Accept "123" and "123/head" — extract the leading numeric part.
        let pr_str = suffix.split('/').next().unwrap_or("");
        let Ok(pr_num) = pr_str.parse::<u32>() else {
            continue;
        };

        // Resolve to a direct OID (follows symbolic refs).
        let oid = match reference.resolve() {
            Ok(r) => r.target(),
            Err(_) => reference.target(),
        };
        let Some(oid) = oid else {
            continue;
        };

        entries.push((pr_num, oid.to_string()));
    }

    // Sort descending — newest PRs first so `limit` keeps the most recent work.
    entries.sort_unstable_by_key(|(n, _)| std::cmp::Reverse(*n));
    // Deduplicate: pr/123 and pr/123/head both resolve to the same commit.
    entries.dedup_by_key(|(n, _)| *n);

    if limit > 0 {
        entries.truncate(limit);
    }
    Ok(entries)
}

// ---------------------------------------------------------------------------
// Base branch resolution
// ---------------------------------------------------------------------------

/// Resolve the base branch to a commit SHA string.
///
/// Tries the following candidates in order:
/// 1. The explicit `base_branch` argument (as `refs/remotes/origin/<branch>`).
/// 2. `refs/remotes/origin/master`
/// 3. `refs/remotes/origin/main`
/// 4. `refs/heads/master`
/// 5. `refs/heads/main`
/// 6. `refs/remotes/origin/trunk`    (Apache projects)
/// 7. `refs/heads/trunk`
/// 8. `refs/remotes/origin/develop`  (Gitflow convention)
/// 9. `refs/heads/develop`
/// 10. `refs/remotes/origin/canary`  (Vercel)
/// 11. `refs/heads/canary`
/// 12. `refs/remotes/origin/unstable` (Redis)
/// 13. `refs/heads/unstable`
/// 14. `refs/remotes/origin/devel`    (kernel.org / freedesktop projects)
/// 15. `refs/heads/devel`
fn find_base_sha(repo_path: &Path, base_branch: Option<&str>) -> Result<String> {
    let repo = Repository::open(repo_path)
        .map_err(|e| anyhow!("Cannot open repository for base resolution: {e}"))?;

    let candidates: Vec<String> = if let Some(b) = base_branch {
        vec![
            format!("refs/remotes/origin/{b}"),
            format!("refs/heads/{b}"),
        ]
    } else {
        vec![
            "refs/remotes/origin/master".to_string(),
            "refs/remotes/origin/main".to_string(),
            "refs/heads/master".to_string(),
            "refs/heads/main".to_string(),
            "refs/remotes/origin/trunk".to_string(),
            "refs/heads/trunk".to_string(),
            "refs/remotes/origin/develop".to_string(),
            "refs/heads/develop".to_string(),
            "refs/remotes/origin/canary".to_string(),
            "refs/heads/canary".to_string(),
            "refs/remotes/origin/unstable".to_string(),
            "refs/heads/unstable".to_string(),
            "refs/remotes/origin/devel".to_string(),
            "refs/heads/devel".to_string(),
        ]
    };

    for candidate in &candidates {
        if let Ok(reference) = repo.find_reference(candidate) {
            let resolved = reference.resolve().unwrap_or(reference);
            if let Some(oid) = resolved.target() {
                return Ok(oid.to_string());
            }
        }
    }

    anyhow::bail!(
        "Could not resolve base branch in {} — tried: {candidates:?}\n\
         Re-run with --base-branch <name> to specify explicitly.",
        repo_path.display()
    )
}

// ---------------------------------------------------------------------------
// Registry loading
// ---------------------------------------------------------------------------

/// Load the symbol registry from `<repo_path>/.janitor/symbols.rkyv`.
///
/// An absent or unreadable registry returns an empty `SymbolRegistry` —
/// bounce analysis degrades gracefully to clone-only scoring.
fn load_registry(repo_path: &Path) -> Result<SymbolRegistry> {
    let rkyv_path: PathBuf = repo_path.join(".janitor").join("symbols.rkyv");
    if rkyv_path.exists() {
        let mapped = MappedRegistry::open(&rkyv_path)
            .map_err(|e| anyhow!("Cannot open registry at {}: {e}", rkyv_path.display()))?;
        rkyv::deserialize::<_, rkyv::rancor::Error>(mapped.archived())
            .map_err(|e| anyhow!("Registry deserialisation failed: {e}"))
    } else {
        // No registry — bounce proceeds without dead-symbol / zombie detection.
        Ok(SymbolRegistry::default())
    }
}

// ---------------------------------------------------------------------------
// Per-PR bounce (called from rayon closure)
// ---------------------------------------------------------------------------

/// Compute the three-way merge base between `global_base_sha` and `pr_sha`.
///
/// This isolates exactly what the PR author changed relative to when they
/// branched, preventing temporal drift from inflating diffs as master advances.
fn compute_merge_base(repo_path: &Path, global_base_sha: &str, pr_sha: &str) -> Result<String> {
    let repo = Repository::open(repo_path)
        .map_err(|e| anyhow!("Cannot open repository for merge-base: {e}"))?;
    let base_oid = Oid::from_str(global_base_sha)
        .map_err(|e| anyhow!("Invalid base SHA {}: {e}", &global_base_sha[..12]))?;
    let pr_oid =
        Oid::from_str(pr_sha).map_err(|e| anyhow!("Invalid PR SHA {}: {e}", &pr_sha[..12]))?;
    let merge_base_oid = repo.merge_base(base_oid, pr_oid).map_err(|e| {
        anyhow!(
            "merge_base({}, {}): {e}",
            &global_base_sha[..12],
            &pr_sha[..12]
        )
    })?;
    Ok(merge_base_oid.to_string())
}

/// Diff PR `pr_num` (at `pr_sha`) against its merge base with the global base
/// branch, run PatchBouncer, and return a populated `BounceLogEntry`.
///
/// Uses `repo.merge_base(global_base_oid, pr_commit.id())` to isolate the
/// exact patch the PR author added — prevents temporal drift from master
/// advancing past the PR's branch point from inflating diff sizes.
///
/// Returns `None` on any error so the parallel iterator can silently skip
/// malformed refs without aborting the batch.
fn bounce_one(
    repo_path: &Path,
    global_base_sha: &str,
    pr_sha: &str,
    registry: &SymbolRegistry,
    pr_num: u32,
    repo_slug: &str,
) -> Option<BounceLogEntry> {
    // Extract the commit author directly from the Git object so the PDF Top
    // Contributors list is populated when running in hyper-drive (offline) mode,
    // which bypasses the GitHub API and has no other source of author metadata.
    //
    // Explicit if-let nesting is required to give the borrow checker a clear
    // drop sequence: `repo` outlives `commit` which outlives the `Signature`
    // temporary.  Chained closures / IIFE with `?` confuse NLL across these
    // libgit2 lifetime boundaries.
    let author: Option<String> = {
        let mut name: Option<String> = None;
        if let Ok(repo) = Repository::open(repo_path) {
            if let Ok(oid) = Oid::from_str(pr_sha) {
                if let Ok(commit) = repo.find_commit(oid) {
                    name = commit.author().name().map(str::to_owned);
                }
            }
        }
        name
    };

    // Compute the merge base to isolate the PR's actual changes.
    let merge_base_sha = compute_merge_base(repo_path, global_base_sha, pr_sha)
        .map_err(|e| eprintln!("hyper-drive PR#{pr_num}: merge-base failed: {e}"))
        .ok()?;

    let (score, blobs) = bounce_git(repo_path, &merge_base_sha, pr_sha, registry)
        .map_err(|e| {
            eprintln!("hyper-drive PR#{pr_num}: {e}");
        })
        .ok()?;

    // Zombie dependency scan over the blobs (best-effort).
    let zombie_deps = anatomist::manifest::find_zombie_deps_in_blobs(&blobs);

    let slop_score = score.score();

    // Minimal MinHash signature for cross-PR collision hints in reports.
    let sig = forge::pr_collider::PrDeltaSignature::from_bytes(pr_sha.as_bytes());

    Some(BounceLogEntry {
        pr_number: Some(pr_num as u64),
        author,
        timestamp: utc_now_iso8601(),
        slop_score,
        dead_symbols_added: score.dead_symbols_added,
        logic_clones_found: score.logic_clones_found,
        zombie_symbols_added: score.zombie_symbols_added,
        unlinked_pr: score.unlinked_pr,
        antipatterns: score.antipattern_details,
        comment_violations: score.comment_violation_details,
        min_hashes: sig.min_hashes.to_vec(),
        zombie_deps,
        state: PrState::Open,
        is_bot: false,
        repo_slug: repo_slug.to_string(),
        suppressed_by_domain: score.suppressed_by_domain,
        collided_pr_numbers: score.collided_pr_numbers,
        necrotic_flag: score.necrotic_flag,
    })
}
