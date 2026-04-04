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

use std::collections::HashSet;
use std::io::{BufWriter, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::{anyhow, Result};
use git2::{Oid, Repository};
use rayon::prelude::*;

use anatomist::parser::ParserHost;
use common::physarum::{Pulse, SystemHeart};

// ---------------------------------------------------------------------------
// Base-lockfile ODB fetch
// ---------------------------------------------------------------------------

/// Read the raw bytes of `Cargo.lock` at `base_sha` from the repository ODB.
///
/// Used to provide the base snapshot for silo delta computation:
/// [`anatomist::manifest::find_version_silos_from_lockfile`] subtracts any
/// crate that was already a version-split on the base branch so that only
/// silos **introduced** by the PR are reported.
///
/// Returns `None` on any failure (missing file, invalid OID, git error) — the
/// caller falls back to reporting all head silos without delta filtering.
fn fetch_base_lockfile(repo_path: &Path, base_sha: &str) -> Option<Vec<u8>> {
    let repo = git2::Repository::open(repo_path).ok()?;
    let oid = git2::Oid::from_str(base_sha).ok()?;
    let commit = repo.find_commit(oid).ok()?;
    let tree = commit.tree().ok()?;
    let entry = tree.get_path(std::path::Path::new("Cargo.lock")).ok()?;
    let blob = repo.find_blob(entry.id()).ok()?;
    Some(blob.content().to_vec())
}
use common::registry::{symbol_hash, MappedRegistry, SymbolEntry, SymbolRegistry};
use common::Protection;
use forge::slop_filter::bounce_git;
use include_deflator::graph::IncludeGraphBuilder;

use crate::report::{BounceLogEntry, PrState};
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
    resume: bool,
) -> Result<()> {
    let t0 = Instant::now();

    // ── Step 1: collect PR refs ───────────────────────────────────────────
    let mut pr_entries = collect_pr_refs(repo_path, limit)?;
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

    // ── Step 2.5: ensure .janitor dir exists (needed for both symbol index
    //             and bounce log, so create it once here) ─────────────────
    let janitor_dir = repo_path.join(".janitor");
    std::fs::create_dir_all(&janitor_dir)
        .map_err(|e| anyhow!("Cannot create .janitor dir: {e}"))?;

    // ── Step 2.55: Resume filter ──────────────────────────────────────────
    // When --resume is active, skip PRs already present in the bounce log so
    // an interrupted run can be continued without re-scoring completed work.
    if resume {
        let processed_set = load_processed_pr_numbers(&janitor_dir);
        if !processed_set.is_empty() {
            let before = pr_entries.len();
            pr_entries.retain(|(pr_num, _)| !processed_set.contains(pr_num));
            eprintln!(
                "janitor hyper-drive: resume — skipping {} already-processed PRs ({} remaining)",
                before - pr_entries.len(),
                pr_entries.len()
            );
        } else {
            eprintln!("janitor hyper-drive: resume — no prior log found, processing all PRs");
        }
        if pr_entries.is_empty() {
            eprintln!("janitor hyper-drive: resume — all PRs already processed, nothing to do");
            return Ok(());
        }
    }

    // ── Step 2.6: In-memory symbol hydration ─────────────────────────────
    // Walk the base-branch tree via libgit2, extract entities from every
    // source blob using the polyglot ParserHost, and serialize the result
    // to .janitor/symbols.rkyv *before* load_registry (Step 3) runs.
    // This ensures the Necrotic Pruning Matrix has a populated symbol table
    // for Ghost Collision and Unwired Island detection without requiring a
    // filesystem checkout.
    match build_symbols_rkyv(repo_path, &base_sha) {
        Ok(n) => eprintln!(
            "janitor hyper-drive: symbol index hydrated ({n} symbols) → {}",
            janitor_dir.join("symbols.rkyv").display()
        ),
        Err(e) => eprintln!(
            "janitor hyper-drive: symbol hydration skipped ({e}); \
             Necrotic Pruner will operate without registry"
        ),
    }

    // ── Step 3: load symbol registry (picks up hydrated index) ───────────
    let registry = load_registry(repo_path)?;

    // ── Step 4: open bounce log for streaming writes ──────────────────────
    let slug = repo_slug.map(str::to_owned).unwrap_or_else(|| {
        repo_path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    });

    // janitor_dir was already created in Step 2.5 — this is a no-op but
    // kept for clarity so the log_path derivation block remains self-contained.

    let log_path = janitor_dir.join("bounce_log.ndjson");
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
        .map_err(|e| anyhow!("Cannot open bounce log {}: {e}", log_path.display()))?;

    // Wrap in a BufWriter behind a mutex so rayon workers can write without
    // blocking each other for the duration of a syscall.
    let writer: Arc<Mutex<BufWriter<std::fs::File>>> =
        Arc::new(Mutex::new(BufWriter::new(log_file)));

    // ── Step 5a: pre-emptive WOPR graph — serialize before any AST work ─────
    // Executed immediately after base resolution so that a SIGABRT from a
    // tree-sitter AST bomb during the bounce loop cannot destroy the graph.
    // The graph is built from the HEAD tree in the git ODB — no working-tree
    // access required.
    let wopr_path = janitor_dir.join("wopr_graph.json");
    match build_wopr_graph(repo_path) {
        Ok(ranked) => match serde_json::to_string(&ranked) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&wopr_path, json) {
                    eprintln!("hyper-drive: cannot write wopr_graph.json: {e}");
                } else {
                    eprintln!(
                        "janitor hyper-drive: WOPR graph written ({} silos) → {}",
                        ranked.len(),
                        wopr_path.display()
                    );
                }
            }
            Err(e) => eprintln!("hyper-drive: WOPR graph serialization failed: {e}"),
        },
        Err(e) => eprintln!("hyper-drive: WOPR graph build skipped: {e}"),
    }

    // ── Step 5: rayon parallel bounce — write + flush every entry ─────────
    let t1 = Instant::now();
    let repo_path_arc: &Path = repo_path;
    let total_prs = pr_entries.len();
    let processed = AtomicUsize::new(0);
    let written = AtomicUsize::new(0);

    // Physarum Protocol — shared RAM-pressure sensor for all rayon workers.
    // Workers spin-wait on Stop (>90% RAM) before entering the AST pipeline.
    let heart = Arc::new(SystemHeart::new());

    // Cap at 4 threads — each worker opens its own git2::Repository handle
    // and may buffer up to 1 MiB of blob data.  4 × 1 MiB = 4 MiB peak
    // anonymous heap; well within budget on any target machine.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(4)
        .thread_name(|i| format!("hyper-drive-{i}"))
        .build()
        .map_err(|e| anyhow!("Cannot build rayon thread pool: {e}"))?;

    pool.install(|| {
        pr_entries.par_iter().for_each(|(pr_num, pr_sha)| {
            // Physarum Viscosity Gate — elastic RAM backpressure with deadlock guard.
            //
            // When RAM pressure exceeds 90% (Stop pulse) we park this thread for
            // 500 ms to let sibling workers complete their bounces and free pages.
            // At this point the thread holds NO heap allocations beyond its own stack.
            //
            // Deadlock guard: if ALL rayon workers enter this sleep simultaneously no
            // work completes, RAM never drops, and the loop never exits.  We cap
            // retries at MAX_STOP_RETRIES (10 × 500 ms = 5 s).  After the cap one
            // worker breaks through, completes a bounce, frees memory, and unblocks
            // the remaining parked workers on their next check.
            const MAX_STOP_RETRIES: u32 = 10;
            let mut stop_retries = 0u32;
            while let Pulse::Stop = heart.beat() {
                if stop_retries >= MAX_STOP_RETRIES {
                    eprintln!(
                        "  [PHYSARUM] RAM still >90% after {}ms — proceeding to prevent deadlock.",
                        MAX_STOP_RETRIES * 500
                    );
                    break;
                }
                eprintln!(
                    "  [PHYSARUM] RAM >90%. Pausing thread for 500ms to allow GC... \
                     ({}/{})",
                    stop_retries + 1,
                    MAX_STOP_RETRIES
                );
                std::thread::sleep(std::time::Duration::from_millis(500));
                stop_retries += 1;
            }

            let entry = bounce_one(repo_path_arc, &base_sha, pr_sha, &registry, *pr_num, &slug);
            let count = processed.fetch_add(1, Ordering::Relaxed) + 1;
            eprintln!(
                "[{}/{}] PR #{} {}",
                count,
                total_prs,
                pr_num,
                if entry.is_some() { "OK" } else { "SKIP" }
            );
            if let Some(ref e) = entry {
                match serde_json::to_string(e) {
                    Ok(line) => {
                        if let Ok(mut guard) = writer.lock() {
                            if writeln!(guard, "{line}").is_ok() {
                                // Flush after every entry — guarantees that a SIGABRT
                                // or core dump cannot lose a completed PR result.
                                let _ = guard.flush();
                                written.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    Err(err) => {
                        eprintln!("hyper-drive PR#{pr_num}: serialize failed: {err}");
                    }
                }
            }
        });
    });

    // Final flush — drains any remaining BufWriter capacity.
    if let Ok(mut guard) = writer.lock() {
        let _ = guard.flush();
    }

    let n_written = written.load(Ordering::Relaxed);
    let elapsed_ms = t1.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "janitor hyper-drive: {} PRs bounced in {:.1}ms ({:.1}ms/PR) [{} threads]",
        n_written,
        elapsed_ms,
        if n_written == 0 {
            0.0
        } else {
            elapsed_ms / n_written as f64
        },
        rayon::current_num_threads(),
    );
    eprintln!(
        "janitor hyper-drive: wrote {} entries to {}",
        n_written,
        log_path.display()
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

    // ── Semantic Null pre-check (full-blob) ──────────────────────────────────
    // Compare full file blobs from the ODB rather than extracted patch lines.
    // If ALL modified source files share identical structural AST skeletons,
    // the PR only changes cosmetic tokens — bypass the full bounce pipeline.
    if forge::slop_filter::semantic_null_pr_check(repo_path, &merge_base_sha, pr_sha) {
        let sig = forge::pr_collider::PrDeltaSignature::from_bytes(pr_sha.as_bytes());
        return Some(BounceLogEntry {
            pr_number: Some(pr_num as u64),
            author,
            timestamp: utc_now_iso8601(),
            slop_score: 0,
            dead_symbols_added: 0,
            logic_clones_found: 0,
            zombie_symbols_added: 0,
            unlinked_pr: 0,
            antipatterns: Vec::new(),
            comment_violations: Vec::new(),
            min_hashes: sig.min_hashes.to_vec(),
            zombie_deps: Vec::new(),
            state: PrState::Open,
            is_bot: false,
            repo_slug: repo_slug.to_string(),
            suppressed_by_domain: 0,
            collided_pr_numbers: Vec::new(),
            necrotic_flag: Some("SEMANTIC_NULL".to_string()),
            commit_sha: pr_sha.to_string(),
            policy_hash: String::new(),
            version_silos: Vec::new(),
            agentic_pct: 0.0,
            ci_energy_saved_kwh: 0.1,
            provenance: crate::report::Provenance::default(),
            governor_status: None,
            pqc_sig: None,
            cognition_surrender_index: 0.0,
        });
    }

    let (mut score, blobs) = bounce_git(repo_path, &merge_base_sha, pr_sha, registry)
        .map_err(|e| {
            eprintln!("hyper-drive PR#{pr_num}: {e}");
        })
        .ok()?;

    // Zombie dependency scan over the blobs (best-effort).
    let zombie_deps = anatomist::manifest::find_zombie_deps_in_blobs(&blobs);

    // Version silo detection — Tier 1: Cargo.toml / package.json blobs.
    let mut version_silos = anatomist::manifest::find_version_silos_in_blobs(&blobs);

    // Tier 2: resolved graph from in-memory Cargo.lock blob (supersedes Tier 1
    // for Rust crates; npm/pip entries from Tier 1 are preserved).
    //
    // MANDATORY GATE: `Cargo.lock` must be present in the PR diff blobs before
    // the lockfile silo detector runs.  `blobs` is built from the libgit2 diff
    // (MergeSnapshot.patches) and contains only files changed by this PR — if
    // Cargo.lock is absent the PR did not touch the dependency graph and CANNOT
    // introduce new version silos.
    let base_lock = fetch_base_lockfile(repo_path, &merge_base_sha);
    let lockfile_in_diff = blobs
        .keys()
        .any(|p| p.file_name().and_then(|n| n.to_str()) == Some("Cargo.lock"));
    let lockfile_silos = if lockfile_in_diff {
        anatomist::manifest::find_version_silos_from_lockfile(&blobs, base_lock.as_deref())
    } else {
        Vec::new()
    };
    if !lockfile_silos.is_empty() {
        let lock_names: std::collections::HashSet<&str> =
            lockfile_silos.iter().map(|s| s.name.as_str()).collect();
        version_silos.retain(|n| !lock_names.contains(n.as_str()));
        // One antipattern_details entry per siloed crate for UI readability.
        version_silos.extend(lockfile_silos.iter().map(|s| s.display()));
        version_silos.sort();
    }

    if !version_silos.is_empty() {
        for silo in &version_silos {
            score
                .antipattern_details
                .push(format!("architecture:version_silo — {silo}"));
        }
        score.version_silo_details = version_silos.clone();
    }

    let slop_score = score.score();

    // Explicit memory flush — compute provenance bytes then drop the
    // MergeSnapshot blob map before building BounceLogEntry.  `blobs` can hold
    // up to 1 MiB of raw file data per PR; releasing it here ensures the OS
    // can reclaim those pages immediately after scoring, which is particularly
    // important during the 500ms Physarum sleep windows that park workers under
    // RAM pressure.
    let source_bytes_processed: u64 = blobs.values().map(|v| v.len() as u64).sum();
    drop(blobs);

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
        commit_sha: pr_sha.to_string(),
        policy_hash: String::new(),
        version_silos,
        agentic_pct: 0.0,
        ci_energy_saved_kwh: if slop_score > 0 { 0.1 } else { 0.0 },
        provenance: crate::report::Provenance {
            source_bytes_processed,
            ..crate::report::Provenance::default()
        },
        governor_status: None,
        pqc_sig: None,
        cognition_surrender_index: 0.0,
    })
}

// ---------------------------------------------------------------------------
// In-memory symbol hydration
// ---------------------------------------------------------------------------

/// Walk the base-branch tree of `repo_path` in-memory, extract entities from
/// every source blob using the polyglot [`ParserHost`], and serialize the
/// result to `<repo_path>/.janitor/symbols.rkyv`.
///
/// This produces the global symbol table required by the Necrotic Pruning
/// Matrix (Ghost Collision / Unwired Island checks) without requiring a
/// filesystem checkout.  All source is read from the Git object database via
/// `blob.content()` — identical to the WOPR graph build pattern.
///
/// ## Language coverage
/// Python and TypeScript are excluded (their extractors require a file on disk
/// or a non-public API not suitable for in-memory use).  All other Tier-1
/// languages are covered: Rust, C/C++, Java, C#, Go, JavaScript, Ruby, PHP,
/// Swift, Lua, Scala, Bash, Objective-C.
///
/// ## Circuit breaker
/// Blobs larger than 256 KiB are skipped — they are almost exclusively
/// auto-generated bindings, compiled assets, or giant monolithic stubs that
/// would overwhelm the tree-sitter AST allocator without adding signal.
///
/// ## Return value
/// Returns the number of symbols inserted into the registry on success, or an
/// error if the repository cannot be opened or the tree cannot be walked.
fn build_symbols_rkyv(repo_path: &Path, base_sha: &str) -> Result<usize> {
    const MAX_BLOB: usize = 256 * 1024;

    let repo = Repository::open(repo_path)
        .map_err(|e| anyhow!("symbol hydration: cannot open repo: {e}"))?;

    let base_oid =
        Oid::from_str(base_sha).map_err(|e| anyhow!("symbol hydration: invalid base SHA: {e}"))?;
    let commit = repo
        .find_commit(base_oid)
        .map_err(|e| anyhow!("symbol hydration: cannot find base commit: {e}"))?;
    let tree = commit
        .tree()
        .map_err(|e| anyhow!("symbol hydration: cannot get base tree: {e}"))?;

    // Phase A: walk the tree to collect (oid, file_path, ext) entries.
    // We stage OIDs first because `repo.find_blob()` borrows `repo` and the
    // tree walk closure also captures `repo` — staging avoids the overlap.
    let mut entries: Vec<(git2::Oid, String, String)> = Vec::new();
    tree.walk(git2::TreeWalkMode::PreOrder, |root, entry| {
        if entry.kind() != Some(git2::ObjectType::Blob) {
            return 0; // TreeWalkResult::Ok
        }
        let name = match entry.name() {
            Some(n) => n,
            None => return 0,
        };
        let ext = std::path::Path::new(name)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_owned();

        // Only collect blobs with a grammar-backed extension.
        if matches!(
            ext.as_str(),
            "rs" | "js"
                | "jsx"
                | "cpp"
                | "cxx"
                | "cc"
                | "hpp"
                | "c"
                | "h"
                | "java"
                | "cs"
                | "go"
                | "rb"
                | "php"
                | "swift"
                | "lua"
                | "scala"
                | "sh"
                | "bash"
                | "m"
                | "mm"
        ) {
            let file_path = if root.is_empty() {
                name.to_owned()
            } else {
                format!("{root}{name}")
            };
            entries.push((entry.id(), file_path, ext));
        }
        0 // TreeWalkResult::Ok
    })
    .map_err(|e| anyhow!("symbol hydration: tree walk failed: {e}"))?;

    // Phase B: load each blob and extract entities.
    let mut registry = SymbolRegistry::new();
    let mut count = 0usize;

    for (oid, file_path, ext) in entries {
        let blob = match repo.find_blob(oid) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let content = blob.content();
        if content.len() > MAX_BLOB {
            continue; // circuit breaker
        }

        let entities = match ext.as_str() {
            "rs" => ParserHost::extract_rust_entities(content, &file_path).unwrap_or_default(),
            "js" | "jsx" => {
                ParserHost::extract_js_entities(content, &file_path).unwrap_or_default()
            }
            "cpp" | "cxx" | "cc" | "hpp" => {
                ParserHost::extract_cpp_entities(content, &file_path).unwrap_or_default()
            }
            "c" | "h" => ParserHost::extract_c_entities(content, &file_path).unwrap_or_default(),
            "java" => ParserHost::extract_java_entities(content, &file_path).unwrap_or_default(),
            "cs" => ParserHost::extract_csharp_entities(content, &file_path).unwrap_or_default(),
            "go" => ParserHost::extract_go_entities(content, &file_path).unwrap_or_default(),
            "rb" => ParserHost::extract_ruby_entities(content, &file_path).unwrap_or_default(),
            "php" => ParserHost::extract_php_entities(content, &file_path).unwrap_or_default(),
            "swift" => ParserHost::extract_swift_entities(content, &file_path).unwrap_or_default(),
            "lua" => ParserHost::extract_lua_entities(content, &file_path).unwrap_or_default(),
            "scala" => ParserHost::extract_scala_entities(content, &file_path).unwrap_or_default(),
            "sh" | "bash" => {
                ParserHost::extract_bash_entities(content, &file_path).unwrap_or_default()
            }
            "m" | "mm" => {
                ParserHost::extract_objc_entities(content, &file_path).unwrap_or_default()
            }
            _ => continue,
        };

        for entity in entities {
            let sym_id = format!("{}::{}", entity.file_path, entity.qualified_name);
            registry.insert(SymbolEntry {
                id: symbol_hash(&sym_id),
                name: entity.name,
                qualified_name: entity.qualified_name,
                file_path: entity.file_path,
                entity_type: entity.entity_type as u8,
                start_line: entity.start_line,
                end_line: entity.end_line,
                start_byte: entity.start_byte,
                end_byte: entity.end_byte,
                structural_hash: entity.structural_hash.unwrap_or(0),
                // All entities from the base tree are alive — Protected::Referenced.
                // This ensures that PR additions with matching hashes count as
                // Global Logic Clones (not Zombie Reintroductions).
                protected_by: Some(Protection::Referenced),
            });
            count += 1;
        }
    }

    let rkyv_path = repo_path.join(".janitor").join("symbols.rkyv");
    registry
        .save(&rkyv_path)
        .map_err(|e| anyhow!("symbol hydration: cannot save symbols.rkyv: {e}"))?;

    Ok(count)
}

// ---------------------------------------------------------------------------
// WOPR graph builder
// ---------------------------------------------------------------------------

/// Walk the `HEAD` tree of `repo_path` in-memory for C/C++ `#include` relationships
/// and return the top-10 nodes by transitive reach, pre-ranked for the WOPR dashboard.
///
/// Uses `git2` blob access so this works even when the orchestrator checked out no
/// working tree (`--no-checkout`) or after Scorched Earth deleted the source files.
///
/// Serialized to `.janitor/wopr_graph.json` by [`cmd_hyper_drive`] after the
/// bounce run completes.  The WOPR dashboard loads this file instead of
/// re-scanning the source tree (which may be absent if the repository was
/// purged after analysis to reclaim SSD space).
///
/// Returns an empty `Vec` when no C/C++ files are found — the dashboard
/// displays `"AWAITING HYPER-DRIVE GRAPH GENERATION..."` in that case.
fn build_wopr_graph(repo_path: &Path) -> Result<Vec<(String, usize, usize)>> {
    let repo = Repository::open(repo_path)
        .map_err(|e| anyhow!("Cannot open git repository for WOPR graph: {e}"))?;
    let mut builder = IncludeGraphBuilder::new();
    let _ = builder.scan_repo(&repo);
    let graph = builder.build();

    let n = graph.node_count();
    if n == 0 {
        return Ok(Vec::new());
    }

    let mut ranked: Vec<(String, usize, usize)> = (0..n as u32)
        .map(|idx| {
            let label = graph.label(idx).to_string();
            let direct = graph.in_degree(idx);
            let reach = graph.transitive_reach(idx);
            (label, direct, reach)
        })
        .collect();
    ranked.sort_by_key(|(_, _, r)| std::cmp::Reverse(*r));
    ranked.truncate(10);
    Ok(ranked)
}

// ---------------------------------------------------------------------------
// Resume helper
// ---------------------------------------------------------------------------

/// Read all PR numbers already present in `<janitor_dir>/bounce_log.ndjson`.
///
/// Returns a `HashSet<u32>` so the caller can filter the harvested PR ref list
/// in O(1) per entry.  An absent or malformed log returns an empty set —
/// the caller degrades gracefully to full processing.
fn load_processed_pr_numbers(janitor_dir: &Path) -> HashSet<u32> {
    let log_path = janitor_dir.join("bounce_log.ndjson");
    let content = match std::fs::read_to_string(&log_path) {
        Ok(s) => s,
        Err(_) => return HashSet::new(),
    };
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| {
            let v: serde_json::Value = serde_json::from_str(l).ok()?;
            v["pr_number"].as_u64().map(|n| n as u32)
        })
        .collect()
}
