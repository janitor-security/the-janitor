//! gauntlet-runner — deterministic multi-repo slop stress tester.
//!
//! Reads a list of `owner/repo` targets from a text file (one per line),
//! bounces PRs in parallel within each repository, then generates an
//! aggregate PDF intelligence report and CSV export from all collected logs.
//!
//! # Architecture
//!
//! - **Repos**: processed **sequentially** — one at a time — so peak RSS
//!   stays bounded even with large target lists.
//! - **PRs per repo**: parallelised via a **2-thread rayon pool** (the same
//!   RAM gate proven in `parallel-bounce`).  Each `janitor bounce` peaks at
//!   ≈100–250 MB; 2 workers stay well under 8 GB.
//! - **Diff fetch**: serialised behind a global `Mutex` to prevent fd
//!   exhaustion and git pack-index races between concurrent workers.
//! - **Final aggregation**: `janitor report --global` and
//!   `janitor export --global` are spawned as **parallel threads** once all
//!   repos have been processed.
//!
//! # Usage
//!
//! ```text
//! gauntlet-runner [--targets gauntlet_targets.txt]
//!                 [--pr-limit 100]
//!                 [--timeout  30]
//!                 [--janitor  ./target/release/janitor]
//!                 [--gauntlet-dir ~/dev/gauntlet]
//!                 [--out-dir  .]
//! ```
//!
//! # Targets file format
//!
//! Plain text, one `owner/repo` GitHub slug per line.  Blank lines and lines
//! starting with `#` are silently skipped.
//!
//! ```text
//! # multi-repo gauntlet targets
//! godotengine/godot
//! NixOS/nixpkgs
//! kubernetes/kubernetes
//! ```

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use common::physarum::detect_optimal_concurrency;
use rayon::prelude::*;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Git-operation serialization lock
// ---------------------------------------------------------------------------

/// Global mutex that serialises every `gh pr diff` subprocess spawn within a
/// single repo's rayon pool.
///
/// Prevents concurrent workers from racing on OS pipe tables or the git
/// pack-index.  Only the *fetch* phase is locked; the expensive bounce
/// analysis runs fully in parallel once the patch bytes are in memory.
static GIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn git_lock() -> &'static Mutex<()> {
    GIT_LOCK.get_or_init(|| Mutex::new(()))
}

// ---------------------------------------------------------------------------
// PR metadata schema (gh pr list --json output)
// ---------------------------------------------------------------------------

/// Minimal PR metadata as returned by `gh pr list --json`.
#[derive(Debug, Deserialize)]
struct PrMeta {
    number: u64,
    #[serde(default)]
    author: Option<AuthorLogin>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    mergeable: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorLogin {
    login: Option<String>,
}

// ---------------------------------------------------------------------------
// Minimal shape of `janitor bounce --format json` stdout
// ---------------------------------------------------------------------------

/// Fields extracted from `janitor bounce --format json` stdout for progress display.
///
/// The bounce engine writes the canonical ndjson log internally; this struct
/// is used only for the per-PR progress line emitted to stderr.
#[derive(Debug, Deserialize, Default)]
struct BounceJson {
    /// Composite slop score.  Stored as `f64` in the bounce JSON; `u32` would
    /// cause serde_json to reject the float literal and silently default to 0.
    #[serde(default)]
    slop_score: f64,
    #[serde(default)]
    unlinked_pr: u32,
    #[serde(default)]
    antipatterns_found: u32,
}

// ---------------------------------------------------------------------------
// CLI configuration
// ---------------------------------------------------------------------------

/// Parsed command-line configuration for gauntlet-runner.
struct Config {
    /// Path to the targets file (one `owner/repo` per line).
    targets_file: PathBuf,
    /// Maximum number of PRs to bounce per repository.
    pr_limit: usize,
    /// Per-PR bounce timeout in seconds.
    timeout_s: u64,
    /// Path to the `janitor` release binary.
    janitor_bin: PathBuf,
    /// Root directory where per-repo directories (and their `.janitor/` logs) live.
    gauntlet_dir: PathBuf,
    /// Directory where the final PDF and CSV artifacts are written.
    out_dir: PathBuf,
    /// When `true`, bypass `gh pr diff`/rayon and use `janitor hyper-drive` instead.
    ///
    /// Clones each repo if absent, populates `refs/remotes/origin/pr/*` via a
    /// packfile fetch, then invokes the libgit2 in-memory bounce engine.
    /// Zero network calls during scoring after the initial fetch.
    hyper: bool,
    /// When `true`, do not purge existing bounce logs and pass `--resume` to
    /// `janitor hyper-drive` so interrupted runs continue from where they left off.
    resume: bool,
    /// Number of parallel bounce workers per repo.
    ///
    /// `0` (the default) triggers hardware-aware auto-detection via
    /// [`detect_optimal_concurrency`]: 2 workers on < 8 GiB, 4 on 8–16 GiB,
    /// 8 on 16–32 GiB, logical-CPU-count on > 32 GiB.
    concurrency: usize,
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().collect();
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_owned());

    // Defaults.
    let mut targets_file = PathBuf::from("gauntlet_targets.txt");
    let mut pr_limit: usize = std::env::var("PR_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(100);
    let mut timeout_s: u64 = std::env::var("BOUNCE_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let mut janitor_bin = PathBuf::from(
        std::env::var("JANITOR").unwrap_or_else(|_| "./target/release/janitor".into()),
    );
    let mut gauntlet_dir = PathBuf::from(
        std::env::var("GAUNTLET_DIR").unwrap_or_else(|_| format!("{home}/dev/gauntlet")),
    );
    let mut out_dir = PathBuf::from(std::env::var("OUTPUT_DIR").unwrap_or_else(|_| ".".into()));
    let mut hyper = false;
    let mut resume = false;
    let mut concurrency: usize = 0; // 0 = auto-detect

    let mut i = 1usize;
    while i < args.len() {
        match args[i].as_str() {
            "--targets" => {
                i += 1;
                targets_file = PathBuf::from(args.get(i).ok_or("--targets requires a file path")?);
            }
            "--pr-limit" => {
                i += 1;
                pr_limit = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--pr-limit requires an integer")?;
            }
            "--timeout" => {
                i += 1;
                timeout_s = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--timeout requires an integer")?;
            }
            "--janitor" => {
                i += 1;
                janitor_bin = PathBuf::from(args.get(i).ok_or("--janitor requires a file path")?);
            }
            "--gauntlet-dir" => {
                i += 1;
                gauntlet_dir = PathBuf::from(
                    args.get(i)
                        .ok_or("--gauntlet-dir requires a directory path")?,
                );
            }
            "--out-dir" => {
                i += 1;
                out_dir = PathBuf::from(args.get(i).ok_or("--out-dir requires a directory path")?);
            }
            "--hyper" => {
                hyper = true;
            }
            "--resume" => {
                resume = true;
            }
            "--concurrency" => {
                i += 1;
                concurrency = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--concurrency requires a non-negative integer (0 = auto)")?;
            }
            unknown => {
                return Err(format!(
                    "Unknown argument: {unknown}\n\
                     Usage: gauntlet-runner [--targets FILE] [--pr-limit N] \
                     [--timeout S] [--janitor PATH] [--gauntlet-dir DIR] [--out-dir DIR] \
                     [--hyper] [--resume] [--concurrency N]"
                ));
            }
        }
        i += 1;
    }

    Ok(Config {
        targets_file,
        pr_limit,
        timeout_s,
        janitor_bin,
        gauntlet_dir,
        out_dir,
        hyper,
        resume,
        concurrency,
    })
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    let cfg = match parse_args() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    };

    // ── Validate prerequisites ───────────────────────────────────────────────
    if !cfg.janitor_bin.is_file() {
        eprintln!(
            "error: janitor binary not found at `{}`. Run: just build",
            cfg.janitor_bin.display()
        );
        std::process::exit(1);
    }

    // ── Read targets file ────────────────────────────────────────────────────
    let targets_raw = match std::fs::read_to_string(&cfg.targets_file) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: Cannot read targets file `{}`: {e}",
                cfg.targets_file.display()
            );
            std::process::exit(1);
        }
    };

    let targets: Vec<String> = targets_raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();

    if targets.is_empty() {
        eprintln!(
            "error: No targets found in `{}`. \
             Add one `owner/repo` slug per line.",
            cfg.targets_file.display()
        );
        std::process::exit(1);
    }

    // Resolve worker count: 0 = hardware-aware auto-detection.
    let workers = if cfg.concurrency == 0 {
        detect_optimal_concurrency()
    } else {
        cfg.concurrency
    };

    eprintln!(
        "gauntlet-runner: {} repos | pr-limit={} | timeout={}s | workers={} | gauntlet-dir={} | mode={}",
        targets.len(),
        cfg.pr_limit,
        cfg.timeout_s,
        workers,
        cfg.gauntlet_dir.display(),
        if cfg.hyper {
            "hyper-drive"
        } else {
            "parallel-bounce"
        }
    );

    // Ensure the gauntlet root exists.
    if let Err(e) = std::fs::create_dir_all(&cfg.gauntlet_dir) {
        eprintln!(
            "error: Cannot create gauntlet directory `{}`: {e}",
            cfg.gauntlet_dir.display()
        );
        std::process::exit(1);
    }

    // ── Process each repo sequentially ──────────────────────────────────────
    let mut total_processed = 0usize;
    let mut total_skipped = 0usize;
    let mut total_errors = 0usize;

    for repo_slug in &targets {
        let repo_name = match repo_slug.split('/').nth(1) {
            Some(n) => n,
            None => {
                eprintln!("warning: Skipping malformed slug `{repo_slug}` (expected owner/repo)");
                continue;
            }
        };

        eprintln!(
            "\n==> [{repo_slug}]  mode={}  limit={}",
            if cfg.hyper {
                "hyper-drive"
            } else {
                "parallel-bounce"
            },
            cfg.pr_limit
        );

        let repo_dir = cfg.gauntlet_dir.join(repo_name);
        // Bounce log path — used by both modes when the directory already exists.
        let log_path = repo_dir.join(".janitor").join("bounce_log.ndjson");

        if cfg.hyper {
            // ── Hyper-Drive execution arm ─────────────────────────────────────
            let repo_dir_str = repo_dir.to_str().unwrap_or(".");

            // Phase 1: idempotent blobless clone guard.
            //
            // Guard on `.git` specifically — NOT `repo_dir.exists()`.
            // Legacy runs leave a `.janitor/` directory without a `.git/`.
            // Remove any such directory first so git clone has a clean target.
            let git_dir = repo_dir.join(".git");
            if !git_dir.exists() {
                let clone_url = format!("https://github.com/{repo_slug}.git");

                // Remove any existing non-git directory (legacy .janitor/ artefacts
                // or partial runs) — git clone aborts on non-empty targets.
                if repo_dir.exists() {
                    // In resume mode: save the existing bounce log before wiping the
                    // directory so the hyper-drive resume filter can read it after
                    // the fresh clone.  Prior standard-mode runs leave a .janitor/
                    // directory (with a valid bounce log) but no .git/ — without this
                    // save/restore the resume flag would be silently ineffective.
                    let saved_log: Option<Vec<u8>> = if cfg.resume && log_path.exists() {
                        match std::fs::read(&log_path) {
                            Ok(b) => {
                                eprintln!(
                                    "  Resume mode: preserving bounce log ({} bytes) across clone",
                                    b.len()
                                );
                                Some(b)
                            }
                            Err(e) => {
                                eprintln!("  warning: Could not read bounce log before clone: {e}");
                                None
                            }
                        }
                    } else {
                        None
                    };

                    eprintln!("  Removing legacy directory before blobless clone...");
                    if let Err(e) = std::fs::remove_dir_all(&repo_dir) {
                        eprintln!(
                            "  error: Cannot remove `{}`: {e} — skipping {repo_slug}",
                            repo_dir.display()
                        );
                        total_errors += 1;
                        continue;
                    }

                    // After removal, immediately restore the bounce log so the
                    // gauntlet log-retention check and the hyper-drive resume filter
                    // both see it in the expected location.
                    if let Some(log_bytes) = saved_log {
                        let janitor_dir = repo_dir.join(".janitor");
                        if std::fs::create_dir_all(&janitor_dir).is_ok() {
                            match std::fs::write(&log_path, &log_bytes) {
                                Ok(()) => eprintln!(
                                    "  Resume mode: bounce log restored → {}",
                                    log_path.display()
                                ),
                                Err(e) => eprintln!("  warning: Could not restore bounce log: {e}"),
                            }
                        }
                    }
                }

                eprintln!("  Cloning {clone_url} (full packfile, no checkout)...");
                let status = Command::new("git")
                    .args(["clone", "--no-checkout", &clone_url, repo_dir_str])
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status();
                match status {
                    Ok(s) if s.success() => eprintln!("  Clone complete."),
                    Ok(s) => {
                        eprintln!("  error: git clone exited {s} — skipping {repo_slug}");
                        total_errors += 1;
                        continue;
                    }
                    Err(e) => {
                        eprintln!("  error: git clone exec failed: {e} — skipping {repo_slug}");
                        total_errors += 1;
                        continue;
                    }
                }
            } else {
                // Verify the existing clone tracks the correct remote.
                // A stale or re-used directory might point at the wrong repo.
                let expected_url = format!("https://github.com/{repo_slug}.git");
                let actual_url = Command::new("git")
                    .args(["-C", repo_dir_str, "remote", "get-url", "origin"])
                    .output()
                    .ok()
                    .filter(|o| o.status.success())
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned());

                match actual_url.as_deref() {
                    Some(url) if url == expected_url => {
                        eprintln!("  Git repo exists and remote matches — reusing clone.");
                    }
                    Some(url) => {
                        eprintln!(
                            "  warning: Remote mismatch (got `{url}`, expected `{expected_url}`). \
                             Correcting remote URL..."
                        );
                        let fix = Command::new("git")
                            .args([
                                "-C",
                                repo_dir_str,
                                "remote",
                                "set-url",
                                "origin",
                                &expected_url,
                            ])
                            .status();
                        match fix {
                            Ok(s) if s.success() => eprintln!("  Remote URL corrected."),
                            Ok(s) => {
                                eprintln!(
                                    "  error: git remote set-url exited {s} — skipping {repo_slug}"
                                );
                                total_errors += 1;
                                continue;
                            }
                            Err(e) => {
                                eprintln!("  error: git remote set-url exec failed: {e} — skipping {repo_slug}");
                                total_errors += 1;
                                continue;
                            }
                        }
                    }
                    None => {
                        eprintln!(
                            "  warning: Could not determine remote URL for existing clone. \
                             Proceeding — fetch will fail if the remote is wrong."
                        );
                    }
                }
            }

            // Remove the partial-clone blob filter so the subsequent fetch
            // downloads full blobs for PR head commits.  libgit2 cannot
            // lazy-fetch missing objects — blobs must be physically present
            // in the local packfile or `simulate_merge` returns BlobNotFound.
            let _ = Command::new("git")
                .args([
                    "-C",
                    repo_dir_str,
                    "config",
                    "--local",
                    "--unset-all",
                    "remote.origin.promisor",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("git")
                .args([
                    "-C",
                    repo_dir_str,
                    "config",
                    "--local",
                    "--unset-all",
                    "remote.origin.partialclonefilter",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            // ── Clean slate: purge stale bounce log ───────────────────────────
            // `janitor hyper-drive` is append-only — purge any residual log from
            // prior runs so ghost entries cannot pollute the aggregate report.
            // Skipped in --resume mode: the existing log is the resumption state.
            if !cfg.resume && log_path.exists() {
                if let Err(e) = std::fs::remove_file(&log_path) {
                    eprintln!(
                        "  warning: Could not purge stale bounce log `{}`: {e}",
                        log_path.display()
                    );
                } else {
                    eprintln!("  Stale log purged → {}", log_path.display());
                }
            } else if cfg.resume && log_path.exists() {
                eprintln!(
                    "  Resume mode: retaining existing log → {}",
                    log_path.display()
                );
            }

            // Phase 2: dual refspec — restore standard branch tracking first,
            // then add PR tracking.  `--replace-all` on the first command
            // clears any stale entries; `--add` appends the PR refspec so
            // both refs/heads/* and refs/pull/*/head are fetched.
            let _ = Command::new("git")
                .args([
                    "-C",
                    repo_dir_str,
                    "config",
                    "--local",
                    "--replace-all",
                    "remote.origin.fetch",
                    "+refs/heads/*:refs/remotes/origin/*",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            let _ = Command::new("git")
                .args([
                    "-C",
                    repo_dir_str,
                    "config",
                    "--local",
                    "--add",
                    "remote.origin.fetch",
                    "+refs/pull/*/head:refs/remotes/origin/pr/*",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            // Phase 3a: fetch base branch (full — blobs required for merge-base).
            eprintln!("  Fetching base branch...");
            let _ = Command::new("git")
                .args([
                    "-C",
                    repo_dir_str,
                    "fetch",
                    "origin",
                    "+refs/heads/master:refs/remotes/origin/master",
                    "+refs/heads/main:refs/remotes/origin/main",
                    "--no-tags",
                    "--force",
                    "--quiet",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .status();

            // Phase 3b: targeted PR fetch — query gh for the N newest PR
            // numbers and build one refspec per PR.  A wildcard refspec would
            // download ALL historical PR blobs (100k+ PRs = multi-GB).
            eprintln!(
                "  Fetching {} most recent PR refs (targeted)...",
                cfg.pr_limit
            );
            let pr_numbers = match fetch_pr_list(repo_slug, cfg.pr_limit) {
                Ok(prs) if prs.is_empty() => {
                    eprintln!("  warning: no PRs returned for {repo_slug} — skipping");
                    continue;
                }
                Ok(prs) => prs.into_iter().map(|p| p.number).collect::<Vec<_>>(),
                Err(e) => {
                    eprintln!("  error: gh pr list failed: {e} — skipping {repo_slug}");
                    total_errors += 1;
                    continue;
                }
            };
            eprintln!("  {} PR numbers harvested via gh.", pr_numbers.len());

            // Build one refspec per PR number.  All refspecs fit in a single
            // git fetch invocation (500 × ~60 bytes ≈ 30 KB — well within the
            // Linux ARG_MAX of 2 MB).
            let refspecs: Vec<String> = pr_numbers
                .iter()
                .map(|n| format!("+refs/pull/{n}/head:refs/remotes/origin/pr/{n}"))
                .collect();

            let mut fetch_args = vec![
                "-C".to_string(),
                repo_dir_str.to_string(),
                "fetch".to_string(),
                "origin".to_string(),
                "--no-tags".to_string(),
                "--force".to_string(),
                "--quiet".to_string(),
            ];
            fetch_args.extend(refspecs);

            let bulk_ok = Command::new("git")
                .args(&fetch_args)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);

            if bulk_ok {
                eprintln!("  Targeted PR fetch complete.");
            } else {
                // A Ghost PR (deleted between API harvest and Git fetch) causes
                // the bulk refspec invocation to fail with exit 128.  Degrade
                // to chunked fetches of 100 refs each.  A ghost only contaminates
                // its own chunk of 100, which then falls back to per-PR fetches
                // — bounding the worst-case individual requests to 100 instead
                // of the full PR limit.
                const CHUNK_SIZE: usize = 100;
                let chunks: Vec<&[u64]> = pr_numbers.chunks(CHUNK_SIZE).collect();
                let total_chunks = chunks.len();
                eprintln!(
                    "  warning: Bulk fetch failed (Ghost PR detected). \
                     Degrading to chunked fetch ({total_chunks} chunks of up to {CHUNK_SIZE})..."
                );
                for (chunk_idx, chunk) in chunks.iter().enumerate() {
                    let chunk_num = chunk_idx + 1;
                    eprintln!("  [Fallback] Processing chunk {chunk_num}/{total_chunks}...");
                    let chunk_refspecs: Vec<String> = chunk
                        .iter()
                        .map(|n| format!("+refs/pull/{n}/head:refs/remotes/origin/pr/{n}"))
                        .collect();
                    let mut chunk_args = vec![
                        "-C".to_string(),
                        repo_dir_str.to_string(),
                        "fetch".to_string(),
                        "origin".to_string(),
                        "--no-tags".to_string(),
                        "--force".to_string(),
                        "--quiet".to_string(),
                    ];
                    chunk_args.extend(chunk_refspecs.clone());
                    let chunk_ok = Command::new("git")
                        .args(&chunk_args)
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status()
                        .map(|s| s.success())
                        .unwrap_or(false);
                    if chunk_ok {
                        eprintln!("  [Chunk] Fetched {} PRs seamlessly.", chunk.len());
                    } else {
                        // Ghost PR is within this chunk — iterate 1-by-1.
                        for pr_num in chunk.iter() {
                            let refspec =
                                format!("+refs/pull/{pr_num}/head:refs/remotes/origin/pr/{pr_num}");
                            let _ = Command::new("git")
                                .args([
                                    "-C",
                                    repo_dir_str,
                                    "fetch",
                                    "origin",
                                    &refspec,
                                    "--no-tags",
                                    "--force",
                                ])
                                .stdout(Stdio::null())
                                .stderr(Stdio::null())
                                .status();
                        }
                    }
                }
                eprintln!(
                    "  Fault-tolerant fetch complete ({} refs attempted).",
                    pr_numbers.len()
                );
            }

            // Phase 4: memory-mapped strike.
            eprintln!("  Launching hyper-drive (limit={})...", cfg.pr_limit);
            let mut hd_args = vec![
                "hyper-drive".to_string(),
                repo_dir_str.to_string(),
                "--limit".to_string(),
                cfg.pr_limit.to_string(),
                "--repo-slug".to_string(),
                repo_slug.to_string(),
            ];
            if cfg.resume {
                hd_args.push("--resume".to_string());
            }
            let status = Command::new(&cfg.janitor_bin)
                .args(&hd_args)
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .status();
            match status {
                Ok(s) if s.success() => {
                    eprintln!("  Done  [hyper-drive OK]");
                    // Count as a single "processed" unit for the summary line.
                    total_processed += 1;
                }
                Ok(s) => {
                    eprintln!("  error: hyper-drive exited {s}");
                    total_errors += 1;
                }
                Err(e) => {
                    eprintln!("  error: hyper-drive exec failed: {e}");
                    total_errors += 1;
                }
            }
        } else {
            // ── Standard parallel-bounce execution arm ────────────────────────

            // Create the repo directory so the janitor binary can write its
            // `.janitor/bounce_log.ndjson` log even without a full git clone.
            if let Err(e) = std::fs::create_dir_all(&repo_dir) {
                eprintln!(
                    "  error: Cannot create repo dir `{}`: {e} — skipping",
                    repo_dir.display()
                );
                continue;
            }

            // ── Clean slate: purge stale bounce log ───────────────────────────
            // `janitor bounce` is append-only — delete any residual log before
            // dispatching the rayon pool so ghost entries from prior runs
            // cannot pollute this repo's aggregate report.
            // Skipped in --resume mode.
            if !cfg.resume && log_path.exists() {
                if let Err(e) = std::fs::remove_file(&log_path) {
                    eprintln!(
                        "  warning: Could not purge stale bounce log `{}`: {e}",
                        log_path.display()
                    );
                } else {
                    eprintln!("  Stale log purged → {}", log_path.display());
                }
            }

            eprintln!("  fetching up to {} PRs...", cfg.pr_limit);

            // ── Fetch PR metadata ─────────────────────────────────────────────
            let prs = match fetch_pr_list(repo_slug, cfg.pr_limit) {
                Ok(v) => v,
                Err(e) => {
                    eprintln!("  error: {e} — skipping {repo_slug}");
                    total_errors += 1;
                    continue;
                }
            };

            let total = prs.len();
            eprintln!("  {total} PRs fetched (after conflict filter) for {repo_slug}");
            eprintln!(
                "  Engine log → {}/.janitor/bounce_log.ndjson",
                repo_dir.display()
            );

            // ── Atomic counters for this repo ─────────────────────────────────
            use std::sync::atomic::{AtomicUsize, Ordering};
            let processed = Arc::new(AtomicUsize::new(0));
            let skipped = Arc::new(AtomicUsize::new(0));
            let errors = Arc::new(AtomicUsize::new(0));

            // Shared config references for rayon closure.
            let janitor_bin = &cfg.janitor_bin;
            let repo_dir_ref = &repo_dir;
            let repo_slug_ref = repo_slug.as_str();
            let timeout_s = cfg.timeout_s;

            // ── Hardware-aware rayon pool ─────────────────────────────────────
            // `workers` was resolved from --concurrency or detect_optimal_concurrency()
            // at startup; use it here so every repo benefits from the same setting.
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(workers)
                .thread_name(|i| format!("bounce-worker-{i}"))
                .build()
                .expect("rayon pool build failed");

            pool.install(|| {
                prs.par_iter().for_each(|pr| {
                    let number = pr.number;
                    let author = pr
                        .author
                        .as_ref()
                        .and_then(|a| a.login.as_deref())
                        .unwrap_or("unknown");
                    let body = pr.body.as_deref().unwrap_or("");
                    let state = pr.state.as_deref().unwrap_or("OPEN").to_ascii_lowercase();

                    // ── Fetch diff (git-lock protected) ───────────────────────
                    let patch_bytes = {
                        let _guard = match git_lock().lock() {
                            Ok(g) => g,
                            Err(_) => {
                                eprintln!("  #{number:<6} GIT LOCK POISONED — skipping");
                                skipped.fetch_add(1, Ordering::Relaxed);
                                return;
                            }
                        };
                        fetch_diff(repo_slug_ref, number)
                    };

                    let patch_bytes = match patch_bytes {
                        Ok(b) if b.is_empty() => {
                            eprintln!("  #{number:<6} [{author}] SKIP: empty/binary-only diff");
                            skipped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                        Ok(b) => b,
                        Err(e) => {
                            eprintln!("  #{number:<6} [{author}] SKIP: {e}");
                            skipped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    };

                    // ── Bounce (runs fully in parallel) ───────────────────────
                    let result = run_bounce(
                        janitor_bin,
                        repo_dir_ref,
                        &patch_bytes,
                        number,
                        author,
                        body,
                        &state,
                        repo_slug_ref,
                        timeout_s,
                    );

                    match result {
                        Ok(bj) => {
                            let mut flags = String::new();
                            if bj.unlinked_pr != 0 {
                                flags.push_str(" [NO-ISSUE]");
                            }
                            if bj.antipatterns_found > 0 {
                                flags.push_str(&format!(" [ANTI×{}]", bj.antipatterns_found));
                            }
                            eprintln!(
                                "  #{number:<6} [{author:<20}] OK   state={state}  score={}{flags}",
                                bj.slop_score
                            );
                            processed.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => {
                            eprintln!("  #{number:<6} [{author:<20}] ERR  {e}");
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                });
            });

            let p = processed.load(Ordering::Relaxed);
            let s = skipped.load(Ordering::Relaxed);
            let e = errors.load(Ordering::Relaxed);
            eprintln!("  Done  processed={p}  skipped={s}  errors={e}");

            total_processed += p;
            total_skipped += s;
            total_errors += e;
        }
    }

    eprintln!(
        "\nAll repos complete.  Total: processed={total_processed}  \
         skipped={total_skipped}  errors={total_errors}"
    );

    // ── Aggregate report + export (parallel) ────────────────────────────────
    let pdf_out = cfg.out_dir.join("gauntlet_intelligence_report.pdf");
    let csv_out = cfg.out_dir.join("gauntlet_export.csv");
    let json_out = cfg.out_dir.join("gauntlet_report.json");
    let gauntlet_dir = cfg.gauntlet_dir.clone();
    let janitor_bin = cfg.janitor_bin.clone();

    eprintln!(
        "\nGenerating aggregate artefacts in parallel:\n  PDF  → {}\n  CSV  → {}\n  JSON → {}",
        pdf_out.display(),
        csv_out.display(),
        json_out.display(),
    );

    let janitor_pdf = janitor_bin.clone();
    let gauntlet_pdf = gauntlet_dir.clone();
    let pdf_path = pdf_out.clone();

    let report_thread = std::thread::spawn(move || {
        run_aggregate_command(
            &janitor_pdf,
            &[
                "report",
                "--global",
                "--gauntlet",
                gauntlet_pdf.to_str().unwrap_or("."),
                "--format",
                "pdf",
                "--out",
                pdf_path
                    .to_str()
                    .unwrap_or("gauntlet_intelligence_report.pdf"),
            ],
            "report --global --format pdf",
        )
    });

    let janitor_json = janitor_bin.clone();
    let gauntlet_json = gauntlet_dir.clone();
    let json_path = json_out.clone();

    let json_thread = std::thread::spawn(move || {
        run_aggregate_command(
            &janitor_json,
            &[
                "report",
                "--global",
                "--gauntlet",
                gauntlet_json.to_str().unwrap_or("."),
                "--format",
                "json",
                "--out",
                json_path.to_str().unwrap_or("gauntlet_report.json"),
            ],
            "report --global --format json",
        )
    });

    let export_result = run_aggregate_command(
        &janitor_bin,
        &[
            "export",
            "--global",
            "--gauntlet-dir",
            gauntlet_dir.to_str().unwrap_or("."),
            "--out",
            csv_out.to_str().unwrap_or("gauntlet_export.csv"),
        ],
        "export --global",
    );

    let report_result = report_thread
        .join()
        .unwrap_or_else(|_| Err("report thread panicked".to_owned()));

    let json_result = json_thread
        .join()
        .unwrap_or_else(|_| Err("json report thread panicked".to_owned()));

    // ── Final status ─────────────────────────────────────────────────────────
    let mut exit_code = 0i32;

    match report_result {
        Ok(()) => eprintln!("PDF report  OK → {}", pdf_out.display()),
        Err(e) => {
            eprintln!("PDF report  FAILED: {e}");
            exit_code = 1;
        }
    }
    match export_result {
        Ok(()) => eprintln!("CSV export  OK → {}", csv_out.display()),
        Err(e) => {
            eprintln!("CSV export  FAILED: {e}");
            exit_code = 1;
        }
    }
    match json_result {
        Ok(()) => eprintln!("JSON report OK → {}", json_out.display()),
        Err(e) => {
            eprintln!("JSON report FAILED: {e}");
            exit_code = 1;
        }
    }

    std::process::exit(exit_code);
}

// ---------------------------------------------------------------------------
// PR list fetch via `gh pr list`
// ---------------------------------------------------------------------------

/// Fetch up to `limit` PR metadata entries for `repo_slug` from GitHub.
///
/// Calls `gh pr list --json number,author,body,state,mergeable` and filters
/// out `CONFLICTING` PRs (same as `generate_client_package.sh`).
fn fetch_pr_list(repo_slug: &str, limit: usize) -> Result<Vec<PrMeta>, String> {
    let output = Command::new("gh")
        .args([
            "pr",
            "list",
            "--repo",
            repo_slug,
            "--state",
            "all",
            "--limit",
            &limit.to_string(),
            "--json",
            "number,author,body,state,mergeable",
        ])
        .output()
        .map_err(|e| format!("gh exec failed: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "gh pr list exited {} for {repo_slug}",
            output.status
        ));
    }

    let all: Vec<PrMeta> = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("Cannot parse gh pr list JSON: {e}"))?;

    // Filter CONFLICTING PRs — they produce meaningless diffs.
    let filtered: Vec<PrMeta> = all
        .into_iter()
        .filter(|pr| {
            pr.mergeable
                .as_deref()
                .map(|m| m != "CONFLICTING")
                .unwrap_or(true)
        })
        .collect();

    Ok(filtered)
}

// ---------------------------------------------------------------------------
// Diff fetch via `gh pr diff`
// ---------------------------------------------------------------------------

/// Fetch the unified diff for `pr_number` from GitHub via `gh pr diff`.
///
/// Returns raw patch bytes with only unparseable binary-extension hunks
/// stripped.  Vendored directories (`thirdparty/`, `vendor/`, etc.) and test
/// files are passed through so the engine's domain router can classify them.
/// **The caller MUST hold [`git_lock()`] while this function executes.**
fn fetch_diff(repo_slug: &str, pr_number: u64) -> Result<Vec<u8>, String> {
    let output = Command::new("gh")
        .args(["pr", "diff", &pr_number.to_string(), "--repo", repo_slug])
        .output()
        .map_err(|e| format!("gh exec failed: {e}"))?;

    if !output.status.success() {
        return Err(format!("gh pr diff exited {}", output.status));
    }

    Ok(strip_binary_hunks(&output.stdout))
}

/// Strip only binary-extension hunks from a unified diff.
///
/// Vendored directories (`thirdparty/`, `vendor/`, etc.) are intentionally
/// left in the patch so the engine's domain router can classify them correctly.
/// Only truly unparseable binary blobs (images, compiled objects, archives)
/// are dropped to prevent the tree-sitter parser from choking on binary bytes.
fn strip_binary_hunks(patch: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(patch.len());
    let mut skip = false;

    for line in patch.split(|&b| b == b'\n') {
        if line.starts_with(b"diff --git ") {
            let s = String::from_utf8_lossy(line);
            skip = has_binary_extension(&s);
        }
        if !skip {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    out
}

/// Returns `true` if the last path token in a `diff --git` header has a known
/// binary extension.
fn has_binary_extension(diff_header: &str) -> bool {
    const BIN: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".webp", ".ttf", ".otf", ".woff",
        ".woff2", ".bin", ".a", ".so", ".dll", ".exe", ".zip", ".tar", ".gz", ".bz2", ".xz",
    ];
    let path = diff_header.split_whitespace().next_back().unwrap_or("");
    BIN.iter().any(|ext| path.ends_with(ext))
}

// ---------------------------------------------------------------------------
// Bounce invocation
// ---------------------------------------------------------------------------

/// Invoke `janitor bounce` with the patch supplied via a temp file.
///
/// Respects `timeout_s`: kills the child process if it exceeds the deadline.
/// Returns a parsed [`BounceJson`] for the progress display line.
///
/// The bounce engine writes the canonical ndjson log entry internally.
#[allow(clippy::too_many_arguments)]
fn run_bounce(
    janitor_bin: &Path,
    repo_dir: &Path,
    patch: &[u8],
    pr_number: u64,
    author: &str,
    pr_body: &str,
    pr_state: &str,
    repo_slug: &str,
    timeout_s: u64,
) -> Result<BounceJson, String> {
    let body = truncate_utf8(pr_body, 4096);
    let num_str = pr_number.to_string();

    // Write patch to a temp file — `janitor bounce --patch <path>` requires a
    // filesystem path, not a stdin stream.
    let tmp_path = std::env::temp_dir().join(format!("gr_patch_{pr_number}.patch"));
    std::fs::write(&tmp_path, patch).map_err(|e| format!("write temp patch: {e}"))?;
    let tmp_str = tmp_path.to_str().unwrap_or("");

    let mut child = Command::new(janitor_bin)
        .args([
            "bounce",
            repo_dir.to_str().unwrap_or("."),
            "--patch",
            tmp_str,
            "--pr-number",
            &num_str,
            "--author",
            author,
            "--pr-body",
            body,
            "--pr-state",
            pr_state,
            "--repo-slug",
            repo_slug,
            "--format",
            "json",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn janitor: {e}"))?;

    // Drain stdout in a background thread to prevent the child from blocking
    // on a full pipe buffer while the main thread is in `try_wait()`.
    let stdout_thread = {
        let mut stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        })
    };

    // Poll for exit with a deadline; kill if the timeout elapses.
    let deadline = Instant::now() + Duration::from_secs(timeout_s);
    let exit_status = loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(s) => break s,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("timed out after {timeout_s}s"));
            }
            None => std::thread::sleep(Duration::from_millis(50)),
        }
    };

    let stdout_bytes = stdout_thread.join().unwrap_or_default();

    // Always clean up the temp file.
    let _ = std::fs::remove_file(&tmp_path);

    if !exit_status.success() {
        return Err(format!("janitor exited {exit_status}"));
    }

    // Parse progress fields from JSON stdout; fall back to defaults on parse
    // error (the engine still ran and wrote its internal ndjson log).
    let bj: BounceJson = serde_json::from_slice(&stdout_bytes).unwrap_or_default();
    Ok(bj)
}

// ---------------------------------------------------------------------------
// Aggregate command runner
// ---------------------------------------------------------------------------

/// Invoke `janitor <args>` and wait for it to exit successfully.
///
/// Used to run `janitor report --global` and `janitor export --global` after
/// all repos have been processed.  Returns `Ok(())` on exit 0, `Err` otherwise.
fn run_aggregate_command(janitor_bin: &Path, args: &[&str], label: &str) -> Result<(), String> {
    let status = Command::new(janitor_bin)
        .args(args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|e| format!("spawn `{label}`: {e}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!("`{label}` exited {status}"))
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Truncate `s` to at most `max_bytes`, respecting UTF-8 character boundaries.
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut idx = max_bytes;
    while !s.is_char_boundary(idx) {
        idx -= 1;
    }
    &s[..idx]
}
