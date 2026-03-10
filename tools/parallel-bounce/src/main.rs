//! parallel-bounce — Rust-native parallel PR bounce worker.
//!
//! Reads the PR JSON cache produced by `generate_client_package.sh` and
//! bounces PRs in parallel against the local `janitor` binary.
//!
//! # Hardware gates
//!
//! - **RAM gate**: a 2-thread rayon pool.  Each `janitor bounce` peaks at
//!   ≈100–250 MB; 2 concurrent workers stay well under 8 GB.
//! - **Git lock**: a global `Mutex<()>` serialises every `gh pr diff`
//!   subprocess spawn.  Prevents OS-level file-descriptor exhaustion and
//!   pack-index races when two workers try to open the same git objects
//!   simultaneously.
//!
//! # Usage
//!
//! ```
//! parallel-bounce <cache.json> <repo_dir> <janitor_bin> <repo_slug> \
//!   [--limit N] [--timeout S]
//! ```
//!
//! Engine ndjson log is written internally by `janitor bounce` to
//! `<repo_dir>/.janitor/bounce_log.ndjson`.
//!
//! # Environment
//!
//! - `BOUNCE_TIMEOUT` — per-PR timeout in seconds (default: 30; overridden by `--timeout`)

use std::{
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

use rayon::prelude::*;
use serde::Deserialize;

// ---------------------------------------------------------------------------
// Git-operation serialization lock
// ---------------------------------------------------------------------------

/// Global mutex that serialises every `gh pr diff` subprocess spawn.
///
/// Prevents concurrent processes from racing on OS pipe tables or the
/// git pack-index lock when both workers hit the same object store.
/// Only the *fetch* phase is locked; the (expensive) bounce analysis
/// runs fully in parallel once the patch bytes are in memory.
static GIT_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

fn git_lock() -> &'static Mutex<()> {
    GIT_LOCK.get_or_init(|| Mutex::new(()))
}

// ---------------------------------------------------------------------------
// PR metadata schema  (mirrors generate_client_package.sh cache JSON)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct PrMeta {
    number: u64,
    #[serde(default)]
    author: Option<AuthorLogin>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    state: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorLogin {
    login: Option<String>,
}

// ---------------------------------------------------------------------------
// Minimal shape of `janitor bounce --format json` stdout
// ---------------------------------------------------------------------------

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
// CLI config
// ---------------------------------------------------------------------------

struct Config {
    cache_json: PathBuf,
    repo_dir: PathBuf,
    janitor_bin: PathBuf,
    repo_slug: String,
    limit: usize,
    timeout_s: u64,
}

fn parse_args() -> Result<Config, String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 5 {
        return Err(format!(
            "Usage: {} <cache.json> <repo_dir> <janitor_bin> <repo_slug> \
             [--limit N] [--timeout S]",
            args[0]
        ));
    }

    let cache_json = PathBuf::from(&args[1]);
    let repo_dir = PathBuf::from(&args[2]);
    let janitor_bin = PathBuf::from(&args[3]);
    let repo_slug = args[4].clone();

    let mut limit = usize::MAX;
    let mut timeout_s = std::env::var("BOUNCE_TIMEOUT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(30u64);

    let mut i = 5usize;
    while i < args.len() {
        match args[i].as_str() {
            "--limit" => {
                i += 1;
                limit = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--limit requires an integer")?;
            }
            "--timeout" => {
                i += 1;
                timeout_s = args
                    .get(i)
                    .and_then(|v| v.parse().ok())
                    .ok_or("--timeout requires an integer")?;
            }
            _ => {}
        }
        i += 1;
    }

    Ok(Config {
        cache_json,
        repo_dir,
        janitor_bin,
        repo_slug,
        limit,
        timeout_s,
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

    // ── Load PR cache ────────────────────────────────────────────────────────
    let raw = match std::fs::read_to_string(&cfg.cache_json) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Cannot read {}: {e}", cfg.cache_json.display());
            std::process::exit(1);
        }
    };
    let all_prs: Vec<PrMeta> = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Cannot parse cache JSON: {e}");
            std::process::exit(1);
        }
    };

    let prs: Vec<PrMeta> = all_prs.into_iter().take(cfg.limit).collect();
    let total = prs.len();

    eprintln!(
        "parallel-bounce: {total} PRs | 2-worker RAM gate | repo={}",
        cfg.repo_slug
    );
    eprintln!(
        "Engine log → {}/.janitor/bounce_log.ndjson",
        cfg.repo_dir.display()
    );

    // ── Atomic counters ──────────────────────────────────────────────────────
    use std::sync::atomic::{AtomicUsize, Ordering};
    let processed = Arc::new(AtomicUsize::new(0));
    let skipped = Arc::new(AtomicUsize::new(0));
    let errors = Arc::new(AtomicUsize::new(0));

    // ── RAM gate: 2-thread rayon pool ────────────────────────────────────────
    // 2 workers × ≤250 MB peak RSS = ≤500 MB; safe headroom on 8 GB systems.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
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
            // GitHub returns OPEN / MERGED / CLOSED — normalise to lowercase.
            let state = pr.state.as_deref().unwrap_or("OPEN").to_ascii_lowercase();

            // ── Fetch diff (git-lock protected) ─────────────────────────────
            // Serialise subprocess launches to prevent fd exhaustion and
            // git pack-index races between concurrent workers.
            let patch_bytes = {
                let _guard = match git_lock().lock() {
                    Ok(g) => g,
                    Err(_) => {
                        eprintln!("  #{number:<6} GIT LOCK POISONED — skipping");
                        skipped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                fetch_diff(&cfg.repo_slug, number)
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

            // ── Bounce (runs fully in parallel) ──────────────────────────────
            let result = run_bounce(
                &cfg.janitor_bin,
                &cfg.repo_dir,
                &patch_bytes,
                number,
                author,
                body,
                &state,
                &cfg.repo_slug,
                cfg.timeout_s,
            );

            match result {
                Ok(bj) => {
                    // Build a compact progress annotation from the parsed JSON.
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

    eprintln!("\nDone  processed={p}  skipped={s}  errors={e}");
}

// ---------------------------------------------------------------------------
// Diff fetch via `gh pr diff`
// ---------------------------------------------------------------------------

/// Fetch the unified diff for `pr_number` from GitHub via `gh pr diff`.
///
/// Returns raw patch bytes with vendor/binary hunks stripped.
/// The caller MUST hold [`git_lock()`] while this function executes.
fn fetch_diff(repo_slug: &str, pr_number: u64) -> Result<Vec<u8>, String> {
    let output = Command::new("gh")
        .args(["pr", "diff", &pr_number.to_string(), "--repo", repo_slug])
        .output()
        .map_err(|e| format!("gh exec failed: {e}"))?;

    if !output.status.success() {
        return Err(format!("gh pr diff exited {}", output.status));
    }

    Ok(strip_vendor_hunks(&output.stdout))
}

/// Strip vendor, thirdparty, and binary-extension hunks from a unified diff.
///
/// Mirrors the `awk` filter in `generate_client_package.sh` so the two
/// pipelines produce identical patch sets.
fn strip_vendor_hunks(patch: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(patch.len());
    let mut skip = false;

    for line in patch.split(|&b| b == b'\n') {
        if line.starts_with(b"diff --git ") {
            let s = String::from_utf8_lossy(line);
            skip = s.contains("/thirdparty/")
                || s.contains("/third_party/")
                || s.contains("/vendor/")
                || s.contains("/tests/")
                || has_binary_extension(&s);
        }
        if !skip {
            out.extend_from_slice(line);
            out.push(b'\n');
        }
    }
    out
}

/// Returns `true` if the last path token in a `diff --git` header ends with a
/// known binary extension.
fn has_binary_extension(diff_header: &str) -> bool {
    const BIN: &[&str] = &[
        ".png", ".jpg", ".jpeg", ".svg", ".gif", ".ico", ".webp", ".ttf", ".otf", ".woff",
        ".woff2", ".bin", ".a", ".so", ".dll", ".exe", ".zip", ".tar", ".gz", ".bz2", ".xz",
    ];
    // The b/… path is the last whitespace-separated token in the header.
    let path = diff_header.split_whitespace().next_back().unwrap_or("");
    BIN.iter().any(|ext| path.ends_with(ext))
}

// ---------------------------------------------------------------------------
// Bounce invocation
// ---------------------------------------------------------------------------

/// Invoke `janitor bounce` with the patch supplied via stdin.
///
/// Returns a parsed [`BounceJson`] with score and flag fields, or an error
/// string. The body is clamped to 4 096 bytes at a valid UTF-8 boundary to
/// mirror the bash script's `head -c 4096`.
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

    // Write patch to a named temp file.
    //
    // The `janitor bounce` CLI treats `--patch <path>` as a filesystem path;
    // passing `-` would attempt to open a file literally named `-`.  Writing
    // to a temp file avoids the issue while keeping the per-PR isolation the
    // bash script achieves with `mktemp`.
    let tmp_path = std::env::temp_dir().join(format!("pb_patch_{pr_number}.patch"));
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
    // on a full pipe buffer while the main thread is in try_wait().
    let stdout_thread = {
        let mut stdout = child.stdout.take().unwrap();
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = stdout.read_to_end(&mut buf);
            buf
        })
    };

    // Poll for exit with a deadline — kill if the timeout elapses.
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

    // Always remove the temp patch file, regardless of outcome.
    let _ = std::fs::remove_file(&tmp_path);

    if !exit_status.success() {
        return Err(format!("janitor exited {exit_status}"));
    }

    // Parse the JSON stdout for progress fields; fall back to defaults on
    // parse error (engine still ran successfully — log is written internally).
    let bj: BounceJson = serde_json::from_slice(&stdout_bytes).unwrap_or_default();
    Ok(bj)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Truncate `s` to at most `max_bytes`, respecting UTF-8 char boundaries.
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
