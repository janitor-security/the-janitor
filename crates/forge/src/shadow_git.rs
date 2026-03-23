//! # Shadow Git — In-Memory PR Merge Simulation
//!
//! Extracts changed-file blobs from a git repository into RAM without touching
//! the working directory.  Enables the Forge pipeline to analyse an entire PR
//! diff at the blob level with no disk I/O beyond pack-index lookups.
//!
//! ## Memory Budget
//! For a 5M-LOC repository with 1000 changed files (~12 KiB each):
//! - Blob data: ~12.0 MiB
//! - HashMap overhead: ~0.1 MiB
//! - libgit2 diff transient: ~0.3 MiB
//! - **Total: ~12.4 MiB** (1.5 % of a full 800 MiB checkout)
//!
//! ## Platform
//! Requires libgit2 (`git2` crate).  This crate is a C binding and requires
//! `libgit2-dev` to be installed in the build environment.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::PathBuf;

use git2::{Oid, Repository};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Chemotaxis constants
// ---------------------------------------------------------------------------

/// High-calorie slop-vector extensions — processed first in priority ordering.
///
/// These file types carry the densest signal for structural analysis:
/// compiled languages (.rs, .go), scripting (.py, .js, .ts), and typed
/// supersets (.tsx, .jsx).  Low-calorie files (.md, .txt, config blobs) are
/// deferred to the end of the processing queue.
const SLOP_VECTOR_PRIORITY: &[&str] = &[
    "rs", "py", "go", "js", "ts", "tsx", "jsx", "cs", "java", "cpp", "cc", "cxx", "c",
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The result of an in-memory merge simulation between two commits.
#[derive(Debug)]
pub struct MergeSnapshot {
    /// Changed and added files: path → raw blob bytes.
    ///
    /// Contains the full HEAD blob for each changed file.  Routed ONLY to the
    /// `IncludeGraphBuilder` (include-graph analysis) and `semantic_null_pr_check`
    /// (full-file AST comparison).  MUST NOT be fed directly into `PatchBouncer`
    /// — doing so causes NCD and clone detection to evaluate unchanged file history
    /// rather than the PR delta, inflating scores on small PRs in large files.
    pub blobs: HashMap<PathBuf, Vec<u8>>,
    /// Per-file unified diff text: path → actual patch string.
    ///
    /// Populated by `simulate_merge` via `diff.foreach` — contains only the
    /// genuinely added, removed, and context lines for each changed file,
    /// exactly as git computed them.  This is the payload that `PatchBouncer`
    /// MUST receive: it ensures NCD entropy, clone detection, and `slop_hunter`
    /// evaluate only the code introduced by the PR.
    pub patches: HashMap<PathBuf, String>,
    /// Deleted file paths (no content — file was removed).
    pub deleted: Vec<PathBuf>,
    /// Total bytes loaded across all blobs.
    pub total_bytes: usize,
}

impl MergeSnapshot {
    /// Iterate blobs in **chemotaxis order**: high-calorie slop vectors first.
    ///
    /// Files whose extension appears in [`SLOP_VECTOR_PRIORITY`] are returned
    /// before all others, allowing the bounce pipeline to surface structural
    /// violations early and abort cheaply when a score ceiling is exceeded.
    ///
    /// Within each priority tier, paths are sorted lexicographically for
    /// determinism across runs.
    pub fn iter_by_priority(&self) -> Vec<(&PathBuf, &Vec<u8>)> {
        let mut pairs: Vec<(&PathBuf, &Vec<u8>)> = self.blobs.iter().collect();
        pairs.sort_by(|(a, _), (b, _)| {
            let priority = |p: &PathBuf| -> u8 {
                let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
                if SLOP_VECTOR_PRIORITY.contains(&ext) {
                    0
                } else {
                    1
                }
            };
            priority(a).cmp(&priority(b)).then_with(|| a.cmp(b))
        });
        pairs
    }
}

/// Errors from [`simulate_merge`].
#[derive(Debug, Error)]
pub enum MergeError {
    #[error("git2 error: {0}")]
    Git(#[from] git2::Error),

    #[error("blob for path '{path}' could not be resolved (oid={oid})")]
    BlobNotFound { path: String, oid: Oid },

    #[error("diff delta had no new-file entry for path '{0}'")]
    MissingNewFile(String),
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Simulate an in-memory merge of `head_oid` onto `base_oid` in `repo`.
///
/// Returns a [`MergeSnapshot`] containing the raw bytes of every file
/// modified or added by the merge, plus a list of deleted paths.
///
/// No working-directory checkout is performed: all data is read from the
/// pack index via libgit2's ODB.
///
/// # Errors
/// Returns [`MergeError`] if any git operation fails or a blob cannot be found.
pub fn simulate_merge(
    repo: &Repository,
    base_oid: Oid,
    head_oid: Oid,
) -> Result<MergeSnapshot, MergeError> {
    let base_commit = repo.find_commit(base_oid)?;
    let head_commit = repo.find_commit(head_oid)?;

    let base_tree = base_commit.tree()?;
    let head_tree = head_commit.tree()?;

    let diff = repo.diff_tree_to_tree(Some(&base_tree), Some(&head_tree), None)?;

    let mut blobs: HashMap<PathBuf, Vec<u8>> = HashMap::new();
    let mut deleted: Vec<PathBuf> = Vec::new();
    let mut total_bytes: usize = 0;

    for delta in diff.deltas() {
        use git2::Delta;

        match delta.status() {
            Delta::Added | Delta::Modified | Delta::Renamed | Delta::Typechange | Delta::Copied => {
                let new_file = delta.new_file();
                let path_str = new_file
                    .path()
                    .ok_or_else(|| MergeError::MissingNewFile("(unknown)".to_string()))?;
                let path = path_str.to_path_buf();
                let oid = new_file.id();

                if oid.is_zero() {
                    // Working-tree file without a blob OID — skip.
                    continue;
                }

                let blob = repo.find_blob(oid).map_err(|_| MergeError::BlobNotFound {
                    path: path.display().to_string(),
                    oid,
                })?;

                let content = blob.content().to_vec();
                total_bytes += content.len();
                blobs.insert(path, content);
            }
            Delta::Deleted => {
                if let Some(old_path) = delta.old_file().path() {
                    deleted.push(old_path.to_path_buf());
                }
            }
            // Unmodified, ignored, conflicted, untracked — skip.
            _ => {}
        }
    }

    // ── Per-file diff text (Payload Bifurcation) ──────────────────────────────
    //
    // Build a unified diff string for each changed file using `diff.foreach`.
    // This is the payload that `bounce_git` feeds to `PatchBouncer::bounce` —
    // it contains ONLY the genuinely added/removed/context lines, not the full
    // blob.  Prevents NCD and clone detection from inflating scores by evaluating
    // historical file content that the PR did not touch.
    //
    // `RefCell` is required because `diff.foreach` accepts three separate closure
    // arguments (file_cb, hunk_cb, line_cb) that all need mutable access to the
    // `patches` map.  The callbacks are invoked sequentially — never concurrently —
    // so `RefCell::borrow_mut()` never panics at runtime.
    let patches: RefCell<HashMap<PathBuf, String>> = RefCell::new(HashMap::new());

    let _ = diff.foreach(
        &mut |delta, _progress| {
            use git2::Delta;
            // Only create patch entries for non-deleted files.
            if !matches!(
                delta.status(),
                Delta::Added | Delta::Modified | Delta::Renamed | Delta::Typechange | Delta::Copied
            ) {
                return true;
            }
            if let Some(path) = delta.new_file().path() {
                let path_str = path.to_str().unwrap_or("");
                // Initialise the entry with the unified diff header.  The `---`
                // line uses the new-file path in all cases (matches PatchBouncer's
                // `extract_patch_path` which reads the `+++` header).
                patches.borrow_mut().insert(
                    path.to_path_buf(),
                    format!("--- a/{path_str}\n+++ b/{path_str}\n"),
                );
            }
            true
        },
        None,
        Some(&mut |delta, hunk| {
            if let Some(path) = delta.new_file().path() {
                if let Some(patch) = patches.borrow_mut().get_mut(&path.to_path_buf()) {
                    // `hunk.header()` is the raw `@@ -x,y +a,b @@\n` bytes.
                    let header = std::str::from_utf8(hunk.header()).unwrap_or("@@ @@\n");
                    patch.push_str(header);
                }
            }
            true
        }),
        Some(&mut |delta, _hunk, line| {
            // Map git2 diff line origin to unified-diff prefix characters.
            // Skip file-header ('F'), hunk-header ('H'), binary ('B'), and
            // no-newline ('\\') origins — hunk headers were appended above.
            let prefix = match line.origin() {
                '+' => "+",
                '-' => "-",
                ' ' | '=' => " ", // context / context-with-no-newline-at-eof
                _ => return true,
            };
            if let Some(path) = delta.new_file().path() {
                if let Some(patch) = patches.borrow_mut().get_mut(&path.to_path_buf()) {
                    let content = std::str::from_utf8(line.content()).unwrap_or("");
                    patch.push_str(prefix);
                    patch.push_str(content);
                    // git2 `line.content()` already includes the trailing `\n`
                    // for normal lines; only add one if the line lacks it.
                    if !content.ends_with('\n') {
                        patch.push('\n');
                    }
                }
            }
            true
        }),
    );

    let patches = patches.into_inner();

    Ok(MergeSnapshot {
        blobs,
        patches,
        deleted,
        total_bytes,
    })
}
