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

use std::collections::HashMap;
use std::path::PathBuf;

use git2::{Oid, Repository};
use thiserror::Error;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The result of an in-memory merge simulation between two commits.
#[derive(Debug)]
pub struct MergeSnapshot {
    /// Changed and added files: path → raw blob bytes.
    pub blobs: HashMap<PathBuf, Vec<u8>>,
    /// Deleted file paths (no content — file was removed).
    pub deleted: Vec<PathBuf>,
    /// Total bytes loaded across all blobs.
    pub total_bytes: usize,
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

    Ok(MergeSnapshot {
        blobs,
        deleted,
        total_bytes,
    })
}
