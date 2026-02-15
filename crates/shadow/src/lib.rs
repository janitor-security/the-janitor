use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

/// Errors from shadow tree operations.
#[derive(Debug, thiserror::Error)]
pub enum ShadowError {
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Walk error: {0}")]
    WalkError(#[from] walkdir::Error),
    #[error("Symlink failure: {0}")]
    SymlinkFailure(String),
}

/// Manages the symlink-based shadow source tree.
///
/// The shadow tree mirrors the source directory structure but uses symlinks
/// for files instead of copies, satisfying the zero-copy constraint.
pub struct ShadowManager {
    source_root: PathBuf,
    shadow_root: PathBuf,
}

impl ShadowManager {
    /// Initialize the shadow tree from a source directory.
    ///
    /// Creates a symlink-based mirror of `source` at `shadow`, skipping
    /// excluded directories (target, .git, .janitor, venv, __pycache__, .venv).
    ///
    /// # Errors
    ///
    /// Returns `ShadowError::SymlinkFailure` on WSL/Windows permission issues.
    /// Enable Developer Mode or run as Administrator to create symlinks.
    pub fn initialize(source: &Path, shadow: &Path) -> Result<Self, ShadowError> {
        // Canonicalize source path to absolute form
        let source_root = fs::canonicalize(source)?;

        // Create shadow root directory
        fs::create_dir_all(shadow)?;
        let shadow_root = fs::canonicalize(shadow)?;

        // Skip list for excluded directories
        let skip_list = ["target", ".git", ".janitor", "venv", "__pycache__", ".venv"];

        // Walk source tree lazily (never collect into memory)
        for entry in WalkDir::new(&source_root).into_iter().filter_entry(|e| {
            // Skip excluded directories
            if let Some(name) = e.file_name().to_str() {
                !skip_list.contains(&name)
            } else {
                true
            }
        }) {
            let entry = entry?;
            let entry_path = entry.path();

            // Get relative path from source root
            let relative = entry_path
                .strip_prefix(&source_root)
                .map_err(|e| ShadowError::IoError(std::io::Error::other(e)))?;

            // Skip the root itself
            if relative.as_os_str().is_empty() {
                continue;
            }

            let shadow_path = shadow_root.join(relative);

            if entry.file_type().is_dir() {
                // Create directory in shadow tree
                fs::create_dir_all(&shadow_path)?;
            } else if entry.file_type().is_file() {
                // Create symlink to original file
                #[cfg(unix)]
                {
                    if let Err(e) = std::os::unix::fs::symlink(entry_path, &shadow_path) {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            return Err(ShadowError::SymlinkFailure(format!(
                                "WSL/Windows symlink failure: Enable Developer Mode or run as Admin. Path: {}",
                                shadow_path.display()
                            )));
                        }
                        return Err(ShadowError::IoError(e));
                    }
                }
                #[cfg(windows)]
                {
                    if let Err(e) = std::os::windows::fs::symlink_file(entry_path, &shadow_path) {
                        if e.kind() == std::io::ErrorKind::PermissionDenied {
                            return Err(ShadowError::SymlinkFailure(format!(
                                "Windows symlink failure: Enable Developer Mode or run as Admin. Path: {}",
                                shadow_path.display()
                            )));
                        }
                        return Err(ShadowError::IoError(e));
                    }
                }
            }
        }

        Ok(ShadowManager {
            source_root,
            shadow_root,
        })
    }

    /// Verify that all symlinks in the shadow tree are valid.
    ///
    /// Returns `Ok(true)` if all symlinks exist and point to valid files,
    /// `Ok(false)` if any symlink is broken.
    pub fn verify_integrity(&self) -> Result<bool, ShadowError> {
        for entry in WalkDir::new(&self.shadow_root).follow_links(false) {
            let entry = entry?;
            let path = entry.path();

            // Check symlinks specifically
            if entry.path_is_symlink() {
                // Use fs::read_link to check if target exists
                if let Ok(target) = fs::read_link(path) {
                    if !target.exists() {
                        return Ok(false);
                    }
                } else {
                    // read_link failed - symlink is broken
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    /// Moves a real file to `.janitor/ghost/{relative_path}` and removes its symlink.
    ///
    /// ## Ghost Protocol
    /// 1. Locate the symlink at `shadow_src/{relative_path}`.
    /// 2. Resolve it to the real file path.
    /// 3. Move the real file into `.janitor/ghost/{relative_path}` (creating parent dirs).
    /// 4. Remove the symlink — the file disappears from the compiler's view.
    ///
    /// The file survives in the Necropolis (`ghost/`) and can be recovered manually.
    ///
    /// # Errors
    /// - `ShadowError::SymlinkFailure` if the symlink cannot be resolved.
    /// - `ShadowError::IoError` on file-system failures.
    pub fn move_to_ghost(&self, relative_path: &Path) -> Result<(), ShadowError> {
        let shadow_path = self.shadow_root.join(relative_path);

        // Resolve the symlink to the real file.
        let real_path = fs::read_link(&shadow_path).map_err(|e| {
            ShadowError::SymlinkFailure(format!(
                "Cannot resolve symlink at {}: {}",
                shadow_path.display(),
                e
            ))
        })?;

        // Build the ghost destination path.
        let ghost_path = self
            .source_root
            .join(".janitor")
            .join("ghost")
            .join(relative_path);

        if let Some(parent) = ghost_path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Attempt an atomic rename first (same-filesystem); fall back to copy + delete.
        if fs::rename(&real_path, &ghost_path).is_err() {
            fs::copy(&real_path, &ghost_path)?;
            fs::remove_file(&real_path)?;
        }

        // Remove the now-dangling symlink from shadow_src.
        fs::remove_file(&shadow_path)?;

        Ok(())
    }

    /// Opens an existing shadow tree without re-scanning the source directory.
    ///
    /// Use this when the shadow tree was already created by [`initialize`] and
    /// you only need a `ShadowManager` handle to call `unmap` / `remap`.
    pub fn open(source: &Path, shadow: &Path) -> Result<Self, ShadowError> {
        let source_root = fs::canonicalize(source)?;
        let shadow_root = fs::canonicalize(shadow)?;
        Ok(ShadowManager {
            source_root,
            shadow_root,
        })
    }

    /// Removes the symlink for `relative_path` from the shadow tree.
    ///
    /// This is the **Shadow Simulation** unmap step: the file disappears from
    /// the shadow tree's view so tests can run as if the file were deleted.
    /// The real file in the source tree is untouched.
    ///
    /// Call [`remap`] to reverse this operation on test failure.
    pub fn unmap(&self, relative_path: &Path) -> Result<(), ShadowError> {
        let shadow_path = self.shadow_root.join(relative_path);
        if shadow_path.is_symlink() {
            fs::remove_file(&shadow_path)?;
        }
        Ok(())
    }

    /// Recreates the symlink for `relative_path` in the shadow tree.
    ///
    /// Used to restore a symlink that was removed by [`unmap`] after a failed
    /// Shadow Simulation.
    pub fn remap(&self, relative_path: &Path) -> Result<(), ShadowError> {
        let real_path = self.source_root.join(relative_path);
        let shadow_path = self.shadow_root.join(relative_path);

        if shadow_path.is_symlink() || shadow_path.exists() {
            return Ok(()); // already present
        }

        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_path, &shadow_path).map_err(|e| {
            ShadowError::SymlinkFailure(format!(
                "remap symlink failed for {}: {}",
                shadow_path.display(),
                e
            ))
        })?;

        #[cfg(windows)]
        std::os::windows::fs::symlink_file(&real_path, &shadow_path).map_err(|e| {
            ShadowError::SymlinkFailure(format!(
                "remap symlink failed for {}: {}",
                shadow_path.display(),
                e
            ))
        })?;

        Ok(())
    }

    /// Get the source root path.
    pub fn source_root(&self) -> &Path {
        &self.source_root
    }

    /// Get the shadow root path.
    pub fn shadow_root(&self) -> &Path {
        &self.shadow_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;

    #[test]
    fn test_initialize_creates_shadow_tree() {
        let temp_dir = std::env::temp_dir().join(format!("shadow_test_{}", std::process::id()));
        let source = temp_dir.join("source");
        let shadow = temp_dir.join("shadow");

        // Create source directory with 2 files
        fs::create_dir_all(&source).unwrap();
        File::create(source.join("file1.txt"))
            .unwrap()
            .write_all(b"content1")
            .unwrap();
        File::create(source.join("file2.txt"))
            .unwrap()
            .write_all(b"content2")
            .unwrap();

        // Initialize shadow tree
        let manager = ShadowManager::initialize(&source, &shadow).unwrap();

        // Verify symlinks exist
        assert!(shadow.join("file1.txt").is_symlink());
        assert!(shadow.join("file2.txt").is_symlink());
        assert!(shadow.join("file1.txt").exists());
        assert!(shadow.join("file2.txt").exists());

        // Verify paths
        assert_eq!(manager.source_root(), fs::canonicalize(&source).unwrap());
        assert_eq!(manager.shadow_root(), fs::canonicalize(&shadow).unwrap());

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_skip_excluded_dirs() {
        let temp_dir = std::env::temp_dir().join(format!("shadow_skip_{}", std::process::id()));
        let source = temp_dir.join("source");
        let shadow = temp_dir.join("shadow");

        // Create source with excluded directories
        fs::create_dir_all(source.join("target")).unwrap();
        fs::create_dir_all(source.join(".git")).unwrap();
        File::create(source.join("target").join("build.o")).unwrap();
        File::create(source.join(".git").join("config")).unwrap();
        File::create(source.join("main.rs")).unwrap();

        // Initialize shadow tree
        ShadowManager::initialize(&source, &shadow).unwrap();

        // Verify excluded dirs are not in shadow
        assert!(!shadow.join("target").exists());
        assert!(!shadow.join(".git").exists());
        assert!(shadow.join("main.rs").exists());

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_verify_integrity_valid() {
        let temp_dir = std::env::temp_dir().join(format!("shadow_verify_{}", std::process::id()));
        let source = temp_dir.join("source");
        let shadow = temp_dir.join("shadow");

        fs::create_dir_all(&source).unwrap();
        File::create(source.join("file.txt")).unwrap();

        let manager = ShadowManager::initialize(&source, &shadow).unwrap();

        // Integrity should be valid
        assert!(manager.verify_integrity().unwrap());

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }

    #[cfg(unix)]
    #[test]
    fn test_move_to_ghost() {
        let temp_dir = std::env::temp_dir().join(format!("shadow_ghost_{}", std::process::id()));
        let source = temp_dir.join("source");
        let shadow = temp_dir.join("shadow");

        fs::create_dir_all(&source).unwrap();
        File::create(source.join("module.py"))
            .unwrap()
            .write_all(b"def foo(): pass\n")
            .unwrap();

        let manager = ShadowManager::initialize(&source, &shadow).unwrap();

        // Symlink exists before move.
        assert!(shadow.join("module.py").is_symlink());

        manager
            .move_to_ghost(std::path::Path::new("module.py"))
            .unwrap();

        // Symlink is gone.
        assert!(!shadow.join("module.py").exists());

        // File is now in ghost directory.
        let ghost = source.join(".janitor/ghost/module.py");
        assert!(ghost.exists());
        assert_eq!(fs::read(&ghost).unwrap(), b"def foo(): pass\n");

        // Real file is gone from source.
        assert!(!source.join("module.py").exists());

        fs::remove_dir_all(&temp_dir).ok();
    }

    #[test]
    fn test_verify_integrity_broken() {
        let temp_dir = std::env::temp_dir().join(format!("shadow_broken_{}", std::process::id()));
        let source = temp_dir.join("source");
        let shadow = temp_dir.join("shadow");

        fs::create_dir_all(&source).unwrap();
        File::create(source.join("file.txt")).unwrap();

        let manager = ShadowManager::initialize(&source, &shadow).unwrap();

        // Delete the original file to break the symlink
        fs::remove_file(source.join("file.txt")).unwrap();

        // Integrity should be broken
        assert!(!manager.verify_integrity().unwrap());

        // Cleanup
        fs::remove_dir_all(&temp_dir).ok();
    }
}
