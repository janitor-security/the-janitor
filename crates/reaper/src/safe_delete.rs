//! Transactional symbol deletion and replacement with backup/restore.
//!
//! ## Workflow
//! 1. `SafeDeleter::new(project_root)` — initialises the ghost directory.
//! 2. `delete_symbols(file, targets)` — backs up the file on first touch,
//!    then excises the listed byte ranges **bottom-to-top** (reverse start_byte order)
//!    so that earlier offsets remain valid during the transaction.
//! 3. `replace_symbols(file, targets)` — backs up the file on first touch,
//!    then substitutes each byte range with replacement text, also bottom-to-top.
//! 4. `commit()` — success path: removes backup files.
//! 5. `restore_all()` — failure path: copies every backup back to its original path.

use crate::ReaperError;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Minimal description of a symbol to be excised.
///
/// The CLI converts `anatomist::Entity` values into `DeletionTarget`s before
/// calling `SafeDeleter`, keeping `reaper` independent of `anatomist`.
#[derive(Debug, Clone)]
pub struct DeletionTarget {
    /// Fully-qualified symbol name (for logging only).
    pub qualified_name: String,
    /// Byte offset of the first character of the definition (inclusive).
    pub start_byte: u32,
    /// Byte offset just past the last character of the definition (exclusive).
    pub end_byte: u32,
}

/// Description of a symbol whose body should be replaced with new text.
///
/// Used by `SafeDeleter::replace_symbols` to surgically substitute code.
#[derive(Debug, Clone)]
pub struct ReplacementTarget {
    /// Fully-qualified symbol name (for logging only).
    pub qualified_name: String,
    /// Byte offset of the first character of the region to replace (inclusive).
    pub start_byte: u32,
    /// Byte offset just past the region to replace (exclusive).
    pub end_byte: u32,
    /// UTF-8 text that replaces the byte range `[start_byte, end_byte)`.
    pub replacement: String,
}

/// Transactional file editor that backs up files before modifying them.
///
/// Ghost directory layout: `{project_root}/.janitor/ghost/{ts}_{filename}.bak`
pub struct SafeDeleter {
    ghost_dir: PathBuf,
    /// `original_path → backup_path`
    backups: HashMap<PathBuf, PathBuf>,
}

impl SafeDeleter {
    /// Creates (or reuses) the ghost directory under `project_root/.janitor/ghost`.
    pub fn new(project_root: &Path) -> Result<Self, ReaperError> {
        let ghost_dir = project_root.join(".janitor").join("ghost");
        std::fs::create_dir_all(&ghost_dir)?;
        Ok(Self {
            ghost_dir,
            backups: HashMap::new(),
        })
    }

    /// Backs up `file_path` (if not already done), then excises all listed byte ranges.
    ///
    /// Targets are processed **bottom-to-top** (descending `start_byte`) so that
    /// earlier offsets remain valid after each splice.
    ///
    /// Returns the number of symbols actually removed.
    pub fn delete_symbols(
        &mut self,
        file_path: &Path,
        targets: &mut [DeletionTarget],
    ) -> Result<usize, ReaperError> {
        if targets.is_empty() {
            return Ok(0);
        }

        self.ensure_backup(file_path)?;

        let mut content = std::fs::read(file_path)?;

        // Sort DESCENDING — bottom-to-top so earlier offsets stay valid.
        targets.sort_by(|a, b| b.start_byte.cmp(&a.start_byte));

        let mut removed = 0usize;
        for target in targets.iter() {
            let start = snap_char_boundary_bwd(&content, target.start_byte as usize);
            let mut end = snap_char_boundary_fwd(&content, target.end_byte as usize);

            if start >= content.len() || end > content.len() || start >= end {
                continue;
            }

            // Consume the trailing newline (if present) to avoid a blank line.
            if end < content.len() && content[end] == b'\n' {
                end += 1;
            }

            content.drain(start..end);
            removed += 1;
        }

        std::fs::write(file_path, &content)?;
        Ok(removed)
    }

    /// Backs up `file_path` (if not already done), then replaces each listed
    /// byte range with the corresponding `ReplacementTarget::replacement` text.
    ///
    /// Targets are processed **bottom-to-top** (descending `start_byte`) so that
    /// earlier offsets remain valid after each splice.
    ///
    /// Returns the number of replacements applied.
    pub fn replace_symbols(
        &mut self,
        file_path: &Path,
        targets: &mut [ReplacementTarget],
    ) -> Result<usize, ReaperError> {
        if targets.is_empty() {
            return Ok(0);
        }

        self.ensure_backup(file_path)?;

        let mut content = std::fs::read(file_path)?;

        // Sort DESCENDING — bottom-to-top.
        targets.sort_by(|a, b| b.start_byte.cmp(&a.start_byte));

        let mut replaced = 0usize;
        for target in targets.iter() {
            let start = snap_char_boundary_bwd(&content, target.start_byte as usize);
            let end = snap_char_boundary_fwd(&content, target.end_byte as usize);

            if start >= content.len() || end > content.len() || start >= end {
                continue;
            }

            let replacement = target.replacement.as_bytes();
            let mut new_content =
                Vec::with_capacity(content.len() - (end - start) + replacement.len());
            new_content.extend_from_slice(&content[..start]);
            new_content.extend_from_slice(replacement);
            new_content.extend_from_slice(&content[end..]);
            content = new_content;
            replaced += 1;
        }

        std::fs::write(file_path, &content)?;
        Ok(replaced)
    }

    /// Copies all backup files back to their original paths.
    ///
    /// Called on test failure to revert the transaction.
    pub fn restore_all(&self) -> Result<(), ReaperError> {
        for (original, backup) in &self.backups {
            std::fs::copy(backup, original)?;
        }
        Ok(())
    }

    /// Deletes all backup files after a successful transaction.
    pub fn commit(&self) -> Result<(), ReaperError> {
        for backup in self.backups.values() {
            std::fs::remove_file(backup).ok();
        }
        Ok(())
    }

    /// Returns the number of files currently backed up.
    pub fn backup_count(&self) -> usize {
        self.backups.len()
    }

    /// Ensures a backup of `file_path` exists, creating one on first touch.
    pub fn ensure_backup(&mut self, file_path: &Path) -> Result<(), ReaperError> {
        if !self.backups.contains_key(file_path) {
            let bak = self.backup_file(file_path)?;
            self.backups.insert(file_path.to_path_buf(), bak);
        }
        Ok(())
    }

    // --- private ---

    fn backup_file(&self, file_path: &Path) -> Result<PathBuf, ReaperError> {
        let filename = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let bak_name = format!("{}_{}.bak", ts, filename);
        let bak_path = self.ghost_dir.join(bak_name);
        std::fs::copy(file_path, &bak_path)?;
        Ok(bak_path)
    }
}

// ---------------------------------------------------------------------------
// UTF-8 boundary helpers
// ---------------------------------------------------------------------------

/// Snaps `offset` backward to the start of the current UTF-8 character.
///
/// Uses `str::is_char_boundary` when the buffer is valid UTF-8 (the common
/// case for Python source files).  Falls back to the continuation-byte mask
/// (`0x80–0xBF`) for non-UTF-8 content (e.g. Python 2 latin-1 files).
fn snap_char_boundary_bwd(buf: &[u8], mut offset: usize) -> usize {
    match std::str::from_utf8(buf) {
        Ok(s) => {
            while offset > 0 && !s.is_char_boundary(offset) {
                offset -= 1;
            }
        }
        Err(_) => {
            // Non-UTF-8 fallback: walk backward past continuation bytes.
            while offset > 0 && (buf[offset] & 0xC0) == 0x80 {
                offset -= 1;
            }
        }
    }
    offset
}

/// Snaps `offset` forward past any UTF-8 continuation bytes.
///
/// Uses `str::is_char_boundary` for valid UTF-8; continuation-byte mask
/// otherwise.
fn snap_char_boundary_fwd(buf: &[u8], mut offset: usize) -> usize {
    match std::str::from_utf8(buf) {
        Ok(s) => {
            while offset < buf.len() && !s.is_char_boundary(offset) {
                offset += 1;
            }
        }
        Err(_) => {
            while offset < buf.len() && (buf[offset] & 0xC0) == 0x80 {
                offset += 1;
            }
        }
    }
    offset
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn tmp_dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(name);
        fs::create_dir_all(&d).ok();
        d
    }

    #[test]
    fn test_bottom_to_top_splice() {
        let tmp = tmp_dir("test_btt_splice");
        let src = b"def alpha():\n    pass\ndef beta():\n    pass\n";
        let file = tmp.join("mod.py");
        fs::write(&file, src).ok();

        let mut deleter = SafeDeleter::new(&tmp).unwrap();
        let mut targets = vec![
            DeletionTarget {
                qualified_name: "alpha".into(),
                start_byte: 0,
                end_byte: 21,
            },
            DeletionTarget {
                qualified_name: "beta".into(),
                start_byte: 21,
                end_byte: src.len() as u32,
            },
        ];
        let removed = deleter.delete_symbols(&file, &mut targets).unwrap();
        assert_eq!(removed, 2);

        let result = fs::read_to_string(&file).unwrap();
        assert!(
            result.trim().is_empty(),
            "File should be empty after deleting all symbols"
        );

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_restore_all() {
        let tmp = tmp_dir("test_restore_all");
        let original_content = b"def foo():\n    pass\ndef bar():\n    pass\n";
        let file = tmp.join("src.py");
        fs::write(&file, original_content).ok();

        let mut deleter = SafeDeleter::new(&tmp).unwrap();
        let mut targets = vec![DeletionTarget {
            qualified_name: "foo".into(),
            start_byte: 0,
            end_byte: 19,
        }];
        deleter.delete_symbols(&file, &mut targets).unwrap();

        deleter.restore_all().unwrap();

        let after = fs::read(&file).unwrap();
        assert_eq!(after, original_content);

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_commit_removes_backups() {
        let tmp = tmp_dir("test_commit_bak");
        let file = tmp.join("app.py");
        fs::write(&file, b"def unused():\n    pass\n").ok();

        let mut deleter = SafeDeleter::new(&tmp).unwrap();
        let mut targets = vec![DeletionTarget {
            qualified_name: "unused".into(),
            start_byte: 0,
            end_byte: 22,
        }];
        deleter.delete_symbols(&file, &mut targets).unwrap();
        assert_eq!(deleter.backup_count(), 1);

        deleter.commit().unwrap();
        let ghost = tmp.join(".janitor/ghost");
        let count = fs::read_dir(ghost).unwrap().count();
        assert_eq!(count, 0);

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_empty_targets_noop() {
        let tmp = tmp_dir("test_empty_noop");
        let file = tmp.join("empty.py");
        fs::write(&file, b"x = 1\n").ok();

        let mut deleter = SafeDeleter::new(&tmp).unwrap();
        let removed = deleter.delete_symbols(&file, &mut vec![]).unwrap();
        assert_eq!(removed, 0);
        assert_eq!(deleter.backup_count(), 0);

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_replace_symbols_proxy_body() {
        let tmp = tmp_dir("test_replace_proxy");
        let src =
            b"def calculate_tax(amount, rate):\n    return amount * rate\ndef other():\n    pass\n";
        let file = tmp.join("service.py");
        fs::write(&file, src).ok();

        // Replace the body of calculate_tax (bytes 33..57: "    return amount * rate\n")
        let body_start = 33u32; // after "def calculate_tax(amount, rate):\n"
        let body_end = 57u32; // end of "    return amount * rate\n"

        let mut deleter = SafeDeleter::new(&tmp).unwrap();
        let mut targets = vec![ReplacementTarget {
            qualified_name: "calculate_tax".into(),
            start_byte: body_start,
            end_byte: body_end,
            replacement: "    return _calculate_tax_impl(amount, rate)\n".into(),
        }];
        let replaced = deleter.replace_symbols(&file, &mut targets).unwrap();
        assert_eq!(replaced, 1);

        let result = fs::read_to_string(&file).unwrap();
        assert!(result.contains("return _calculate_tax_impl(amount, rate)"));
        assert!(result.contains("def other():"));

        deleter.restore_all().unwrap();
        let restored = fs::read(&file).unwrap();
        assert_eq!(restored, src);

        fs::remove_dir_all(tmp).ok();
    }

    #[test]
    fn test_utf8_emoji_boundary() {
        // Verify no panic when byte offsets land inside multi-byte emoji sequences.
        let tmp = tmp_dir("test_emoji_boundary");
        // "def foo():\n    # 🚀 rocket\n    pass\n"
        // 🚀 is 4 bytes (U+1F680 = 0xF0 0x9F 0x9A 0x80)
        let src = "def foo():\n    # \u{1F680} rocket\n    pass\n";
        let file = tmp.join("emoji.py");
        fs::write(&file, src.as_bytes()).ok();

        let src_bytes = src.as_bytes().to_vec();
        // Find the byte offset that lands INSIDE the emoji (offset+1, +2, +3)
        let rocket_pos = src.find('\u{1F680}').unwrap();

        // snap_char_boundary_bwd should walk back to the emoji start
        let snapped_bwd = snap_char_boundary_bwd(&src_bytes, rocket_pos + 1);
        assert_eq!(snapped_bwd, rocket_pos);

        // snap_char_boundary_fwd should walk forward to after the emoji
        let snapped_fwd = snap_char_boundary_fwd(&src_bytes, rocket_pos + 1);
        assert_eq!(snapped_fwd, rocket_pos + 4); // 🚀 is 4 bytes

        // Deleting the whole function should not panic
        let mut deleter = SafeDeleter::new(&tmp).unwrap();
        let mut targets = vec![DeletionTarget {
            qualified_name: "foo".into(),
            start_byte: 0,
            end_byte: src_bytes.len() as u32,
        }];
        let removed = deleter.delete_symbols(&file, &mut targets).unwrap();
        assert_eq!(removed, 1);

        fs::remove_dir_all(tmp).ok();
    }
}
