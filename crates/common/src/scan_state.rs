//! Incremental scan state — maps file paths to their last-seen BLAKE3 content
//! hash so that unchanged files can bypass the full AST parse and slop-hunting
//! pipeline on repeated `bounce` / `scan` invocations.
//!
//! Persisted to `.janitor/scan_state.rkyv` using the symlink-safe atomic-write
//! pattern (stage → `sync_all` → `rename`).

use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use std::collections::HashMap;
use std::io::Write as _;
use std::path::Path;

/// Per-file content fingerprint cache.
///
/// Keys are repo-relative file paths (UTF-8 strings).  Values are the raw
/// 32-byte BLAKE3 digest of the file's content at the time it was last
/// analysed.  A matching digest means the AST parse result would be identical
/// — the file can be skipped entirely.
#[derive(Debug, Clone, Default, Archive, RkyvDeserialize, RkyvSerialize, CheckBytes)]
#[rkyv(derive(Debug))]
pub struct ScanState {
    /// `path_str → blake3_digest`
    pub cache: HashMap<String, [u8; 32]>,
}

impl ScanState {
    /// Load `ScanState` from `path`.
    ///
    /// Returns `Ok(Default::default())` when the file is absent — a clean
    /// first run is indistinguishable from an empty cache.  Returns `Err` only
    /// on I/O or deserialization failures.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let bytes = std::fs::read(path)
            .map_err(|e| anyhow::anyhow!("scan_state: failed to read {}: {e}", path.display()))?;
        // Use rkyv access + copy-out deserialization for safety.
        let archived = rkyv::access::<ArchivedScanState, rkyv::rancor::Error>(&bytes)
            .map_err(|e| anyhow::anyhow!("scan_state: archived access failed: {e}"))?;
        let state = rkyv::deserialize::<ScanState, rkyv::rancor::Error>(archived)
            .map_err(|e| anyhow::anyhow!("scan_state: deserialization failed: {e}"))?;
        Ok(state)
    }

    /// Persist `ScanState` to `path` using the symlink-safe atomic-write pattern.
    ///
    /// Stages to `<path>.tmp`, calls `sync_all`, then renames atomically.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        // Symlink guard — refuse to overwrite a symlink target.
        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                anyhow::bail!(
                    "scan_state: write rejected: {} is a symlink — potential symlink overwrite attack",
                    path.display()
                );
            }
        }

        let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(|e| anyhow::anyhow!("scan_state: rkyv serialization failed: {e}"))?;

        let tmp_path = path.with_extension("rkyv.tmp");
        {
            let mut tmp = std::fs::File::create(&tmp_path).map_err(|e| {
                anyhow::anyhow!("scan_state: failed to create {}: {e}", tmp_path.display())
            })?;
            tmp.write_all(&bytes)
                .map_err(|e| anyhow::anyhow!("scan_state: write failed: {e}"))?;
            tmp.sync_all()
                .map_err(|e| anyhow::anyhow!("scan_state: sync_all failed: {e}"))?;
        }
        std::fs::rename(&tmp_path, path)
            .map_err(|e| anyhow::anyhow!("scan_state: atomic rename failed: {e}"))?;
        Ok(())
    }

    /// Returns `true` if `path_str` matches the stored BLAKE3 digest.
    ///
    /// A `true` result means the file content is identical to the last
    /// analysed version — the file can be skipped.
    #[inline]
    pub fn is_unchanged(&self, path_str: &str, digest: &[u8; 32]) -> bool {
        self.cache.get(path_str) == Some(digest)
    }

    /// Record or update the digest for `path_str`.
    #[inline]
    pub fn record(&mut self, path_str: String, digest: [u8; 32]) {
        self.cache.insert(path_str, digest);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_state_default_is_empty() {
        let s = ScanState::default();
        assert!(s.cache.is_empty());
    }

    #[test]
    fn scan_state_unchanged_detection() {
        let mut s = ScanState::default();
        let digest = [0xabu8; 32];
        assert!(!s.is_unchanged("src/main.rs", &digest));
        s.record("src/main.rs".to_string(), digest);
        assert!(s.is_unchanged("src/main.rs", &digest));
        // Different digest → not unchanged.
        let other = [0xcd_u8; 32];
        assert!(!s.is_unchanged("src/main.rs", &other));
    }

    #[test]
    fn scan_state_round_trips_through_rkyv() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("scan_state.rkyv");

        let mut s = ScanState::default();
        s.record("crates/foo/src/lib.rs".to_string(), [0x11_u8; 32]);
        s.record("crates/bar/src/main.rs".to_string(), [0x22_u8; 32]);
        s.save(&path).unwrap();

        let loaded = ScanState::load(&path).unwrap();
        assert_eq!(loaded.cache.len(), 2);
        assert!(loaded.is_unchanged("crates/foo/src/lib.rs", &[0x11_u8; 32]));
        assert!(loaded.is_unchanged("crates/bar/src/main.rs", &[0x22_u8; 32]));
    }

    #[test]
    fn scan_state_load_absent_returns_default() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nonexistent.rkyv");
        let s = ScanState::load(&path).unwrap();
        assert!(s.cache.is_empty());
    }
}
