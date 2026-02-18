//! Structured audit log for symbol excision events.
//!
//! Every physical deletion via [`crate::SafeDeleter`] should produce an
//! [`AuditEntry`] and be flushed to `.janitor/audit_log.json` via [`AuditLog`].
//! The log is append-only: new entries are merged with any existing records.
//!
//! ## Schema
//! ```json
//! [
//!   {
//!     "timestamp": "2026-02-16T12:34:56Z",
//!     "file_path": "/abs/path/to/module.py",
//!     "symbol_name": "unused_helper",
//!     "sha256_pre_cleanup": "a3b4c5...",
//!     "heuristic_id": "DEAD_SYMBOL",
//!     "lines_removed": 14
//!   }
//! ]
//! ```

use crate::ReaperError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// A single excision event recorded in the audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// ISO 8601 UTC timestamp when the excision was recorded.
    pub timestamp: String,
    /// Absolute path of the file that was modified.
    pub file_path: String,
    /// Qualified name of the excised symbol (e.g. `ClassName.method_name`).
    pub symbol_name: String,
    /// Lowercase hex SHA-256 of the **entire file** before the cleanup.
    pub sha256_pre_cleanup: String,
    /// Identifier describing why the symbol was classified for removal.
    ///
    /// `"DEAD_SYMBOL"` for unreferenced symbols; protection variant name
    /// (e.g. `"Referenced"`) if the symbol survived the pipeline.
    pub heuristic_id: String,
    /// Number of source lines removed by this cleanup operation.
    pub lines_removed: u32,
}

impl AuditEntry {
    /// Constructs an entry, computing the SHA-256 hash from `file_bytes`.
    pub fn new(
        file_path: impl Into<String>,
        symbol_name: impl Into<String>,
        file_bytes: &[u8],
        heuristic_id: impl Into<String>,
        start_line: u32,
        end_line: u32,
    ) -> Self {
        let hash = hex_sha256(file_bytes);
        AuditEntry {
            timestamp: utc_now(),
            file_path: file_path.into(),
            symbol_name: symbol_name.into(),
            sha256_pre_cleanup: hash,
            heuristic_id: heuristic_id.into(),
            lines_removed: end_line.saturating_sub(start_line) + 1,
        }
    }
}

/// Append-only structured audit log backed by `.janitor/audit_log.json`.
///
/// Entries are buffered in memory and written in a single flush, which
/// merges with any pre-existing log entries (preserving history across runs).
pub struct AuditLog {
    path: PathBuf,
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// Creates a new log handle pointing to `<janitor_dir>/audit_log.json`.
    pub fn new(janitor_dir: &Path) -> Self {
        AuditLog {
            path: janitor_dir.join("audit_log.json"),
            entries: Vec::new(),
        }
    }

    /// Buffers an audit entry. Call [`flush`] to persist.
    pub fn record(&mut self, entry: AuditEntry) {
        self.entries.push(entry);
    }

    /// Merges buffered entries with the existing log file and writes to disk.
    ///
    /// A no-op if no entries were recorded since the last flush.
    pub fn flush(&self) -> Result<(), ReaperError> {
        if self.entries.is_empty() {
            return Ok(());
        }

        // Load existing entries (tolerate missing file or corrupt JSON).
        // Zero-copy: mmap the log file rather than heap-allocating its contents.
        let mut existing: Vec<AuditEntry> = if self.path.exists() {
            std::fs::File::open(&self.path)
                .ok()
                .and_then(|f| unsafe { memmap2::Mmap::map(&f).ok() })
                .and_then(|mmap| serde_json::from_slice(&mmap).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        existing.extend_from_slice(&self.entries);

        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let json = serde_json::to_string_pretty(&existing)
            .map_err(|e| ReaperError::ParseError(e.to_string()))?;
        std::fs::write(&self.path, json.as_bytes())?;
        Ok(())
    }

    /// Returns the number of buffered (unflushed) entries.
    pub fn pending_count(&self) -> usize {
        self.entries.len()
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns the lowercase hex SHA-256 digest of `data`.
fn hex_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Returns the current UTC time as an ISO 8601 string.
///
/// Uses a manual RFC 3339-compatible formatter to avoid pulling in `chrono`
/// or `time`. Precision: seconds.
fn utc_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let (y, mo, d, h, min, s) = epoch_to_ymd_hms(secs);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", y, mo, d, h, min, s)
}

/// Converts a Unix timestamp (seconds since 1970-01-01) to (year, month, day, hour, min, sec).
fn epoch_to_ymd_hms(secs: u64) -> (u32, u32, u32, u32, u32, u32) {
    const SECS_PER_MIN: u64 = 60;
    const SECS_PER_HOUR: u64 = 3600;
    const SECS_PER_DAY: u64 = 86400;
    const DAYS_PER_400Y: u64 = 146097;
    const DAYS_PER_100Y: u64 = 36524;
    const DAYS_PER_4Y: u64 = 1461;
    const DAYS_PER_Y: u64 = 365;

    let days = secs / SECS_PER_DAY;
    let rem = secs % SECS_PER_DAY;

    let h = (rem / SECS_PER_HOUR) as u32;
    let min = ((rem % SECS_PER_HOUR) / SECS_PER_MIN) as u32;
    let s = (rem % SECS_PER_MIN) as u32;

    // Compute year/month/day using the proleptic Gregorian calendar algorithm.
    let mut n = days + 719468; // offset to epoch year
    let era = n / DAYS_PER_400Y;
    let doe = n % DAYS_PER_400Y;
    let yoe =
        (doe - doe / DAYS_PER_4Y + doe / DAYS_PER_100Y - doe / (DAYS_PER_400Y - 1)) / DAYS_PER_Y;
    let y = yoe + era * 400;
    let doy = doe - (DAYS_PER_Y * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    n = y;
    if mo <= 2 {
        n += 1;
    }
    (n as u32, mo as u32, d, h, min, s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_sha256_deterministic() {
        let h1 = hex_sha256(b"hello");
        let h2 = hex_sha256(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_audit_entry_new() {
        let entry = AuditEntry::new(
            "/src/module.py",
            "unused_fn",
            b"def unused_fn(): pass",
            "DEAD_SYMBOL",
            10,
            12,
        );
        assert_eq!(entry.symbol_name, "unused_fn");
        assert_eq!(entry.heuristic_id, "DEAD_SYMBOL");
        assert_eq!(entry.lines_removed, 3); // end_line - start_line + 1 = 12 - 10 + 1
        assert_eq!(entry.sha256_pre_cleanup.len(), 64);
    }

    #[test]
    fn test_audit_log_flush_creates_file() {
        let tmp = std::env::temp_dir().join(format!("audit_test_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut log = AuditLog::new(&tmp);
        log.record(AuditEntry::new(
            "/src/a.py",
            "dead_func",
            b"def dead_func(): pass",
            "DEAD_SYMBOL",
            1,
            2,
        ));

        assert_eq!(log.pending_count(), 1);
        log.flush().unwrap();

        let raw = std::fs::read_to_string(tmp.join("audit_log.json")).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["symbol_name"], "dead_func");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_audit_log_append_across_flushes() {
        let tmp = std::env::temp_dir().join(format!("audit_append_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut log1 = AuditLog::new(&tmp);
        log1.record(AuditEntry::new("/a.py", "fn1", b"x", "DEAD_SYMBOL", 1, 1));
        log1.flush().unwrap();

        let mut log2 = AuditLog::new(&tmp);
        log2.record(AuditEntry::new("/b.py", "fn2", b"y", "DEAD_SYMBOL", 5, 8));
        log2.flush().unwrap();

        let raw = std::fs::read_to_string(tmp.join("audit_log.json")).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.len(), 2);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
