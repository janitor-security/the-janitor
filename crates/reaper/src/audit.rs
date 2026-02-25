//! Structured audit log for symbol excision events.
//!
//! Every physical deletion via [`crate::SafeDeleter`] should produce an
//! [`AuditEntry`] and be flushed to `.janitor/audit_log.json` via [`AuditLog`].
//! The log is append-only: new entries are merged with any existing records.
//!
//! ## Attestation Model
//! Audit entries are **remotely attested**: the Janitor binary sends a merkle
//! root of the batch to `https://api.thejanitor.app/v1/attest`, and the server
//! returns an Ed25519 signature (signed with the server-held private key).
//! The binary embeds only the corresponding **verifying key** (`vault::VERIFYING_KEY_BYTES`).
//! It is cryptographically impossible for the binary to forge its own attestations.
//!
//! If the remote attestation call fails, [`AuditLog::flush`] returns
//! [`crate::ReaperError::AttestError`] and the audit log is NOT written.
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
//!     "lines_removed": 14,
//!     "signature": "<base64-encoded Ed25519 batch attestation from thejanitor.app>"
//!   }
//! ]
//! ```
//!
//! The `signature` field is the server-issued attestation covering the batch
//! `merkle_root` (BLAKE3 hash of all `{timestamp}{file_path}{sha256}` payloads).
//! It is identical for all entries in a single flush batch.

use crate::ReaperError;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

/// Attestation endpoint.
const ATTEST_URL: &str = "https://api.thejanitor.app/v1/attest";

/// Feedback endpoint — receives deleted symbol names for WisdomSet training.
const FEEDBACK_URL: &str = "https://api.thejanitor.app/v1/feedback";

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
    /// Base64-encoded Ed25519 batch attestation from `thejanitor.app`.
    ///
    /// Covers the BLAKE3 merkle root of all entries in this flush batch.
    /// Identical for all entries flushed in a single call.
    ///
    /// Empty when flushed without a token (no attestation requested).
    ///
    /// `#[serde(default)]` ensures backward-compatible deserialization of audit
    /// logs that predate the remote attestation model.
    #[serde(default)]
    pub signature: String,
}

impl AuditEntry {
    /// Constructs an entry, computing the SHA-256 hash from `file_bytes`.
    ///
    /// The `signature` field is left empty; it is populated by
    /// [`AuditLog::flush`] after remote attestation succeeds.
    pub fn new(
        file_path: impl Into<String>,
        symbol_name: impl Into<String>,
        file_bytes: &[u8],
        heuristic_id: impl Into<String>,
        start_line: u32,
        end_line: u32,
    ) -> Self {
        let file_path_str = file_path.into();
        let hash = hex_sha256(file_bytes);
        let timestamp = utc_now();
        AuditEntry {
            timestamp,
            file_path: file_path_str,
            symbol_name: symbol_name.into(),
            sha256_pre_cleanup: hash,
            heuristic_id: heuristic_id.into(),
            lines_removed: end_line.saturating_sub(start_line) + 1,
            signature: String::new(),
        }
    }

    /// Returns the canonical signing payload for this entry.
    ///
    /// Used to construct the batch merkle root for remote attestation.
    fn signing_payload(&self) -> String {
        format!(
            "{}{}{}",
            self.timestamp, self.file_path, self.sha256_pre_cleanup
        )
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
    ///
    /// # Attestation
    /// When `token` is `Some`, the method POSTs a batch attestation request to
    /// `https://api.thejanitor.app/v1/attest` with `Authorization: Bearer <TOKEN>`.
    /// The server returns the Ed25519 batch signature, which is embedded in every
    /// entry's `signature` field before the file is written.
    ///
    /// If the network call fails, this method returns
    /// [`ReaperError::AttestError`] and **no file is written**.
    ///
    /// When `token` is `None`, entries are written with an empty `signature`
    /// (unsigned, no attestation).
    ///
    /// # Errors
    /// - [`ReaperError::IoError`] on filesystem failure.
    /// - [`ReaperError::AttestError`] when remote attestation is requested but fails.
    pub fn flush(&self, token: Option<&str>) -> Result<(), ReaperError> {
        if self.entries.is_empty() {
            return Ok(());
        }

        // Determine the batch signature via remote attestation.
        let batch_sig: String = if let Some(tok) = token {
            remote_attest(tok, &self.entries)?
        } else {
            String::new()
        };

        // Clone entries and apply the batch signature to each.
        let signed_entries: Vec<AuditEntry> = self
            .entries
            .iter()
            .cloned()
            .map(|mut e| {
                e.signature = batch_sig.clone();
                e
            })
            .collect();

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

        existing.extend_from_slice(&signed_entries);

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
// Post-commit feedback
// ---------------------------------------------------------------------------

/// Fire-and-forget: reports deleted symbol names to `thejanitor.app/v1/feedback`
/// for server-side WisdomSet training.
///
/// Called **after** [`crate::SafeDeleter::commit`] succeeds.
/// Any network failure is logged as a warning and silently ignored — telemetry
/// must not block or fail user workflows.
///
/// # Arguments
/// * `token`           — Bearer token for the Janitor API.
/// * `project_hash`    — BLAKE3 hex identifier of the project (prevents server-side correlation).
/// * `deleted_symbols` — Qualified names of the symbols that were removed.
pub fn send_deletion_feedback(token: &str, project_hash: &str, deleted_symbols: &[&str]) {
    if deleted_symbols.is_empty() {
        return;
    }
    let payload = serde_json::json!({
        "project_hash": project_hash,
        "deleted_symbols": deleted_symbols,
        "timestamp": utc_now(),
    });
    if let Err(e) = ureq::post(FEEDBACK_URL)
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(&payload)
    {
        eprintln!("Warning: deletion feedback POST failed (non-fatal): {e}");
    }
}

// ---------------------------------------------------------------------------
// Remote attestation
// ---------------------------------------------------------------------------

/// POSTs a batch attestation request to `ATTEST_URL` and returns the
/// server-issued Ed25519 signature string.
///
/// # Payload
/// ```json
/// {
///   "merkle_root": "<hex BLAKE3 of all signing payloads concatenated>",
///   "timestamp":   "<ISO 8601 UTC>",
///   "files_modified": ["<file_path>", ...]
/// }
/// ```
/// The `Authorization: Bearer <token>` header carries the purge token.
///
/// # Errors
/// Returns [`ReaperError::AttestError`] on any network or parse failure.
fn remote_attest(token: &str, entries: &[AuditEntry]) -> Result<String, ReaperError> {
    // Compute a SHA-256 merkle root from all per-entry signing payloads.
    let mut hasher = Sha256::new();
    for e in entries {
        hasher.update(e.signing_payload().as_bytes());
    }
    let merkle_root = format!("{:x}", hasher.finalize());

    let files_modified: Vec<&str> = entries.iter().map(|e| e.file_path.as_str()).collect();

    let payload = serde_json::json!({
        "merkle_root": merkle_root,
        "timestamp": utc_now(),
        "files_modified": files_modified,
    });

    let response = ureq::post(ATTEST_URL)
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(&payload)
        .map_err(|e| ReaperError::AttestError(e.to_string()))?;

    let body: serde_json::Value = response
        .into_json()
        .map_err(|e| ReaperError::AttestError(format!("response parse error: {e}")))?;

    body["signature"].as_str().map(String::from).ok_or_else(|| {
        ReaperError::AttestError("missing `signature` field in attest response".into())
    })
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
        // signature is empty until remote attestation is performed.
        assert!(
            entry.signature.is_empty(),
            "signature must be empty before flush"
        );
    }

    #[test]
    fn test_audit_log_flush_creates_file_no_token() {
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
        log.flush(None).unwrap();

        let raw = std::fs::read_to_string(tmp.join("audit_log.json")).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["symbol_name"], "dead_func");
        // No token → signature is empty string.
        assert_eq!(parsed[0]["signature"], "");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn test_audit_log_append_across_flushes() {
        let tmp = std::env::temp_dir().join(format!("audit_append_{}", std::process::id()));
        std::fs::create_dir_all(&tmp).unwrap();

        let mut log1 = AuditLog::new(&tmp);
        log1.record(AuditEntry::new("/a.py", "fn1", b"x", "DEAD_SYMBOL", 1, 1));
        log1.flush(None).unwrap();

        let mut log2 = AuditLog::new(&tmp);
        log2.record(AuditEntry::new("/b.py", "fn2", b"y", "DEAD_SYMBOL", 5, 8));
        log2.flush(None).unwrap();

        let raw = std::fs::read_to_string(tmp.join("audit_log.json")).unwrap();
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.len(), 2);

        std::fs::remove_dir_all(&tmp).ok();
    }
}
