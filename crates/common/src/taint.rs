//! Interprocedural taint tracking data structures (P0-1 Taint Spine).
//!
//! [`TaintExportRecord`] is the per-function taint summary persisted to
//! `.janitor/taint_catalog.rkyv`.  Downstream consumers (`PatchBouncer`,
//! `bounce_git`) thread these records across file boundaries to propagate
//! source-to-sink signal through helper functions and module wrappers.
//!
//! ## Budget constraint
//! The taint catalog must remain under **10 MB** on disk.  Callers MUST check
//! the catalog size before appending new records and drop the oldest entries
//! when the budget would be exceeded.

use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize as RkyvDeserialize, Serialize as RkyvSerialize};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// TaintKind — source classification
// ---------------------------------------------------------------------------

/// Classification of a taint source entering a function parameter.
///
/// Governs which sink detectors fire when a tainted value reaches a call site.
/// `Unknown` is the conservative fallback used when the source cannot be
/// statically determined from the function body alone.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug))]
#[repr(u8)]
pub enum TaintKind {
    /// HTTP request body, query parameter, or path segment.
    UserInput = 0,
    /// Value read from an environment variable.
    EnvVar = 1,
    /// Bytes read from the filesystem via `open`/`read`/`File::read_to_string`.
    FileRead = 2,
    /// Response body from an outbound HTTP/gRPC call.
    NetworkResponse = 3,
    /// Row or column value returned from a database query.
    DatabaseResult = 4,
    /// Standard output/stderr captured from a subprocess.
    ProcessOutput = 5,
    /// Source cannot be determined from local analysis — treat as worst-case.
    Unknown = 6,
}

// ---------------------------------------------------------------------------
// TaintedParam — parameter-level taint annotation
// ---------------------------------------------------------------------------

/// Describes a single tainted parameter on a function boundary.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct TaintedParam {
    /// Zero-based index of the parameter in the function signature.
    pub param_index: u32,
    /// Source name of the parameter (best-effort from AST; may be empty).
    pub param_name: String,
    /// Taint classification inferred from the call site or propagated from
    /// a callee's [`TaintExportRecord`].
    pub kind: TaintKind,
}

// ---------------------------------------------------------------------------
// TaintExportRecord — cross-file taint summary
// ---------------------------------------------------------------------------

/// Per-function taint summary exported for cross-file propagation.
///
/// Stored in `.janitor/taint_catalog.rkyv` (zero-copy via `rkyv`).
/// Each record describes which parameters of a public or module-visible
/// function carry taint, and which sink kinds were observed in the function
/// body.  Consumers use these records to follow a 3-hop propagation chain:
/// `source → helper → wrapper → sink`.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Archive,
    RkyvSerialize,
    RkyvDeserialize,
    CheckBytes,
    Serialize,
    Deserialize,
)]
#[rkyv(derive(Debug))]
pub struct TaintExportRecord {
    /// Fully-qualified function name (e.g. `"module.Class.method"`).
    pub symbol_name: String,
    /// Relative file path (UTF-8, forward slashes) containing the function.
    pub file_path: String,
    /// Parameters through which external taint enters this function.
    pub tainted_params: Vec<TaintedParam>,
    /// Sink categories observed reachable from tainted params within this
    /// function's body.  Empty if no sink was detected locally.
    pub sink_kinds: Vec<TaintKind>,
    /// True if this function forwards taint to its return value, enabling
    /// caller-side propagation without a full body re-parse.
    pub propagates_to_return: bool,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_kind_repr_is_stable() {
        // Numeric repr is persisted in rkyv — must not change across versions.
        assert_eq!(TaintKind::UserInput as u8, 0);
        assert_eq!(TaintKind::EnvVar as u8, 1);
        assert_eq!(TaintKind::FileRead as u8, 2);
        assert_eq!(TaintKind::NetworkResponse as u8, 3);
        assert_eq!(TaintKind::DatabaseResult as u8, 4);
        assert_eq!(TaintKind::ProcessOutput as u8, 5);
        assert_eq!(TaintKind::Unknown as u8, 6);
    }

    #[test]
    fn taint_export_record_clone_eq() {
        let rec = TaintExportRecord {
            symbol_name: "auth.validate_token".to_string(),
            file_path: "src/auth.py".to_string(),
            tainted_params: vec![TaintedParam {
                param_index: 0,
                param_name: "token".to_string(),
                kind: TaintKind::UserInput,
            }],
            sink_kinds: vec![TaintKind::DatabaseResult],
            propagates_to_return: false,
        };
        let cloned = rec.clone();
        assert_eq!(rec, cloned);
        assert_eq!(cloned.tainted_params[0].kind, TaintKind::UserInput);
        assert_eq!(cloned.sink_kinds[0], TaintKind::DatabaseResult);
    }

    #[test]
    fn tainted_param_default_kind_is_unknown() {
        let p = TaintedParam {
            param_index: 2,
            param_name: String::new(),
            kind: TaintKind::Unknown,
        };
        assert_eq!(p.kind, TaintKind::Unknown);
    }
}
