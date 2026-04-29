//! Local Adaptive Brain — Count-Min Sketch + Naïve Bayes false-positive suppressor.
//!
//! Persisted at `.janitor/local_brain.rkyv` in the target repository.
//! Loaded on every `janitor scan` and `janitor bounce`; updated exclusively
//! by `janitor pardon <symbol>`.
//!
//! ## Algorithm
//!
//! Two parallel Count-Min Sketches record, for each symbol string, how many
//! times it was pardoned (user asserts false positive) versus confirmed (real
//! finding — reserved for a future feedback loop).  The minimum-frequency
//! estimator feeds a Laplace-smoothed Naïve Bayes classifier:
//!
//! ```text
//! P(FP | symbol) = (pardoned + 1) / (pardoned + confirmed + 2)
//! ```
//!
//! If `P(FP)` exceeds [`SUPPRESS_THRESHOLD`] (0.85) the finding is silently
//! suppressed.  A single `janitor pardon` invocation shifts the probability to
//! 0.67; three consecutive pardons push it to ~0.84, just below the threshold.
//! Five pardons cross it definitively (≈ 0.86).
//!
//! ## Wire format
//!
//! `[32-byte BLAKE3 checksum][rkyv payload]` — identical to `symbols.rkyv`
//! so the same integrity tooling works across both files.

use anyhow::Result;
use common::slop::StructuredFinding;
use memmap2::Mmap;
use ndarray::arr1;
use rkyv::bytecheck::CheckBytes;
use rkyv::{Archive, Deserialize, Serialize};
use std::fs::File;
use std::io::Write as _;
use std::path::Path;

/// Probability above which a finding is suppressed by the local brain.
pub const SUPPRESS_THRESHOLD: f32 = 0.85;

const TRIAGE_WEIGHTS: [f32; 4] = [3.0, 1.5, 1.0, -4.0];

/// Number of independent hash rows in the Count-Min Sketch.
const DEPTH: usize = 4;

/// Number of counter slots per row.
///
/// 2048 cells → < 0.1 % collision probability for up to ~200 distinct patterns,
/// with the conservative minimum-frequency estimator bounding over-counting.
const WIDTH: usize = 2048;

/// Total counter slots (`DEPTH × WIDTH`).
const TABLE_SIZE: usize = DEPTH * WIDTH;

/// Local Adaptive Brain — probabilistic false-positive suppression model.
///
/// Stores two parallel Count-Min Sketches and provides:
///
/// - [`update`](AdaptiveBrain::update) — record a pardon or confirmation.
/// - [`predict_false_positive_probability`](AdaptiveBrain::predict_false_positive_probability)
///   — estimate P(false_positive | symbol).
/// - [`load`](AdaptiveBrain::load) / [`save`](AdaptiveBrain::save) — atomic
///   persistence with BLAKE3 integrity check.
#[derive(Debug, Clone, Archive, Deserialize, Serialize, CheckBytes)]
#[rkyv(derive(Debug))]
#[repr(C)]
pub struct AdaptiveBrain {
    /// CMS counters for pardoned (false-positive) observations.
    pub pardoned_counts: Vec<u32>,
    /// CMS counters for confirmed (true-positive) observations.
    pub confirmed_counts: Vec<u32>,
    /// Lifetime pardon event count (diagnostic / CLI display).
    pub total_pardons: u64,
    /// Lifetime confirm event count (reserved for future feedback loop).
    pub total_confirms: u64,
}

impl Default for AdaptiveBrain {
    fn default() -> Self {
        Self {
            pardoned_counts: vec![0u32; TABLE_SIZE],
            confirmed_counts: vec![0u32; TABLE_SIZE],
            total_pardons: 0,
            total_confirms: 0,
        }
    }
}

impl AdaptiveBrain {
    /// Creates a new, empty `AdaptiveBrain`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the flat counter index for `(row, symbol_bytes)`.
    ///
    /// Uses BLAKE3 keyed hashing with a row-derived key so each row acts as an
    /// independent hash function (pairwise-independent hashing property).
    fn cell_index(row: usize, symbol_bytes: &[u8]) -> usize {
        let mut key = [0u8; 32];
        key[0] = row as u8;
        let hash = blake3::keyed_hash(&key, symbol_bytes);
        let h = u64::from_le_bytes(
            hash.as_bytes()[..8]
                .try_into()
                .expect("blake3 output is always ≥ 8 bytes"),
        );
        row * WIDTH + (h as usize) % WIDTH
    }

    /// Records one observation for `symbol`.
    ///
    /// - `is_false_positive = true` → increments pardoned counters (`janitor pardon`).
    /// - `is_false_positive = false` → increments confirmed counters (reserved).
    pub fn update(&mut self, symbol: &str, is_false_positive: bool) {
        let bytes = symbol.as_bytes();
        for row in 0..DEPTH {
            let idx = Self::cell_index(row, bytes);
            if is_false_positive {
                self.pardoned_counts[idx] = self.pardoned_counts[idx].saturating_add(1);
            } else {
                self.confirmed_counts[idx] = self.confirmed_counts[idx].saturating_add(1);
            }
        }
        if is_false_positive {
            self.total_pardons += 1;
        } else {
            self.total_confirms += 1;
        }
    }

    /// Returns `P(false_positive | symbol)` in `[0, 1]`.
    ///
    /// Uses the minimum-frequency estimate from the CMS (conservative upper bound
    /// on collision noise) and Laplace smoothing so unseen symbols return 0.5
    /// (uninformative prior).
    pub fn predict_false_positive_probability(&self, symbol: &str) -> f32 {
        let bytes = symbol.as_bytes();
        let mut min_pardoned = u32::MAX;
        let mut min_confirmed = u32::MAX;
        for row in 0..DEPTH {
            let idx = Self::cell_index(row, bytes);
            min_pardoned = min_pardoned.min(self.pardoned_counts[idx]);
            min_confirmed = min_confirmed.min(self.confirmed_counts[idx]);
        }
        // Laplace-smoothed Naïve Bayes.
        (min_pardoned as f32 + 1.0) / (min_pardoned as f32 + min_confirmed as f32 + 2.0)
    }

    /// Loads `AdaptiveBrain` from `path`, verifying the BLAKE3 checksum.
    ///
    /// Returns a fresh default brain if the file does not exist.
    ///
    /// # Errors
    /// Returns an error if the file exists but the checksum fails or the rkyv
    /// payload cannot be deserialised.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }

        let file = File::open(path)?;
        // SAFETY: mmap is read-only; the file handle outlives the mmap borrow.
        let mmap = unsafe { Mmap::map(&file) }?;

        if mmap.len() < 32 {
            // Truncated file — reset rather than hard-failing.
            return Ok(Self::new());
        }

        let stored_hash =
            blake3::Hash::from_bytes(mmap[..32].try_into().expect("slice length is exactly 32"));
        let payload = &mmap[32..];

        if blake3::hash(payload) != stored_hash {
            anyhow::bail!(
                "local_brain.rkyv checksum mismatch — delete {} to reset",
                path.display()
            );
        }

        let archived = rkyv::access::<rkyv::Archived<Self>, rkyv::rancor::Error>(payload)
            .map_err(|e| anyhow::anyhow!("local_brain.rkyv access failed: {e}"))?;
        let brain = rkyv::deserialize::<Self, rkyv::rancor::Error>(archived)
            .map_err(|e| anyhow::anyhow!("local_brain.rkyv deserialize failed: {e}"))?;

        Ok(brain)
    }

    /// Serialises the brain and writes it atomically to `path`.
    ///
    /// Wire format: `[32-byte BLAKE3 checksum][rkyv payload]`.
    ///
    /// # Errors
    /// Returns an error on serialisation failure or I/O error.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let payload = rkyv::to_bytes::<rkyv::rancor::Error>(self)
            .map_err(|e| anyhow::anyhow!("local_brain.rkyv serialize failed: {e}"))?;
        let checksum = blake3::hash(&payload);

        let tmp = path.with_extension("rkyv.tmp");
        {
            let mut f = File::create(&tmp)?;
            f.write_all(checksum.as_bytes())?;
            f.write_all(&payload)?;
            f.flush()?;
        }

        std::fs::rename(&tmp, path).inspect_err(|_| {
            let _ = std::fs::remove_file(&tmp);
        })?;

        Ok(())
    }
}

/// Deterministic lightweight finding ranker for bounty/report triage.
#[derive(Debug, Default, Clone, Copy)]
pub struct FindingRanker;

impl FindingRanker {
    /// Rank findings by exploit evidence, component attribution, severity, and
    /// static-source disproof. Higher scores sort first.
    pub fn rank_findings(
        mut findings: Vec<StructuredFinding>,
        component_info: Option<&str>,
    ) -> Vec<StructuredFinding> {
        findings.sort_by(|left, right| {
            let left_score = Self::score(left, component_info);
            let right_score = Self::score(right, component_info);
            right_score
                .total_cmp(&left_score)
                .then_with(|| left.id.cmp(&right.id))
                .then_with(|| left.file.cmp(&right.file))
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });
        findings
    }

    /// Return ranked borrowed findings without cloning the underlying records.
    pub fn rank_finding_refs<'a>(
        findings: &'a [StructuredFinding],
        component_info: Option<&str>,
    ) -> Vec<&'a StructuredFinding> {
        let mut refs = findings.iter().collect::<Vec<_>>();
        refs.sort_by(|left, right| {
            let left_score = Self::score(left, component_info);
            let right_score = Self::score(right, component_info);
            right_score
                .total_cmp(&left_score)
                .then_with(|| left.id.cmp(&right.id))
                .then_with(|| left.file.cmp(&right.file))
                .then_with(|| left.line.cmp(&right.line))
                .then_with(|| left.fingerprint.cmp(&right.fingerprint))
        });
        refs
    }

    /// Compute the deterministic triage score for one finding.
    pub fn score(finding: &StructuredFinding, component_info: Option<&str>) -> f32 {
        let features = Self::feature_vector(finding, component_info);
        let weights = arr1(&TRIAGE_WEIGHTS);
        features.dot(&weights)
    }

    fn feature_vector(
        finding: &StructuredFinding,
        component_info: Option<&str>,
    ) -> ndarray::Array1<f32> {
        arr1(&[
            has_concrete_poc(finding),
            has_component_attribution(component_info),
            severity_weight(finding.severity.as_deref()),
            static_source_proven(finding),
        ])
    }
}

fn has_concrete_poc(finding: &StructuredFinding) -> f32 {
    let Some(witness) = finding.exploit_witness.as_ref() else {
        return 0.0;
    };
    if witness.repro_cmd.is_some()
        || witness.payload.is_some()
        || witness.reproduction_steps.is_some()
    {
        1.0
    } else {
        0.0
    }
}

fn has_component_attribution(component_info: Option<&str>) -> f32 {
    match component_info {
        Some(component)
            if !component.trim().is_empty()
                && !component.contains("Unknown / Source Repository")
                && !component.contains("Unknown Component") =>
        {
            1.0
        }
        _ => 0.0,
    }
}

fn severity_weight(severity: Option<&str>) -> f32 {
    match severity {
        Some("KevCritical") => 5.0,
        Some("Exhaustion" | "Critical") => 4.0,
        Some("High") => 3.0,
        Some("Medium") => 2.0,
        Some("Low" | "Informational") => 1.0,
        _ => 0.0,
    }
}

fn static_source_proven(finding: &StructuredFinding) -> f32 {
    finding
        .exploit_witness
        .as_ref()
        .and_then(|witness| witness.static_source_proven)
        .map(|value| if value { 1.0 } else { 0.0 })
        .unwrap_or(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fresh_brain_returns_prior() {
        let brain = AdaptiveBrain::new();
        // Laplace prior for unseen symbol: (0+1)/(0+0+2) = 0.5
        let p = brain.predict_false_positive_probability("unknown_fn");
        assert!((p - 0.5).abs() < f32::EPSILON, "prior should be 0.5");
    }

    #[test]
    fn test_pardon_raises_probability() {
        let mut brain = AdaptiveBrain::new();
        for _ in 0..20 {
            brain.update("simulate_merge", true);
        }
        let p = brain.predict_false_positive_probability("simulate_merge");
        assert!(p > SUPPRESS_THRESHOLD, "p should exceed threshold");
    }

    #[test]
    fn test_confirmed_lowers_probability() {
        let mut brain = AdaptiveBrain::new();
        for _ in 0..3 {
            brain.update("real_dead_fn", true);
        }
        for _ in 0..50 {
            brain.update("real_dead_fn", false);
        }
        let p = brain.predict_false_positive_probability("real_dead_fn");
        assert!(p < 0.2, "p should be low after many confirmations");
    }

    #[test]
    fn test_symbols_are_independent() {
        let mut brain = AdaptiveBrain::new();
        for _ in 0..30 {
            brain.update("pardoned_fn", true);
        }
        let p_pardoned = brain.predict_false_positive_probability("pardoned_fn");
        let p_other = brain.predict_false_positive_probability("other_fn");
        assert!(
            p_pardoned > SUPPRESS_THRESHOLD,
            "pardoned_fn should be suppressed"
        );
        assert!(p_other < 0.6, "other_fn should be near prior");
    }

    #[test]
    fn test_roundtrip_save_load() {
        let tmp = std::env::temp_dir().join("test_adaptive_brain_roundtrip.rkyv");
        let mut brain = AdaptiveBrain::new();
        for _ in 0..10 {
            brain.update("my_macro_fn", true);
        }
        brain.save(&tmp).unwrap();
        let loaded = AdaptiveBrain::load(&tmp).unwrap();
        let p = loaded.predict_false_positive_probability("my_macro_fn");
        assert!(p > 0.8, "loaded brain should remember pardons");
        std::fs::remove_file(tmp).ok();
    }

    #[test]
    fn test_load_missing_file_returns_default() {
        let result = AdaptiveBrain::load(Path::new("/nonexistent/local_brain.rkyv"));
        assert!(result.is_ok(), "missing file should yield default brain");
        let brain = result.unwrap();
        assert_eq!(brain.total_pardons, 0);
    }

    #[test]
    fn test_five_pardons_suppress() {
        let mut brain = AdaptiveBrain::new();
        for _ in 0..5 {
            brain.update("my_macro_fn", true);
        }
        let p = brain.predict_false_positive_probability("my_macro_fn");
        assert!(p > SUPPRESS_THRESHOLD, "5 pardons should cross threshold");
    }

    #[test]
    fn exploit_witness_payload_ranks_above_informational_noise() {
        let exploitable = StructuredFinding {
            id: "security:deserialization_gadget".to_string(),
            severity: Some("Critical".to_string()),
            exploit_witness: Some(common::slop::ExploitWitness {
                payload: Some("aced0005".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let informational = StructuredFinding {
            id: "security:unpinned_asset".to_string(),
            severity: Some("Informational".to_string()),
            ..Default::default()
        };

        let ranked =
            FindingRanker::rank_findings(vec![informational, exploitable], Some("**pkg** v1"));

        assert_eq!(ranked[0].id, "security:deserialization_gadget");
    }
}
