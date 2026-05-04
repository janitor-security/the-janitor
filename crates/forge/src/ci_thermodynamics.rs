//! P3-8 Thermodynamic CI Anomaly Detection.
//!
//! Detects adversarial CI manipulation and build-system supply-chain attacks
//! by comparing runtime thermodynamic metrics (execution time, memory peak)
//! against a recorded baseline.  When a small AST diff (<100 lines) produces
//! a large resource spike (>300%), the engine emits
//! `security:thermodynamic_execution_anomaly` at Critical — evidence of an
//! obfuscated macro-bomb, a stealth compiler, or a poisoned `actions/cache`
//! substitution that traditional SAST never sees.
//!
//! ## Baseline file
//!
//! `.janitor/thermo_baseline.json` — JSON object:
//! ```json
//! { "execution_time_ms": 12000, "memory_peak_kb": 204800 }
//! ```
//!
//! ## Detection invariant
//!
//! ```text
//! ast_diff_lines < SMALL_DIFF_THRESHOLD
//!   AND ( execution_time_ms / baseline_execution_time_ms > SPIKE_RATIO
//!      OR memory_peak_kb   / baseline_memory_peak_kb    > SPIKE_RATIO )
//! ⟹ emit security:thermodynamic_execution_anomaly (Critical)
//! ```

use anyhow::{Context as _, Result};
use common::slop::StructuredFinding;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// AST diff line count below which a resource spike is suspicious.
const SMALL_DIFF_THRESHOLD: usize = 100;
/// Resource ratio above which a spike is flagged (300% = 3×).
const SPIKE_RATIO: f64 = 3.0;

/// Persisted baseline recorded during a known-clean CI run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CiThermoBaseline {
    /// Wall-clock execution time of the full CI pipeline, in milliseconds.
    pub execution_time_ms: u64,
    /// Peak resident-set size reported by the CI runner, in kibibytes.
    pub memory_peak_kb: u64,
}

/// Observed metrics for the current CI run.
#[derive(Debug, Clone)]
pub struct CiRunMetrics {
    /// Wall-clock execution time of the current CI pipeline, in milliseconds.
    pub execution_time_ms: u64,
    /// Peak resident-set size for the current CI run, in kibibytes.
    pub memory_peak_kb: u64,
}

/// Deserialize a `CiThermoBaseline` from `path` (`.janitor/thermo_baseline.json`).
pub fn load_thermo_baseline(path: &Path) -> Result<CiThermoBaseline> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("reading thermodynamic baseline from {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parsing thermodynamic baseline from {}", path.display()))
}

/// Compare `metrics` against `baseline` for a diff of `ast_diff_lines` lines.
///
/// Returns a non-empty `Vec<StructuredFinding>` containing
/// `security:thermodynamic_execution_anomaly` (Critical) when the diff is small
/// but the resource consumption spikes — the fingerprint of obfuscated payloads,
/// macro-bombs, and stealth compiler injections.
pub fn detect_ci_entropy_anomaly(
    metrics: &CiRunMetrics,
    baseline: &CiThermoBaseline,
    ast_diff_lines: usize,
) -> Vec<StructuredFinding> {
    if ast_diff_lines >= SMALL_DIFF_THRESHOLD {
        return Vec::new();
    }
    if baseline.execution_time_ms == 0 && baseline.memory_peak_kb == 0 {
        return Vec::new();
    }

    let time_ratio = if baseline.execution_time_ms > 0 {
        metrics.execution_time_ms as f64 / baseline.execution_time_ms as f64
    } else {
        0.0
    };
    let mem_ratio = if baseline.memory_peak_kb > 0 {
        metrics.memory_peak_kb as f64 / baseline.memory_peak_kb as f64
    } else {
        0.0
    };

    if time_ratio <= SPIKE_RATIO && mem_ratio <= SPIKE_RATIO {
        return Vec::new();
    }

    let spike_kind = if time_ratio > mem_ratio {
        "execution-time"
    } else {
        "memory"
    };
    let ratio = if time_ratio > mem_ratio {
        time_ratio
    } else {
        mem_ratio
    };

    vec![StructuredFinding {
        id: "security:thermodynamic_execution_anomaly".to_string(),
        file: Some(".github/workflows/janitor.yml".to_string()),
        line: None,
        fingerprint: String::new(),
        severity: Some("Critical".to_string()),
        remediation: Some(format!(
            "{spike_kind} spiked {ratio:.1}x baseline on a <{SMALL_DIFF_THRESHOLD}-line diff. \
             Audit CI for injected build steps, non-reproducible binary substitutions, and \
             actions/cache poisoning. Rebuild from a clean runner and compare \
             sha384sum target/release/janitor across both runs."
        )),
        docs_url: Some(
            "https://thejanitor.app/findings/thermodynamic-execution-anomaly".to_string(),
        ),
        ..Default::default()
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn baseline() -> CiThermoBaseline {
        CiThermoBaseline {
            execution_time_ms: 10_000,
            memory_peak_kb: 100_000,
        }
    }

    #[test]
    fn clean_run_no_findings() {
        let metrics = CiRunMetrics {
            execution_time_ms: 11_000,
            memory_peak_kb: 105_000,
        };
        assert!(detect_ci_entropy_anomaly(&metrics, &baseline(), 50).is_empty());
    }

    #[test]
    fn large_diff_suppresses_spike() {
        // Spike is real but diff is large → not suspicious.
        let metrics = CiRunMetrics {
            execution_time_ms: 100_000,
            memory_peak_kb: 500_000,
        };
        assert!(detect_ci_entropy_anomaly(&metrics, &baseline(), 200).is_empty());
    }

    #[test]
    fn cpu_spike_on_small_diff_triggers() {
        // 5× execution time spike on a 10-line diff → anomaly.
        let metrics = CiRunMetrics {
            execution_time_ms: 50_000,
            memory_peak_kb: 105_000,
        };
        let findings = detect_ci_entropy_anomaly(&metrics, &baseline(), 10);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "security:thermodynamic_execution_anomaly");
        assert_eq!(findings[0].severity.as_deref(), Some("Critical"));
        assert!(
            findings[0].id.contains("anomaly"),
            "finding id must reference anomaly"
        );
    }

    #[test]
    fn memory_spike_on_small_diff_triggers() {
        // 4× memory spike on a 5-line diff → anomaly.
        let metrics = CiRunMetrics {
            execution_time_ms: 10_500,
            memory_peak_kb: 400_001,
        };
        let findings = detect_ci_entropy_anomaly(&metrics, &baseline(), 5);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].id.contains("thermodynamic"));
    }

    #[test]
    fn zero_baseline_does_not_panic() {
        let zero = CiThermoBaseline {
            execution_time_ms: 0,
            memory_peak_kb: 0,
        };
        let metrics = CiRunMetrics {
            execution_time_ms: 99_999,
            memory_peak_kb: 999_999,
        };
        // Zero baseline → guard returns empty (avoids division by zero).
        assert!(detect_ci_entropy_anomaly(&metrics, &zero, 1).is_empty());
    }

    #[test]
    fn baseline_roundtrip_json() {
        let b = CiThermoBaseline {
            execution_time_ms: 12_000,
            memory_peak_kb: 204_800,
        };
        let json = serde_json::to_string(&b).unwrap();
        let b2: CiThermoBaseline = serde_json::from_str(&json).unwrap();
        assert_eq!(b.execution_time_ms, b2.execution_time_ms);
        assert_eq!(b.memory_peak_kb, b2.memory_peak_kb);
    }
}
