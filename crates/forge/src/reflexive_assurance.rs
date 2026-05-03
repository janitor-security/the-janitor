//! P4-11 Reflexive Assurance — Formal Verification Harnesses.
//!
//! Provides `#[kani::proof]` harnesses for critical security-scoring and
//! serialization functions. All harnesses are gated behind `#[cfg(kani)]`
//! and are therefore compiled only when the Kani Rust Verifier toolchain
//! is active (`cargo kani`). Regular `cargo test` excludes this block.
//!
//! ## Kani integration
//!
//! The `kani` crate is injected by the Kani toolchain and does NOT require a
//! separate crates.io dependency. Harnesses are written to the Kani ABI
//! (`kani::any::<T>()`, `kani::assume!`, `kani::assert!`) which is resolved
//! at verification time.
//!
//! To run: `cargo kani --harness <name>` with the Kani toolchain installed.

// ---------------------------------------------------------------------------
// Kani proof harnesses — compiled only under the Kani toolchain.
// ---------------------------------------------------------------------------

// The `kani` cfg is injected by the Kani toolchain at verification time.
// It is not a standard Cargo feature; suppress the lint for this module.
#[allow(unexpected_cfgs)]
#[cfg(kani)]
mod kani_proofs {
    use crate::slop_hunter::Severity;

    /// Prove that `Severity::points()` never panics and always returns a value
    /// within the declared range [0, 150] for any symbolic `Severity` variant.
    ///
    /// Safety property: exhaustive `match` covers every discriminant; no
    /// integer overflow is possible because all arms are constant literals.
    #[kani::proof]
    fn severity_points_no_panic_and_bounded() {
        // kani::any::<Severity>() generates all enum discriminants symbolically.
        let sev: Severity = kani::any();
        let pts = sev.points();
        // Verify the output is within the known bounded range.
        kani::assert(pts <= 150, "points() must not exceed 150 (KevCritical cap)");
    }

    /// Prove that the OTLP `timeUnixNano` computation (`ts_ms as u128 * 1_000_000`)
    /// never overflows a u128 for any representable u64 timestamp.
    ///
    /// Safety property: u64::MAX (≈1.84e19) × 1_000_000 ≈ 1.84e25, which is
    /// well below u128::MAX (≈3.4e38). CBMC / Kani verifies this statically.
    #[kani::proof]
    fn otlp_time_nanosecond_conversion_no_overflow() {
        let ts_ms: u64 = kani::any();
        // This mirrors the cast in esg_ledger::build_otlp_payload.
        let ts_ns: u128 = ts_ms as u128 * 1_000_000u128;
        // Proof obligation: result fits in u128 with no wrap.
        let _ = ts_ns;
    }

    /// Prove that `Severity::points()` for KevCritical specifically equals 150.
    ///
    /// Guards against future refactors that accidentally change the scoring
    /// constant without also updating Crucible and Bounty Ledger payout tables.
    #[kani::proof]
    fn kev_critical_points_is_150() {
        let pts = Severity::KevCritical.points();
        kani::assert(pts == 150, "KevCritical must score exactly 150 points");
    }
}

// ---------------------------------------------------------------------------
// Regression tests (compiled under standard cargo test).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use crate::slop_hunter::Severity;

    #[test]
    fn severity_points_exhaustive_match() {
        // Verify every variant maps to the documented constant — guards against
        // accidental constant changes that would invalidate Kani proof bounds.
        assert_eq!(Severity::KevCritical.points(), 150);
        assert_eq!(Severity::Exhaustion.points(), 100);
        assert_eq!(Severity::Critical.points(), 50);
        assert_eq!(Severity::High.points(), 40);
        assert_eq!(Severity::Warning.points(), 10);
        assert_eq!(Severity::Lint.points(), 0);
    }

    #[test]
    fn severity_points_max_is_150() {
        let all = [
            Severity::KevCritical,
            Severity::Exhaustion,
            Severity::Critical,
            Severity::High,
            Severity::Warning,
            Severity::Lint,
        ];
        assert!(
            all.iter().all(|s| s.points() <= 150),
            "no severity must exceed the 150-point Kani proof bound"
        );
    }

    #[test]
    fn otlp_ts_ns_conversion_does_not_overflow_u64_max() {
        let ts_ms = u64::MAX;
        // Same cast as build_otlp_payload — must not panic.
        let ts_ns: u128 = ts_ms as u128 * 1_000_000u128;
        assert!(ts_ns <= u128::MAX, "u64::MAX * 1_000_000 must fit in u128");
    }
}
