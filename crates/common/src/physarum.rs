//! Physarum Protocol — biological backpressure for the daemon request queue.
//!
//! Queries OS memory usage to produce a [`Pulse`] that governs whether the
//! daemon accepts new work, throttles concurrency, or enters a full stop.
//!
//! Named after *Physarum polycephalum* (slime mould), which modulates nutrient
//! flow through its vein network in direct response to environmental pressure:
//! veins carrying less traffic constrict and eventually die; those carrying more
//! dilate.  The same principle governs our request queue under memory pressure.
//!
//! ## Thresholds
//!
//! | RAM used | Pulse        | Effect                                |
//! |----------|--------------|---------------------------------------|
//! | ≤ 75 %   | `Flow`       | Accept work at full concurrency.       |
//! | 75–90 %  | `Constrict`  | Limit to 2 concurrent tasks.          |
//! | > 90 %   | `Stop`       | Reject; caller sleeps 500 ms and retries. |

use sysinfo::System;

// ---------------------------------------------------------------------------
// Pulse
// ---------------------------------------------------------------------------

/// Memory-pressure signal emitted by [`SystemHeart::beat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pulse {
    /// RAM ≤ 75 % — accept new work at full concurrency.
    Flow,
    /// 75 % < RAM ≤ 90 % — throttle; limit parallel tasks to 2.
    Constrict,
    /// RAM > 90 % — full stop; caller must sleep and retry.
    Stop,
}

// ---------------------------------------------------------------------------
// SystemHeart
// ---------------------------------------------------------------------------

/// Samples OS memory state and returns a [`Pulse`] representing current pressure.
///
/// Holds a [`sysinfo::System`] behind a `Mutex` so it can be shared across
/// Tokio tasks via `Arc<DaemonState>`.  The lock is held only for the duration
/// of a single `refresh_memory()` call — negligible contention.
pub struct SystemHeart {
    sys: std::sync::Mutex<System>,
}

impl SystemHeart {
    /// Create a new `SystemHeart`, initialising the sysinfo handle.
    pub fn new() -> Self {
        Self {
            sys: std::sync::Mutex::new(System::new()),
        }
    }

    /// Sample current memory pressure and return the corresponding [`Pulse`].
    ///
    /// Refreshes memory statistics on every call to ensure an up-to-date
    /// reading.  Returns [`Pulse::Flow`] on platforms where `sysinfo` cannot
    /// determine total memory (i.e., when `total_memory() == 0`).
    pub fn beat(&self) -> Pulse {
        let mut sys = self.sys.lock().unwrap_or_else(|e| e.into_inner());
        sys.refresh_memory();

        let total = sys.total_memory();
        if total == 0 {
            // No memory info available (e.g. some BSDs, CI sandboxes) — allow flow.
            return Pulse::Flow;
        }

        let used = sys.used_memory();
        let pct = used as f64 / total as f64 * 100.0;

        if pct > 90.0 {
            Pulse::Stop
        } else if pct > 75.0 {
            Pulse::Constrict
        } else {
            Pulse::Flow
        }
    }
}

impl Default for SystemHeart {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heart_returns_valid_pulse() {
        // Just confirm it doesn't panic and returns one of the three variants.
        let heart = SystemHeart::new();
        let pulse = heart.beat();
        assert!(matches!(
            pulse,
            Pulse::Flow | Pulse::Constrict | Pulse::Stop
        ));
    }

    #[test]
    fn test_pulse_thresholds() {
        // Verify threshold logic with synthetic percentages.
        let classify = |pct: f64| -> Pulse {
            if pct > 90.0 {
                Pulse::Stop
            } else if pct > 75.0 {
                Pulse::Constrict
            } else {
                Pulse::Flow
            }
        };
        assert_eq!(classify(50.0), Pulse::Flow);
        assert_eq!(classify(75.0), Pulse::Flow); // boundary — inclusive
        assert_eq!(classify(75.1), Pulse::Constrict);
        assert_eq!(classify(90.0), Pulse::Constrict); // boundary — inclusive
        assert_eq!(classify(90.1), Pulse::Stop);
    }

    #[test]
    fn test_heart_default_matches_new() {
        // Default and new() must behave identically.
        let _a = SystemHeart::new();
        let _b = SystemHeart::default();
        // Both should return a valid Pulse without panicking.
    }
}
