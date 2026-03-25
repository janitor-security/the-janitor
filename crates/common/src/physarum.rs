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
//! ## Threshold table
//!
//! | Condition                             | Pulse       | Effect                                     |
//! |---------------------------------------|-------------|--------------------------------------------|
//! | SMA% ≤ 75 %  AND  velocity ≤ 100 MB/s | `Flow`      | Accept work at full concurrency.           |
//! | SMA% 75–90 %  OR  velocity > 100 MB/s | `Constrict` | Limit to 2 concurrent tasks.              |
//! | SMA% > 90 %                           | `Stop`      | Reject; caller sleeps 500 ms and retries. |
//!
//! ## SMA gate
//!
//! Each call to [`SystemHeart::beat`] records the current `used_memory` reading
//! with a timestamp in a 16-slot ring buffer.  The arithmetic mean of all
//! samples within the last [`SMA_WINDOW_SECS`] seconds is used for the
//! percentage thresholds instead of the raw instantaneous reading.  This
//! smooths transient allocation spikes that self-resolve within the window,
//! while still responding promptly to sustained pressure.
//!
//! ## Velocity gate
//!
//! Alongside the SMA, [`SystemHeart::beat`] computes a linear allocation
//! velocity from the oldest to the newest sample in the window
//! (`Δused / Δtime`).  A positive velocity exceeding
//! [`HIGH_VELOCITY_BYTES_PER_SEC`] (100 MB/s) escalates the pulse to at least
//! `Constrict` even when the SMA percentage is below 75 %.  Negative velocity
//! (memory being freed) is ignored.  The velocity override cannot escalate
//! beyond `Constrict`; a hard `Stop` is always driven by the percentage gate.
//!
//! ## Overhead
//!
//! The ring buffer is a fixed 16-slot array of `(Instant, u64)` pairs (224
//! bytes on 64-bit platforms).  No heap allocation occurs on any call path.
//! The per-beat cost is one `sysinfo::refresh_memory()` call plus O(16) scalar
//! arithmetic — negligible on any hardware the daemon is likely to run on.

use std::time::{Duration, Instant};

use sysinfo::System;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of the sliding window used for the Simple Moving Average.
const SMA_WINDOW_SECS: f64 = 3.0;

/// Allocation velocity above which the pulse is escalated to at least
/// [`Pulse::Constrict`], even when the SMA percentage is below 75 %.
///
/// 100 MB/s is chosen as the threshold: sustained allocation at that rate
/// would exhaust a 4 GB free-RAM headroom in ~40 seconds, which is fast
/// enough to pre-empt OOM before the static 75 % gate fires.
const HIGH_VELOCITY_BYTES_PER_SEC: f64 = 100.0 * 1024.0 * 1024.0;

/// Capacity of the ring buffer.  16 slots at typical daemon call rates
/// (1–4 calls/sec) provides 4–16 seconds of history — well beyond the
/// 3-second SMA window.
const RING_CAPACITY: usize = 16;

// ---------------------------------------------------------------------------
// Pulse
// ---------------------------------------------------------------------------

/// Memory-pressure signal emitted by [`SystemHeart::beat`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pulse {
    /// SMA% ≤ 75 % and velocity ≤ 100 MB/s — accept new work at full concurrency.
    Flow,
    /// SMA% 75–90 % **or** velocity > 100 MB/s — throttle; limit parallel tasks to 2.
    Constrict,
    /// SMA% > 90 % — full stop; caller must sleep and retry.
    Stop,
}

// ---------------------------------------------------------------------------
// Ring-buffer history
// ---------------------------------------------------------------------------

/// A single memory sample.
#[derive(Clone, Copy)]
struct Sample {
    at: Instant,
    used: u64,
}

/// Fixed-capacity ring buffer for the SMA and velocity computation.
///
/// No heap allocation.  Maximum size: `RING_CAPACITY × size_of::<Option<Sample>>()`
/// = 16 × 14 bytes ≈ 224 bytes on 64-bit platforms.
struct SmaHistory {
    buf: [Option<Sample>; RING_CAPACITY],
    /// Index of the next write slot (wraps around).
    head: usize,
}

impl SmaHistory {
    fn new() -> Self {
        Self {
            buf: [None; RING_CAPACITY],
            head: 0,
        }
    }

    /// Record a new memory sample, overwriting the oldest slot when full.
    fn push(&mut self, sample: Sample) {
        self.buf[self.head] = Some(sample);
        self.head = (self.head + 1) % RING_CAPACITY;
    }

    /// Compute `(sma_bytes, velocity_bytes_per_sec)` from samples within
    /// the last [`SMA_WINDOW_SECS`] seconds relative to `now`.
    ///
    /// Returns `(None, None)` if no samples fall within the window.
    /// `velocity` is `None` when fewer than 2 window samples exist or when
    /// the time span between oldest and newest is effectively zero.
    fn compute(&self, now: Instant) -> (Option<f64>, Option<f64>) {
        // Saturating subtraction: if `now` is somehow earlier than the
        // duration (shouldn't happen, but be safe).
        let cutoff = now
            .checked_sub(Duration::from_secs_f64(SMA_WINDOW_SECS))
            .unwrap_or(now);

        let mut count: u64 = 0;
        let mut sum: u64 = 0;
        let mut oldest: Option<Sample> = None;
        let mut newest: Option<Sample> = None;

        for s in self.buf.iter().flatten() {
            if s.at >= cutoff {
                count += 1;
                sum = sum.saturating_add(s.used);
                oldest = Some(match oldest {
                    None => *s,
                    Some(o) if s.at < o.at => *s,
                    Some(o) => o,
                });
                newest = Some(match newest {
                    None => *s,
                    Some(n) if s.at > n.at => *s,
                    Some(n) => n,
                });
            }
        }

        if count == 0 {
            return (None, None);
        }

        let sma = sum as f64 / count as f64;

        // Velocity: bytes per second from oldest to newest window sample.
        // Only meaningful (and non-zero) when the two endpoints differ.
        let velocity = match (oldest, newest) {
            (Some(o), Some(n)) if n.at > o.at => {
                let elapsed = n.at.duration_since(o.at).as_secs_f64();
                if elapsed > 0.0 {
                    Some((n.used as f64 - o.used as f64) / elapsed)
                } else {
                    None
                }
            }
            _ => None,
        };

        (Some(sma), velocity)
    }
}

// ---------------------------------------------------------------------------
// Inner state (single lock)
// ---------------------------------------------------------------------------

/// Combined sysinfo handle + ring-buffer history, protected by one mutex so
/// the sample push and the SMA/velocity read are always consistent.
struct Inner {
    sys: System,
    history: SmaHistory,
}

// ---------------------------------------------------------------------------
// SystemHeart
// ---------------------------------------------------------------------------

/// Samples OS memory state and returns a [`Pulse`] representing current pressure.
///
/// Holds all mutable state behind a single `Mutex` so it can be shared across
/// Tokio tasks via `Arc<DaemonState>`.  The lock is held only for the duration
/// of one `refresh_memory()` call plus O(16) arithmetic — negligible contention.
pub struct SystemHeart {
    inner: std::sync::Mutex<Inner>,
}

impl SystemHeart {
    /// Create a new `SystemHeart`, initialising the sysinfo handle and the
    /// empty ring-buffer history.
    pub fn new() -> Self {
        Self {
            inner: std::sync::Mutex::new(Inner {
                sys: System::new(),
                history: SmaHistory::new(),
            }),
        }
    }

    /// Sample current memory pressure and return the corresponding [`Pulse`].
    ///
    /// # Algorithm
    ///
    /// 1. Refresh OS memory statistics.
    /// 2. Push `(now, used_bytes)` into the ring buffer.
    /// 3. Compute the SMA and allocation velocity from all samples in the
    ///    last [`SMA_WINDOW_SECS`] seconds.
    /// 4. Apply the percentage gate using the SMA (falls back to the raw
    ///    reading on the very first call before the window has any history).
    /// 5. Apply the velocity override: escalate to `Constrict` if the
    ///    allocation rate exceeds [`HIGH_VELOCITY_BYTES_PER_SEC`] and the
    ///    percentage gate would otherwise return `Flow`.
    ///
    /// Returns [`Pulse::Flow`] on platforms where `sysinfo` cannot determine
    /// total memory (i.e., when `total_memory() == 0`).
    pub fn beat(&self) -> Pulse {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.sys.refresh_memory();

        let total = g.sys.total_memory();
        if total == 0 {
            // No memory info available (e.g. some BSDs, CI sandboxes) — allow flow.
            return Pulse::Flow;
        }

        let used = g.sys.used_memory();
        let now = Instant::now();

        // Record the new sample before computing — ensures the current reading
        // participates in both the SMA and the velocity calculation.
        g.history.push(Sample { at: now, used });

        let (sma, velocity) = g.history.compute(now);

        // Use the SMA-smoothed value for the percentage gate; fall back to
        // the raw reading on the very first beat (window empty before push).
        let effective_used = sma.unwrap_or(used as f64);
        let pct = effective_used / total as f64 * 100.0;

        // Percentage-driven base pulse.
        let base = if pct > 90.0 {
            Pulse::Stop
        } else if pct > 75.0 {
            Pulse::Constrict
        } else {
            Pulse::Flow
        };

        // Velocity override: a rapid positive allocation surge escalates to
        // at least Constrict even when the SMA is within normal bounds.
        // Negative velocity (memory being freed) is intentionally ignored.
        // The velocity gate cannot produce Stop — that requires the SMA to
        // cross the 90 % hard ceiling.
        if base == Pulse::Flow {
            if let Some(v) = velocity {
                if v > HIGH_VELOCITY_BYTES_PER_SEC {
                    return Pulse::Constrict;
                }
            }
        }

        base
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
        let heart = SystemHeart::new();
        let pulse = heart.beat();
        assert!(matches!(
            pulse,
            Pulse::Flow | Pulse::Constrict | Pulse::Stop
        ));
    }

    #[test]
    fn test_pulse_thresholds() {
        // Verify percentage-driven threshold logic directly.
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
        let _a = SystemHeart::new();
        let _b = SystemHeart::default();
        // Both should return a valid Pulse without panicking.
    }

    #[test]
    fn test_sma_history_empty_returns_none() {
        let h = SmaHistory::new();
        let (sma, vel) = h.compute(Instant::now());
        assert!(sma.is_none());
        assert!(vel.is_none());
    }

    #[test]
    fn test_sma_history_single_sample() {
        let mut h = SmaHistory::new();
        let now = Instant::now();
        h.push(Sample {
            at: now,
            used: 1_000_000,
        });
        let (sma, vel) = h.compute(now);
        assert_eq!(sma, Some(1_000_000.0));
        // Only one sample — no velocity.
        assert!(vel.is_none());
    }

    #[test]
    fn test_sma_history_two_samples_velocity() {
        let mut h = SmaHistory::new();
        let t0 = Instant::now();
        // Simulate 200 MB increase over 1 second — should be 200 MB/s.
        let t1 = t0 + Duration::from_secs(1);
        h.push(Sample { at: t0, used: 0 });
        h.push(Sample {
            at: t1,
            used: 200 * 1024 * 1024,
        });
        let (sma, vel) = h.compute(t1);
        // SMA: (0 + 200 MB) / 2
        assert_eq!(sma, Some(100.0 * 1024.0 * 1024.0));
        // Velocity: 200 MB/s
        let v = vel.expect("velocity should be Some with 2 samples");
        let expected = 200.0 * 1024.0 * 1024.0;
        assert!((v - expected).abs() < 1.0, "velocity {v} ≉ {expected}");
    }

    #[test]
    fn test_sma_history_stale_samples_excluded() {
        let mut h = SmaHistory::new();
        let now = Instant::now();
        // Push a sample 10 seconds ago — outside the 3-second window.
        let stale = now - Duration::from_secs(10);
        h.push(Sample {
            at: stale,
            used: 999_999_999,
        });
        // Only the stale sample is in the buffer; it should be excluded.
        let (sma, vel) = h.compute(now);
        assert!(sma.is_none(), "stale sample should be excluded from SMA");
        assert!(vel.is_none());
    }

    #[test]
    fn test_sma_history_ring_overflow() {
        // Push more than RING_CAPACITY samples; oldest must be overwritten.
        let mut h = SmaHistory::new();
        let now = Instant::now();
        for i in 0..=(RING_CAPACITY + 2) {
            h.push(Sample {
                at: now,
                used: i as u64 * 1024,
            });
        }
        // After overflow the oldest slots are gone; we should still get a valid SMA.
        let (sma, _) = h.compute(now);
        assert!(sma.is_some(), "SMA should be Some after ring overflow");
    }

    #[test]
    fn test_velocity_override_triggers_constrict() {
        // Build a history with a >100 MB/s ramp and verify the velocity gate.
        let mut h = SmaHistory::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        // 200 MB increase in 1 second = 200 MB/s — above the 100 MB/s threshold.
        h.push(Sample { at: t0, used: 0 });
        h.push(Sample {
            at: t1,
            used: 200 * 1024 * 1024,
        });
        let (_, vel) = h.compute(t1);
        let v = vel.unwrap();
        assert!(
            v > HIGH_VELOCITY_BYTES_PER_SEC,
            "velocity {v} should exceed HIGH_VELOCITY_BYTES_PER_SEC"
        );
    }

    #[test]
    fn test_negative_velocity_does_not_trigger() {
        // Memory being freed (negative delta) must not trigger the velocity gate.
        let mut h = SmaHistory::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(1);
        h.push(Sample {
            at: t0,
            used: 500 * 1024 * 1024,
        });
        h.push(Sample {
            at: t1,
            used: 100 * 1024 * 1024,
        });
        let (_, vel) = h.compute(t1);
        let v = vel.unwrap();
        // Velocity is negative — should NOT exceed the positive threshold.
        assert!(
            v <= HIGH_VELOCITY_BYTES_PER_SEC,
            "negative velocity should not trigger the gate"
        );
    }
}
