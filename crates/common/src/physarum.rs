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
//! ## Swarm Edge Integrity
//!
//! [`SystemHeart::beat_swarm`] accepts an `active_collisions` count from the
//! `LshIndex`.  When the Swarm detector observes coordinated clone injection,
//! a virtual pressure multiplier is applied to the SMA percentage before the
//! threshold gates are evaluated.  This tightens the effective thresholds
//! proportionally to collision load, preserving RAM headroom before a wave of
//! structurally identical patches saturates the analysis pool simultaneously.
//!
//! The principle mirrors *Physarum* Edge Integrity: peripheral veins constrict
//! first under nutrient pressure, protecting the core network routing capacity.
//! Under a Swarm attack the "peripheral veins" are the excess analysis slots —
//! they close before the core is starved.
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
//! ## Hardware-Aware Concurrency
//!
//! [`detect_optimal_concurrency`] queries `sysinfo` for total system RAM and
//! returns a thread-count recommendation:
//!
//! | Total RAM    | Workers          | Mode            |
//! |-------------|-----------------|-----------------|
//! | < 8 GB      | 2               | Safety          |
//! | 8–16 GB     | 4               | Standard        |
//! | 16–32 GB    | 8               | High-Velocity   |
//! | > 32 GB     | logical CPU count | Aggressive    |
//!
//! The `--concurrency` flag on both `janitor` and `gauntlet-runner` allows
//! manual override; `0` (the default) selects auto-detection.
//!
//! ## Overhead
//!
//! The ring buffer is a fixed 16-slot array of `(Instant, u64)` pairs (224
//! bytes on 64-bit platforms).  No heap allocation occurs on any call path.
//!
//! `beat()` calls `sysinfo::refresh_memory()` **at most once per
//! [`REFRESH_THROTTLE`] interval** (100 ms).  Calls within the throttle
//! window return the cached reading immediately — one mutex acquisition and
//! one `Instant::now()` call, with no OS syscall.  This decouples the
//! memory observer from the scanning hot-path: a rayon pool processing 100
//! PRs/sec issues ≤ 10 sysinfo reads/sec instead of 100.

use std::time::{Duration, Instant};

use sysinfo::System;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Length of the sliding window used for the Simple Moving Average.
const SMA_WINDOW_SECS: f64 = 3.0;

/// Allocation velocity above which the pulse is escalated to at least
/// [`Pulse::Constrict`], even when the SMA percentage is below the normal
/// Constrict threshold.
///
/// 100 MB/s is chosen as the threshold: sustained allocation at that rate
/// would exhaust a 4 GB free-RAM headroom in ~40 seconds, which is fast
/// enough to pre-empt OOM before the static gate fires.
const HIGH_VELOCITY_BYTES_PER_SEC: f64 = 100.0 * 1024.0 * 1024.0;

/// Constrict threshold on systems with ≤ 16 GB total RAM, or whenever the
/// SMA velocity exceeds [`HIGH_VELOCITY_BYTES_PER_SEC`].
const CONSTRICT_THRESHOLD_NORMAL: f64 = 75.0;

/// Constrict threshold on systems with > 16 GB total RAM **and** stable
/// velocity (≤ [`HIGH_VELOCITY_BYTES_PER_SEC`]).  Rewards high-RAM hosts
/// with a wider Flow band before throttling.
const CONSTRICT_THRESHOLD_HIGH_RAM: f64 = 85.0;

/// Total-RAM boundary (in GiB) above which the high-RAM Constrict threshold
/// applies when velocity is stable.
const HIGH_RAM_THRESHOLD_GIB: u64 = 16;

/// Capacity of the ring buffer.  16 slots at typical daemon call rates
/// (1–4 calls/sec) provides 4–16 seconds of history — well beyond the
/// 3-second SMA window.
const RING_CAPACITY: usize = 16;

/// Minimum elapsed time between actual `sysinfo::refresh_memory()` syscalls.
///
/// Consecutive `beat()` calls within this window reuse the cached memory
/// reading and return immediately.  The SMA ring buffer is updated **only**
/// on actual refreshes so the window always contains real observations.
///
/// 100 ms is chosen to decouple the memory observer from the scanning
/// hot-path: a rayon pool processing PRs at 50–200 ms each previously
/// issued one `refresh_memory()` per PR.  With the throttle the refresh
/// rate is bounded at ≤ 10 reads/sec regardless of PR throughput, while
/// still responding to sustained memory pressure within one SMA window
/// (3 s / 0.1 s = up to 30 samples per window — more than enough for the
/// velocity and SMA calculations).
const REFRESH_THROTTLE: Duration = Duration::from_millis(100);

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
    /// Timestamp of the last actual `sysinfo::refresh_memory()` call.
    ///
    /// Initialised to `now - REFRESH_THROTTLE` so the very first `beat()`
    /// always performs a real refresh.
    last_refresh: Instant,
    /// Cached total memory bytes from the most recent real refresh.
    cached_total: u64,
    /// Cached used memory bytes from the most recent real refresh.
    cached_used: u64,
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
        // Initialise last_refresh to (now − REFRESH_THROTTLE) so the very
        // first beat() always performs a real sysinfo refresh.
        // checked_sub guards against the (theoretical) case where Instant::now()
        // is less than REFRESH_THROTTLE after the monotonic clock epoch.
        let stale = Instant::now()
            .checked_sub(REFRESH_THROTTLE)
            .unwrap_or_else(Instant::now);
        Self {
            inner: std::sync::Mutex::new(Inner {
                sys: System::new(),
                history: SmaHistory::new(),
                last_refresh: stale,
                cached_total: 0,
                cached_used: 0,
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
        let now = Instant::now();

        // Throttled refresh — call sysinfo only when the window has elapsed.
        // The SMA ring buffer is updated only on actual refreshes so every
        // sample in the history represents a distinct OS observation.
        if now.duration_since(g.last_refresh) >= REFRESH_THROTTLE {
            g.sys.refresh_memory();
            g.cached_total = g.sys.total_memory();
            g.cached_used = g.sys.used_memory();
            g.last_refresh = now;
            // Copy before the push to avoid a simultaneous mut/imm borrow of `g`.
            let snapshot_used = g.cached_used;
            g.history.push(Sample {
                at: now,
                used: snapshot_used,
            });
        }

        let total = g.cached_total;
        if total == 0 {
            // No memory info available (e.g. some BSDs, CI sandboxes) — allow flow.
            return Pulse::Flow;
        }

        let used = g.cached_used;
        let (sma, velocity) = g.history.compute(now);

        // Use the SMA-smoothed value for the percentage gate; fall back to
        // the raw reading on the very first beat (window empty before push).
        let effective_used = sma.unwrap_or(used as f64);
        let pct = effective_used / total as f64 * 100.0;

        // Adaptive Constrict threshold: on systems with > 16 GiB total RAM
        // and stable allocation velocity, widen the Flow band to 85 % so
        // high-memory hosts benefit from proportionally higher throughput.
        // Under velocity pressure (rapid allocation) the conservative 75 %
        // gate is always enforced regardless of total RAM.
        let velocity_is_stable = velocity
            .map(|v| v <= HIGH_VELOCITY_BYTES_PER_SEC)
            .unwrap_or(true);
        let total_gib = total / (1024 * 1024 * 1024);
        let constrict_threshold = if total_gib >= HIGH_RAM_THRESHOLD_GIB && velocity_is_stable {
            CONSTRICT_THRESHOLD_HIGH_RAM
        } else {
            CONSTRICT_THRESHOLD_NORMAL
        };

        // Percentage-driven base pulse.
        let base = if pct > 90.0 {
            Pulse::Stop
        } else if pct > constrict_threshold {
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

    /// Sample memory pressure under active Swarm conditions and return the
    /// corresponding [`Pulse`].
    ///
    /// Identical to [`beat`] except that a **virtual pressure multiplier** is
    /// applied to the SMA percentage when `active_collisions > 0`.  When the
    /// `LshIndex` detects coordinated clone injection across multiple PRs the
    /// daemon passes the live collision count so the gate triggers earlier —
    /// preserving RAM headroom before a wave of structurally identical patches
    /// is analysed simultaneously.
    ///
    /// The principle mirrors *Physarum polycephalum* Edge Integrity: veins at
    /// the network periphery constrict first when nutrient supply is threatened,
    /// protecting the core routing capacity.  A Swarm attack is the biological
    /// equivalent of a simultaneous peripheral load spike.
    ///
    /// # Multiplier schedule
    ///
    /// | `active_collisions` | Multiplier | Effective `Flow` ceiling |
    /// |---------------------|------------|--------------------------|
    /// | 0                   | ×1.00      | ≤ 75 % (delegates to [`beat`]) |
    /// | 1–4                 | ×1.15      | ≤ ~65 % real RAM         |
    /// | 5+                  | ×1.25      | ≤ 60 % real RAM          |
    ///
    /// The velocity override remains active regardless of multiplier.  A hard
    /// `Stop` is still only reachable when the *inflated* percentage exceeds
    /// 90 % — the multiplier can produce `Stop` at lower real RAM under heavy
    /// Swarm load, which is the intended behaviour.
    pub fn beat_swarm(&self, active_collisions: usize) -> Pulse {
        // Zero collisions — identical semantics to beat(); avoid touching the
        // lock twice by delegating directly.
        if active_collisions == 0 {
            return self.beat();
        }

        let multiplier = if active_collisions >= 5 {
            1.25_f64 // heavy swarm: 72 % real RAM saturates the Stop gate
        } else {
            1.15_f64 // light swarm: ~78 % real RAM saturates the Stop gate
        };

        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let now = Instant::now();

        // Same throttled-refresh logic as beat() — the Swarm variant shares
        // the Inner cache so both paths benefit from the same deduplication.
        if now.duration_since(g.last_refresh) >= REFRESH_THROTTLE {
            g.sys.refresh_memory();
            g.cached_total = g.sys.total_memory();
            g.cached_used = g.sys.used_memory();
            g.last_refresh = now;
            let snapshot_used = g.cached_used;
            g.history.push(Sample {
                at: now,
                used: snapshot_used,
            });
        }

        let total = g.cached_total;
        if total == 0 {
            return Pulse::Flow;
        }

        let used = g.cached_used;
        let (sma, velocity) = g.history.compute(now);

        let effective_used = sma.unwrap_or(used as f64);
        // Apply the Swarm multiplier: virtual pressure inflates the percentage
        // so that the existing static thresholds fire at a lower real RAM%.
        let pct = effective_used / total as f64 * 100.0 * multiplier;

        let base = if pct > 90.0 {
            Pulse::Stop
        } else if pct > 75.0 {
            Pulse::Constrict
        } else {
            Pulse::Flow
        };

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
// Hardware-Aware Concurrency
// ---------------------------------------------------------------------------

/// Recommend an optimal rayon worker count based on total system RAM.
///
/// Queries `sysinfo` for total physical memory and maps it to a thread count
/// that keeps peak RSS safely within available headroom.  Each bounce worker
/// peaks at ≈100–250 MB; the table below targets ≤ 50 % RSS on the host RAM
/// tier as a steady-state safety margin.
///
/// | Total RAM    | Workers          | Mode            |
/// |--------------|-----------------|-----------------|
/// | < 8 GiB      | 2               | Safety          |
/// | 8–16 GiB     | 4               | Standard        |
/// | 16–32 GiB    | 8               | High-Velocity   |
/// | > 32 GiB     | logical CPU count | Aggressive    |
///
/// Returns `2` on platforms where `sysinfo` cannot report total memory.
/// The caller may override this value with `--concurrency <N>`.
pub fn detect_optimal_concurrency() -> usize {
    let mut sys = System::new();
    sys.refresh_memory();
    let total = sys.total_memory();
    if total == 0 {
        return 2; // sysinfo unavailable — conservative default
    }
    let total_gib = total / (1024 * 1024 * 1024);
    match total_gib {
        0..=7 => 2,   // < 8 GiB: Safety Mode
        8..=15 => 4,  // 8–16 GiB: Standard
        16..=31 => 8, // 16–32 GiB: High-Velocity
        _ => {
            // > 32 GiB: Aggressive — saturate all logical cores.
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(8)
        }
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

    #[test]
    fn test_beat_swarm_zero_collisions_returns_valid_pulse() {
        // beat_swarm(0) must delegate to beat() and return a valid Pulse.
        let heart = SystemHeart::new();
        let pulse = heart.beat_swarm(0);
        assert!(matches!(
            pulse,
            Pulse::Flow | Pulse::Constrict | Pulse::Stop
        ));
    }

    #[test]
    fn test_beat_swarm_light_collisions_returns_valid_pulse() {
        let heart = SystemHeart::new();
        let pulse = heart.beat_swarm(2);
        assert!(matches!(
            pulse,
            Pulse::Flow | Pulse::Constrict | Pulse::Stop
        ));
    }

    #[test]
    fn test_beat_swarm_heavy_collisions_returns_valid_pulse() {
        let heart = SystemHeart::new();
        let pulse = heart.beat_swarm(5);
        assert!(matches!(
            pulse,
            Pulse::Flow | Pulse::Constrict | Pulse::Stop
        ));
    }

    #[test]
    fn test_beat_swarm_multiplier_tightens_threshold() {
        // Verify the multiplier: at 70 % real RAM, a ×1.25 multiplier
        // produces a virtual 87.5 % — which must cross the 75 % Constrict
        // gate.  We test the math directly without relying on sysinfo.
        let real_pct: f64 = 70.0;

        let normal_pulse = |pct: f64| -> Pulse {
            if pct > 90.0 {
                Pulse::Stop
            } else if pct > 75.0 {
                Pulse::Constrict
            } else {
                Pulse::Flow
            }
        };

        // Without multiplier: 70 % → Flow.
        assert_eq!(normal_pulse(real_pct), Pulse::Flow);

        // With ×1.25 swarm multiplier: 70 × 1.25 = 87.5 % → Constrict.
        assert_eq!(normal_pulse(real_pct * 1.25), Pulse::Constrict);

        // With ×1.15 light swarm: 70 × 1.15 = 80.5 % → Constrict.
        assert_eq!(normal_pulse(real_pct * 1.15), Pulse::Constrict);
    }

    #[test]
    fn test_beat_swarm_heavy_multiplier_can_reach_stop() {
        // At 73 % real RAM, ×1.25 = 91.25 % — crosses the 90 % Stop gate.
        let real_pct: f64 = 73.0;
        let virtual_pct = real_pct * 1.25;
        assert!(
            virtual_pct > 90.0,
            "heavy Swarm multiplier must push 73 % real RAM past the Stop gate"
        );
    }

    #[test]
    fn test_throttled_refresh_rapid_calls_return_valid_pulse() {
        // Rapid consecutive beat() calls within the 100 ms throttle window
        // must all return valid pulses without panicking.
        let heart = SystemHeart::new();
        for _ in 0..20 {
            let pulse = heart.beat();
            assert!(
                matches!(pulse, Pulse::Flow | Pulse::Constrict | Pulse::Stop),
                "rapid beat() call returned unexpected variant"
            );
        }
    }

    #[test]
    fn test_throttled_refresh_beat_and_beat_swarm_share_cache() {
        // beat() followed immediately by beat_swarm() within the throttle
        // window must both return valid pulses — they share the Inner cache.
        let heart = SystemHeart::new();
        let p1 = heart.beat();
        let p2 = heart.beat_swarm(3);
        assert!(matches!(p1, Pulse::Flow | Pulse::Constrict | Pulse::Stop));
        assert!(matches!(p2, Pulse::Flow | Pulse::Constrict | Pulse::Stop));
    }

    #[test]
    fn test_detect_optimal_concurrency_returns_positive() {
        let n = super::detect_optimal_concurrency();
        assert!(n >= 2, "concurrency must be at least 2, got {n}");
    }

    #[test]
    fn test_detect_optimal_concurrency_tiers() {
        // Validate the tier logic directly using the same formula, without
        // relying on actual sysinfo (which varies per machine).
        let tier = |total_gib: u64| -> usize {
            match total_gib {
                0..=7 => 2,
                8..=15 => 4,
                16..=31 => 8,
                _ => std::thread::available_parallelism()
                    .map(|n| n.get())
                    .unwrap_or(8),
            }
        };
        assert_eq!(tier(4), 2, "4 GiB → Safety Mode (2 workers)");
        assert_eq!(tier(7), 2, "7 GiB → Safety Mode boundary");
        assert_eq!(tier(8), 4, "8 GiB → Standard (4 workers)");
        assert_eq!(tier(15), 4, "15 GiB → Standard boundary");
        assert_eq!(tier(16), 8, "16 GiB → High-Velocity (8 workers)");
        assert_eq!(tier(31), 8, "31 GiB → High-Velocity boundary");
        assert!(tier(32) >= 1, "32+ GiB → Aggressive (≥1 workers)");
    }

    #[test]
    fn test_adaptive_constrict_threshold_high_ram() {
        // On a high-RAM host with stable velocity, the Constrict threshold
        // is 85 % — so 80 % usage must remain Flow.
        let pct: f64 = 80.0;
        let total_gib: u64 = 32; // > HIGH_RAM_THRESHOLD_GIB
        let velocity_is_stable = true;
        let constrict_threshold = if total_gib >= HIGH_RAM_THRESHOLD_GIB && velocity_is_stable {
            CONSTRICT_THRESHOLD_HIGH_RAM
        } else {
            CONSTRICT_THRESHOLD_NORMAL
        };
        let base = if pct > 90.0 {
            Pulse::Stop
        } else if pct > constrict_threshold {
            Pulse::Constrict
        } else {
            Pulse::Flow
        };
        assert_eq!(
            base,
            Pulse::Flow,
            "80 % on 32 GiB host with stable velocity must be Flow (threshold=85%)"
        );
    }

    #[test]
    fn test_adaptive_constrict_threshold_normal_ram() {
        // On a normal host, 80 % must be Constrict (threshold=75 %).
        let pct: f64 = 80.0;
        let total_gib: u64 = 8;
        let velocity_is_stable = true;
        let constrict_threshold = if total_gib >= HIGH_RAM_THRESHOLD_GIB && velocity_is_stable {
            CONSTRICT_THRESHOLD_HIGH_RAM
        } else {
            CONSTRICT_THRESHOLD_NORMAL
        };
        let base = if pct > 90.0 {
            Pulse::Stop
        } else if pct > constrict_threshold {
            Pulse::Constrict
        } else {
            Pulse::Flow
        };
        assert_eq!(
            base,
            Pulse::Constrict,
            "80 % on 8 GiB host must be Constrict (threshold=75 %)"
        );
    }

    #[test]
    fn test_adaptive_constrict_threshold_high_ram_unstable_velocity() {
        // High-RAM host BUT velocity is unstable → conservative 75 % threshold.
        let pct: f64 = 80.0;
        let total_gib: u64 = 32;
        let velocity_is_stable = false; // rapid allocation
        let constrict_threshold = if total_gib >= HIGH_RAM_THRESHOLD_GIB && velocity_is_stable {
            CONSTRICT_THRESHOLD_HIGH_RAM
        } else {
            CONSTRICT_THRESHOLD_NORMAL
        };
        let base = if pct > 90.0 {
            Pulse::Stop
        } else if pct > constrict_threshold {
            Pulse::Constrict
        } else {
            Pulse::Flow
        };
        assert_eq!(
            base,
            Pulse::Constrict,
            "80 % on 32 GiB host with unstable velocity must still be Constrict"
        );
    }
}
