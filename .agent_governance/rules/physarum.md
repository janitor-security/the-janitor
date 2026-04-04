---
# Rule: The Melanin Layer — Physarum Runtime Invariants

The Physarum subsystem (`crates/common/src/physarum.rs`) is the daemon's
biological backpressure engine. It governs concurrency and work admission
based on real-time OS memory pressure.

## Architecture

- **`SystemHeart`** — polls `sysinfo` at ≥100 ms intervals; maintains a
  16-slot ring buffer (3-second SMA window).
- **`Pulse`** — the three-state signal read lock-free from `GLOBAL_PULSE`:
  - `Flow` — SMA ≤75% (≤85% on >16 GiB) AND velocity ≤100 MB/s → full concurrency
  - `Constrict` — SMA 75–90% OR velocity >100 MB/s → cap at 2 concurrent tasks
  - `Stop` — SMA >90% → reject admission, caller sleeps 500 ms and retries
- **Background thread**: named `physarum-heart`, 500 ms tick, zero-contention
  publish via atomic cell.

## Hard invariants (never violate)

1. **Never read Pulse under a mutex.** The GLOBAL_PULSE atomic cell is the
   sole read path. Adding a lock defeats the purpose of the design.
2. **Never skip the Pulse check in any hot dispatch loop.** Every
   scan/bounce worker must consult Pulse before acquiring the next work item.
3. **The `beat_swarm` multiplier must not exceed ×1.25.** If the collision
   count is ≥5, apply ×1.25 and hold. Do not increase this ceiling without
   a measured regression justification.
4. **`sysinfo` refresh guard: 100 ms minimum.** Never remove the debounce
   gate — unconstrained `sysinfo` polls have measurable latency on Linux.

## Extension protocol

When adding a new Pulse state or modifying thresholds:
1. Add a deterministic unit test that injects synthetic SMA/velocity values
   and asserts the resulting `Pulse` variant.
2. Update the table in this file to reflect the new thresholds.
3. Run `/self-test` to confirm `SANCTUARY INTACT` — the ghost attack
   simulation exercises the Physarum RAM gate on synthetic concurrency load.

## Cross-reference

- `tools/gauntlet-runner/src/main.rs` uses `detect_optimal_concurrency()`
  to size the rayon thread pool — see `.claude/rules/hardware-scaling.md`.
- `crates/cli/src/daemon.rs` uses `Pulse` to gate `HotRegistry` refresh.
