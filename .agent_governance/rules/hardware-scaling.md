---
# Rule: Hardware-Aware Scaling — Concurrency Tiers

`detect_optimal_concurrency()` in `crates/common/src/physarum.rs` maps
installed RAM to a safe parallel-worker count. This is the authoritative
source for all rayon pool and work-queue sizing decisions.

## Tier table

| Total RAM    | Workers              | Rationale                             |
|-------------|---------------------|---------------------------------------|
| < 8 GiB     | 2                   | Safety floor; 2× 250 MB peak = 500 MB |
| 8–16 GiB    | 4                   | Standard; leaves headroom for OS      |
| 16–32 GiB   | 8                   | High-velocity; Physarum backstop active |
| > 32 GiB    | logical CPU count   | Aggressive; SMA gate is primary guard  |
| unavailable | 2                   | Fallback when `sysinfo` cannot report  |

Each `janitor bounce` peaks at roughly 100–250 MB of RSS (tree-sitter grammars
+ clone index). The tiers are calibrated so that even worst-case peak usage
stays well under 50% of installed RAM at the maximum tier.

## Hard constraints

1. **Never hardcode a thread-pool size.** Always call
   `detect_optimal_concurrency()` or accept a `--concurrency` CLI override
   (value `0` triggers auto-detection).
2. **The `--concurrency` override MUST still be bounded by Pulse.**
   A user-supplied value does not bypass the Physarum `Stop` gate.
3. **2 is the minimum worker count**, even on constrained hardware.
   Single-threaded execution hides data-race bugs and is not supported.

## Enforcement checklist

- [ ] New parallelism-introducing code calls `detect_optimal_concurrency()`
  or respects a CLI-supplied `--concurrency` flag.
- [ ] `gauntlet-runner` and `parallel-bounce` use the same tier table —
  do not introduce a second, ad-hoc sizing formula.
- [ ] Any change to the tier table must include a comment citing the RSS
  measurement that justifies the new threshold.
