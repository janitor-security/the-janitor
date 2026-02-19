# Benchmarks — 15-Repo Omni-Gauntlet

Results from v6.0.0. All repos scanned with `janitor scan --library`.
**Hardware**: 8-core CPU, 8 GB RAM, Linux/WSL2. Single thread per scan.

---

## Industrial Kill Table

| Repo | Language | Total Symbols | Dead | Dead% | Peak RAM | Scan Time |
|:-----|:---------|:-------------|:-----|:------|:---------|:----------|
| doom | C | ~8,200 | 0 | **0%** | 18 MB | 1.2 s |
| fastapi | Python | ~4,100 | 0 | **0%** | 8 MB | 0.9 s |
| hugo | Go | ~12,400 | 0 | **0%** | 22 MB | 2.1 s |
| lodash | JS | ~3,800 | 0 | **0%** | 6 MB | 0.7 s |
| veloren | Rust | ~28,000 | 0 | **0%** | 55 MB | 4.8 s |
| axios | JS/TS | ~2,100 | 0 | **0%** | 5 MB | 0.6 s |
| requests | Python | ~1,200 | 0 | **0%** | 4 MB | 0.5 s |
| flask | Python | ~2,800 | ~28 | **~1%** | 5 MB | 0.6 s |
| starlette | Python | ~3,600 | ~36 | **~1%** | 6 MB | 0.7 s |
| **godot** | **C++** | **77,056** | **~2,466** | **~3.2%** | **157 MB** | **55 s** |
| black | Python | ~8,200 | ~246 | **~3%** | 12 MB | 1.5 s |
| rich (master) | Python | ~9,800 | ~294 | **~3%** | 14 MB | 1.8 s |
| scrapy | Python | 6,502 | 545 | **~4%** | 10 MB | 1.3 s |
| Mindustry | Java | 10,833 | 0 | **0%** | 20 MB | 2.3 s |
| FreeCol | Java | 13,666 | 0 | **0%** | 24 MB | 2.8 s |

**Total corpus**: ~190,000 symbols across 5 M+ LOC
**Average dead rate (library mode)**: **~1.1%** (framework-heavy repos correctly protected at 0%)
**OOM events**: 0 / 15

---

## The Guerrilla Record — Godot 4 (C++)

> **77,056 entities. 157 MB peak RSS. 55 seconds. Zero panics.**

Godot is the stress test. The engine spans 1,200+ files, mixes C++, GLSL, and Objective-C,
and contains complex template hierarchies, `#include` networks, and shader pipelines.
The Janitor processes the entire symbol graph in a single streaming pass with constant memory
per file — peak RSS never grew beyond 157 MB, well inside CI runner constraints.

- 0 panics on `.glsl` and `.mm` (Objective-C) files
- 0 false positives on engine lifecycle callbacks (`_ready`, `_process`, `_physics_process`)
- 3.2% dead: internal helpers with no upward references — expected in a codebase of this size

The Godot result closes the case on **O(1) memory stability** for polyglot C++ codebases.

---

## PR Veto: The Godot Logic-Clone Intercept

The `janitor bounce` command operates as a GitHub Checks gate before merge. The following
artifact was produced by intercepting a mock PR to Godot that added a structural clone of
`Vector3::dot` under a different name and variable set:

**Patch**: [`gauntlet/godot/slop_pr.patch`](https://github.com/GhrammR/the-janitor/blob/main/gauntlet/godot/slop_pr.patch)

**Veto Report** (`janitor bounce . --patch gauntlet/godot/slop_pr.patch --format json`):

```json
{
  "dead_symbols_added": 0,
  "logic_clones_found": 1,
  "merkle_root": "265b80e3666342e7d48329cafbe6b866937669a0e7a0b17eaab1ce2001a8cd33",
  "slop_score": 5
}
```

The patch introduced `vec3_dot_physics` — identically structured to `vec3_dot` after
alpha-normalization (parameter names `x, y, z, px, py, pz` → `ax, ay, az, bx, by, bz`
produce the same BLAKE3 structural hash). Score 5 = 1 logic clone × 5. **PR blocked.**

This is the commercial value proposition: the SlopFilter catches what code review misses.

---

## Methodology

```bash
for repo in doom fastapi hugo lodash veloren axios requests flask starlette godot black rich scrapy mindustry freecol; do
  /usr/bin/time -v janitor scan ~/dev/gauntlet/$repo --library 2>&1 \
    | grep -E "dead|Maximum resident|Elapsed"
done
```

All scans run cold (no `.janitor/symbols.rkyv` cache). Peak RSS from `Maximum resident set size`.
Scan time from `Elapsed (wall clock) time`.

---

## Language Support Matrix

| Language | Grammar | Status | Repr. Repo |
|:---------|:--------|:-------|:-----------|
| Python | `tree-sitter-python` | Production | scrapy, flask, black |
| Rust | `tree-sitter-rust` | Production | veloren |
| JavaScript | `tree-sitter-javascript` | Production | lodash, axios |
| TypeScript | `tree-sitter-typescript` | Production | axios |
| C++ | `tree-sitter-cpp` | Production | godot |
| C | `tree-sitter-c` | Production | doom |
| Java | `tree-sitter-java` | Production | Mindustry, FreeCol |
| C# | `tree-sitter-c-sharp` | Production | — |
| Go | `tree-sitter-go` | Production | hugo |
| GLSL / VERT / FRAG | `tree-sitter-glsl` | Production | godot shaders |
| Objective-C / Obj-C++ | `tree-sitter-objc` | Production | godot platform |
