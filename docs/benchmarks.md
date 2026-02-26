# Benchmarks — 15-Repo Omni-Gauntlet

Results from **v6.7.0**. All repos scanned with `janitor scan` (default mode — no `--library` flag).
**Hardware**: AMD64 / WSL2, Linux 6.6.87. Single-threaded scan per repo.

---

## Industrial Kill Table

| Repo | Language | Total Symbols | Dead | Dead% | Peak RAM | Scan Time |
|:-----|:---------|:-------------|:-----|:------|:---------|:----------|
| doom | C | 759 | 757 | **99.7%** | 17 MB | 1.0 s |
| FreeCol | Java | 13,711 | 11,904 | **86.8%** | 27 MB | 3.6 s |
| Mindustry | Java | 10,964 | 8,071 | **73.6%** | 25 MB | 3.2 s |
| veloren | Rust | 12,130 | 8,856 | **73.0%** | 28 MB | 6.8 s |
| hugo | Go | 9,737 | 7,058 | **72.5%** | 33 MB | 3.9 s |
| **godot** | **C++** | **22,747** | **16,195** | **71.2%** | **58 MB** | **33 s** |
| lodash | JS | 1,870 | 1,190 | **63.6%** | 39 MB | 1.1 s |
| black | Python | 2,512 | 473 | **18.8%** | 79 MB | 9.8 s |
| rich | Python | 2,089 | 357 | **17.1%** | 16 MB | 2.0 s |
| starlette | Python | 1,633 | 148 | **9.1%** | 12 MB | 0.9 s |
| scrapy | Python | 6,554 | 578 | **8.8%** | 18 MB | 3.4 s |
| flask | Python | 1,619 | 135 | **8.3%** | 12 MB | 0.6 s |
| requests | Python | 756 | 81 | **10.7%** | 12 MB | 0.4 s |
| fastapi | Python | 5,407 | 99 | **1.8%** | 19 MB | 4.8 s |
| axios | JS/TS | 248 | 11 | **4.4%** | 13 MB | 0.4 s |

**Total corpus**: 92,736 symbols across 15 repos
**Total dead symbols found**: 55,913 (60.3% average)
**OOM events**: 0 / 15

> **Note**: Default scan mode (no `--library`) is used here for maximum signal: all unreferenced
> internal symbols are candidates. Use `--library` when scanning a library you publish as an API —
> it promotes all `pub` symbols to `Protection::LibraryMode`, dropping the dead rate to near-zero
> for framework-heavy repos (fastapi, starlette, flask).

---

## The Godot Record — C++ at Scale

> **22,747 entities. 58 MB peak RSS. 33 seconds. Zero panics.**

Godot is the stress anchor. The engine spans 1,200+ files, mixes C++, GLSL, and Objective-C,
and contains complex template hierarchies, `#include` networks, and shader pipelines.
The Janitor processes the entire symbol graph in a single streaming pass with constant memory
per file — peak RSS stabilised at 58 MB, well inside CI runner constraints.

- 0 panics on `.glsl` and `.mm` (Objective-C) files
- 0 false positives on engine lifecycle callbacks (`_ready`, `_process`, `_physics_process`)
- 71.2% dead in default mode: internal helpers with no upward references
- In `--library` mode (all `pub` symbols protected), the dead rate drops to structural cruft only

The Godot result confirms **O(1) memory stability** for polyglot C++ codebases at production scale.

---

## PR Veto: The Godot Logic-Clone Intercept

The `janitor bounce` command operates as a GitHub Checks gate before merge. The following
artifact was produced by intercepting a mock PR to Godot that added a structural clone of
`Vector3::dot` under a different name and variable set:

**Veto Report** (`janitor bounce . --patch slop_pr.patch --format json`):

```json
{
  "schema_version": "6.5.0",
  "dead_symbols_added": 0,
  "logic_clones_found": 1,
  "zombie_symbols_added": 0,
  "antipatterns_found": 0,
  "merkle_root": "265b80e3666342e7d48329cafbe6b866937669a0e7a0b17eaab1ce2001a8cd33",
  "slop_score": 5
}
```

The patch introduced `vec3_dot_physics` — identically structured to `vec3_dot` after
alpha-normalization. Score 5 = 1 logic clone × 5. **PR blocked.**

---

## Methodology

```bash
# Gauntlet runner (tools/run_gauntlet.sh)
for repo in $GAUNTLET_DIR/*/; do
  /usr/bin/time -v janitor scan "$repo" 2>time.log >scan.log
  # parse Total/Dead from scan.log, RSS/Elapsed from time.log
done
```

All scans run cold (no `.janitor/symbols.rkyv` cache from a prior run). Peak RSS from
`Maximum resident set size (kbytes)` in GNU `time -v` output. Scan time from
`Elapsed (wall clock) time`.

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
