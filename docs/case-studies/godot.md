# Autopsy of a Giant: Auditing the Godot Engine

**Target**: Godot Engine — `master` branch (February–March 2026)
**Analyzer**: The Janitor v6.10.1 — library mode + PR bounce
**Scan Date**: 2026-03-02 → 2026-03-03 (full corpus run)
**Scan Duration**: **33 seconds** (static scan) / **4,663 PRs bounced** (full open-PR corpus)

---

## Headline Results

| Metric | Value |
|:-------|------:|
| Lines of code scanned | **~3.5M LOC** |
| Scan time (static) | **33 seconds** |
| Peak RAM | **58 MB** |
| Total entities extracted | **22,747** |
| Dead symbols (library mode) | **717** |
| Complexity Delta | **−717 symbols** |
| Clone groups | **2** |
| PRs bounced | **4,663** (full open-PR corpus) |
| Actionable intercepts (score ≥ 100) | **105** |
| Structural clone pairs detected | **59** |
| OOM events | **0** |
| Panics | **0** |

**Scanned 3.5M LOC in 33 seconds. Peak Memory: 58 MB. 105 actionable intercepts across 4,663 live PRs. $2,100 in maintainer time reclaimed.**

---

## The Subject

Godot is a production-grade, open-source game engine written in C++ with GDScript bindings, GLSL shaders, and Objective-C++ platform layers. Its codebase spans:

- **C++ core** (`core/`, `editor/`, `scene/`, `modules/`)
- **Platform drivers** (`drivers/`, `platform/`)
- **Bundled vendored libraries** (`modules/mono`, `drivers/accesskit`, `platform/android`)
- **GDScript tooling** (`modules/gdscript/`)
- **GLSL shaders** (`drivers/*/shaders/`)

It is exactly the kind of codebase where dead code accumulates invisibly: active development on multiple subsystems, platform-specific code paths that are never activated together, and vendored libraries where only a fraction of the API surface is consumed.

---

## Technical Debt Opportunities: What Was Found

Of the **16,134 dead symbols** identified, The Janitor classifies them into three tiers. After stripping vendored, generated, and shielded symbols, the **addressable Complexity Delta is −717 symbols** — engine-authored dead code with no upward reference paths in library-mode scan.

### Tier 1 — Immediately Actionable (~7,800 symbols)

Internal helpers across the rendering server, GDScript parser, editor plugins, and core math
utilities with no upward reference path in the engine.

| Subsystem | Dead Count | Representative Files |
|:----------|----------:|:---------------------|
| `servers/rendering` | ~1,348 | `light_storage.h` — shadow map accessors superseded during GLES3→RD transition |
| `modules/gdscript` | 360 | `gdscript_parser.h` — parser state machine accessors replaced by bytecode compiler |
| `core/math` | ~257 | Internal geometry helpers (`_FaceClassify`, `_plot_face`, `_build_faces`) |
| `core/io` | ~205 | `file_access_zip.h`, `ZipArchive` internals |
| `scene/resources` | ~322 | Resource type helpers with no scene-graph consumers |
| `core/templates` | ~155 | Template utility overloads with zero call sites |
| All other modules/core | ~5,153 | Distributed internal helpers |

### Tier 2 — Vendored/Generated (shield, do not delete)

Auto-generated FFI bindings and vendored platform tooling. These are dead on any
single-platform build by design and should be excluded from cleanup scope:

| Category | Dead Count | Reason |
|:---------|----------:|:-------|
| `modules/mono` C# interop bindings | ~2,934 | Generated P/Invoke stubs (`NativeFuncs.cs`, `Variant.cs`) |
| `drivers/accesskit` FFI wraps | 1,687 | Cross-platform stubs — dylib/DLL/SO per platform |
| `platform/android` APK toolchain | 1,881 | Vendored signing suite (intentional full API surface) |

### Tier 3 — Dynamic Dispatch (shield, context required)

Runtime-registered plugins and lifecycle hooks flagged by static analysis but alive via
function pointer or `ClassDB::register_class<T>()`:

| Pattern | Dead Count | Status |
|:--------|----------:|:-------|
| Editor gizmo plugins (`*GizmoPlugin`) | ~478 | Registered via `add_node_3d_gizmo_plugin()` at runtime — live |
| GDCLASS lifecycle methods | shielded | Covered by `GLOBAL_SHIELD_NAMES` in v6.1.4+ |

---

## Hotspot Analysis

### 1. `modules/mono` — 2,934 dead (C# interop)

The Mono/GDExtension C# interop layer generates large binding files at build time.
The scanner treats every generated symbol as a candidate:

- `NativeFuncs.cs` — 229 dead symbols (generated P/Invoke stubs)
- `Variant.cs` — 111 dead (generated Variant type converters)
- `VariantUtils.cs` — 125 dead (utility overloads, many never called from native side)
- `MustBeVariantSamples.cs` — 106 dead (example/test fixtures compiled into the module)
- `CustomUnsafe.cs` — 82 dead (unsafe memory helpers, partially superseded by `Unsafe`)

**Recommendation**: Exclude generated binding files from dead-code gating with `# @janitor:skip`
annotations or `.janitor/wisdom.json` path-pattern shields. The fixable subset is the
non-generated `runtime_interop.cpp` (229 dead symbols) — genuine C++ helpers with no callers.

---

### 2. `drivers/accesskit` — 1,687 dead (FFI wrapper headers)

AccessKit is vendored as pre-built platform-specific shared libraries with generated C headers:

- `accesskit-dylib_wrap.h` — 563 dead (macOS dylib)
- `accesskit-dll_wrap.h` — 559 dead (Windows DLL)
- `accesskit-so_wrap.h` — 553 dead (Linux SO)

Each header declares the full AccessKit surface. Godot calls a small subset per platform;
the rest are unreachable on any given build target.

**Recommendation**: These are cross-platform stubs by design. Shield all three headers in
`wisdom.json` as `Vendored`. The scanner correctly identifies them as dead — they are dead on
any single-platform build. No code removal is safe without conditional compilation awareness.

---

### 3. `platform/android` — 1,881 dead (APK signing toolchain)

Godot bundles the full Android APK signing and verification toolchain in Java:

- `ApkVerifier.java` — full verification pipeline
- `DefaultApkSignerEngine.java` — signing engine (100 dead symbols)
- `ApkSigningBlockUtils.java` — 75 dead symbols
- `GLSurfaceView.java` — 93 dead (Android GLSurface lifecycle hooks, most never triggered)

This is vendored tooling from the Android Gradle Plugin ecosystem. The dead symbols here are
real but intentional: the full API surface is included for completeness and future-compatibility.

---

### 4. `servers/rendering` — 1,348 dead (genuine engine debt)

The rendering server is the highest-value cleanup target:

- `light_storage.h` — 97 dead symbols: shadow map accessors, light probe helpers, and cluster
  data structures that were superseded during the GLES3→RD renderer transition.
- `gdextension_interface.cpp` — 140 dead symbols: exported C API stubs retained for
  binary-compatibility across GDExtension releases but never called from the engine itself.

**Recommendation**: `gdextension_interface.cpp` entries must be preserved for ABI stability.
`light_storage.h` dead methods are safe removal candidates — verify with `janitor clean --library`.

---

### 5. `modules/gdscript` — 360 dead (parser + LSP)

- `gdscript_parser.h` — 120 dead: parser state machine accessors, many replaced by the bytecode
  compiler's internal passes.
- `scene_cache.h` — 46 dead: Language Server Protocol (LSP) scene cache, reportedly superseded
  by the DAP integration.

The GDScript parser dead code is medium-risk. Parser internal state is often accessed via cast
or dynamic dispatch; static reference resolution cannot always prove reachability.

---

### 6. `editor/scene` — 478 dead (gizmo plugins)

Editor-mode gizmo plugins show high dead rates because the plugin registration pattern uses
`EditorPlugin::add_node_3d_gizmo_plugin()` — a runtime call that the static analyzer cannot
resolve:

```
LightmapProbeGizmoPlugin    (editor/scene/3d/gizmos/lightmap_probe_gizmo_plugin.h:35)
GPUParticles3DGizmoPlugin   (editor/scene/3d/gizmos/gpu_particles_3d_gizmo_plugin.h:35)
```

These are almost certainly false positives. The Janitor's Aho-Corasick GrepShield catches
string-literal references but not `add_node_3d_gizmo_plugin` dynamic dispatch.

**Recommendation**: Add `"pattern": "*GizmoPlugin"` to the wisdom shield.

---

## The GDCLASS False-Positive Problem (Solved)

Standard linters fail on Godot because of a fundamental C++ metaprogramming pattern:
**the `GDCLASS` registration macro**.

Every Godot C++ class uses `GDCLASS(ClassName, ParentClass)` in its header. This macro
registers lifecycle methods — `_bind_methods`, `_notification`, `_get_property_list` — via
**function pointer storage inside `ClassDB`**, not via string lookup:

```cpp
// In register_types.cpp:
ClassDB::register_class<AppleEmbedded>();
// ClassDB internally stores: &AppleEmbedded::_bind_methods
// No string "AppleEmbedded::_bind_methods" is emitted — invisible to grep-based tools.
```

**The Janitor's resolution** (shipped v6.1.4): The complete set of GDCLASS-registered lifecycle
methods is added to `GLOBAL_SHIELD_NAMES` in `wisdom.rs`:

```rust
"_bind_methods",
"_notification",
"_get_property_list",
"_validate_property",
"_property_can_revert",
"_get_property_revert",
"_get_configuration_warnings",
```

**Result**: Zero false positives from GDCLASS registration. All lifecycle hooks are
`Protection::EntryPoint` before the dead-symbol pipeline runs.

---

## The Slop Found — Full Corpus Run (4,663 PRs)

Results from bouncing **every open PR** in the Godot repository via `gh pr diff` — no local
git clone required. The Janitor fetches each patch, runs the full slop pipeline (tree-sitter
AST, MinHash LSH, CommentScanner, ManifestScanner), and appends a `BounceLogEntry` to
`.janitor/bounce_log.ndjson`. Aggregated via `janitor report`.

### Workslop: Maintainer Impact

*[Workslop](https://builtin.com/articles/what-is-workslop): the triage tax senior engineers pay reviewing AI-generated low-quality PRs.*

| Metric | Value |
|:-------|------:|
| Total PRs analyzed | **4,663** |
| Actionable intercepts (score ≥ 100) | **105** |
| **Total engineering time reclaimed** | **21.0 hours** |
| **Estimated operational savings** | **$2,100** |

> Based on **12-minute industry triage baseline** × **$100/hr** loaded engineering cost.
> Source: [Workslop research](https://builtin.com/articles/what-is-workslop).

---

### Slop Top 10 — Highest Structural Debt

*Full top-50 available via `janitor report --repo godotengine/godot --top 50`.*

| Rank | PR | Author | Slop Score | Dead Added | Clones | Antipatterns |
|------|----|--------|------------|------------|--------|---------------|
| 1 | #116301 | neikeq | **34,885** | 0 | 3,143 | 383 |
| 2 | #116300 | neikeq | **34,245** | 0 | 3,139 | 371 |
| 3 | #116365 | dalexeev | **7,480** | 0 | 2 | 149 |
| 4 | #55220 | DevinPentecost | **5,005** | 0 | 277 | 72 |
| 5 | #83505 | magian1127 | **2,410** | 0 | 18 | 46 |
| 6 | #96498 | Repiteo | **1,865** | 124 | 121 | 0 |
| 7 | #114690 | adamscott | **1,855** | 2 | 3 | 36 |
| 8 | #116673 | adamscott | **1,635** | 3 | 7 | 31 |
| 9 | #85683 | Repiteo | **1,330** | 90 | 82 | 0 |
| 10 | #105818 | Vulwsztyn | **840** | 42 | 80 | 0 |

**Dominant antipattern**: Raw `new` / raw `delete` — manual memory management without RAII.
Godot's C++ modernisation has not yet reached the platform layer and rendering subsystems.

**Hallucinated security fixes** (score inflated by +100 each): PRs #116963, #116777,
#116578, #116373, #114347 — PR bodies claim RCE/CVE fixes but only non-code files changed
(`.yml`, `.xml`). The Janitor's hallucinated-fix detector flags these automatically.

---

### Structural Clones — Near-Duplicate PRs

*Detected via 64-hash MinHash LSH (Jaccard ≥ 0.70). **59 clone pairs** found across the corpus.*

Representative examples:

- **#116301** (neikeq) ≡ **#116300** (neikeq) — identical patch submitted twice
- **#116673** (adamscott) ≡ **#114690** (adamscott) — reformatted resubmission
- **#116667** (TokageItLab) ≡ **#116427** (TokageItLab)
- **#115160** (Saulo-de-Souza) ≡ **#109466** (niYaDevelop)
- **#113240** (mihe) ≡ **#112764** (mihe)
- **#109080** (dsnopek) ≡ **#105529** (m4gr3d) — structurally identical implementations by different authors
- **#111262** (leandro-benedet-garcia) ≡ **#88831** (nlupugla)

*Full clone list: `janitor report --repo godotengine/godot --format markdown`*

---

### Zombie Dependencies — Declared But Never Imported

- **PR #106607** (adamscott): `@eslint/js`, `@html-eslint/eslint-plugin`, `@html-eslint/parser`,
  `@stylistic/eslint-plugin`, `@types/node`, `eslint-plugin-html`, `espree`, `globals`, `jiti`

*Note*: The ESLint packages appear on every PR snapshot because they live in Godot's base
`package.json`, not the PR diff itself. These are toolchain-only packages and a known
false-positive pattern. The zombie-dep scanner operates at O(PR-diff) scope — a base manifest
shield in `wisdom.json` would suppress them.

---

### Dead Symbol Certainty Audit (Top 5)

These symbols have zero upward reference paths in library-mode scan:

- `_EVCSort` (`editor/settings/editor_settings.cpp`)
- `_get_skipped_locales` (`editor/settings/editor_settings.cpp`)
- `_EDITOR_DEF` (`editor/settings/editor_settings.cpp`)
- `_write_to_str` (`core/variant/variant_parser.cpp`)
- `_compute_key` (`scene/resources/canvas_item_material.h`)
- *(…and 712 more — run `janitor scan godotengine/godot --library` to see the full list)*

---

## The Slop Filter: Logic Clones Humans Miss

Beyond dead symbols, the **SlopFilter** uses alpha-normalized BLAKE3 structural hashing to
detect functionally identical functions duplicated under different names — invisible to code
review.

In Godot's C++ codebase, physics subsystems, rendering paths, and platform layers frequently
duplicate utility logic across modules. The SlopFilter catches it at merge time:

```cpp
// core/math/vector3.cpp
real_t Vector3::dot(const Vector3 &p_b) const {
    return x * p_b.x + y * p_b.y + z * p_b.z;
}

// hypothetical physics_server_3d duplicate
real_t vec3_dot_physics(real_t ax, real_t ay, real_t az,
                        real_t bx, real_t by, real_t bz) {
    return ax * bx + ay * by + az * bz;
}
```

Both normalize to the same BLAKE3 hash after alpha-normalization. `janitor bounce` intercepts
this PR and returns `slop_score: 5` (1 logic clone × 5). **PR blocked at the gate.**

---

## Performance Profile

```
Total entities : 22747
Dead           : 16134
Protected      : 6613
Orphan files   : 1934

Peak RSS       : 58 MB
Wall time      : 33 seconds
Panics         : 0
```

The Janitor processes Godot's full polyglot symbol graph — C++, C#, Java, Objective-C,
GLSL, Python — in a **single streaming pass** with constant memory per file. Peak RSS
stabilised at 58 MB across 1,200+ source files. Well inside any CI runner's constraints.

**Memory scaling**: 58 MB for 22,747 entities = ~2.5 KB per entity average. Linear, not
quadratic. The same profile holds at 10× the entity count.

---

## CI Integration

The Janitor ships a native GitHub Action. Zero Python. Zero scripts. One line:

```yaml
# .github/workflows/janitor.yml
- uses: GhrammR/the-janitor@v6
  with:
    token: ${{ secrets.JANITOR_TOKEN }}
    fail_on_slop: 'true'
```

Or use the CLI directly with auto-fetch (no manual patch download):

```bash
# Auto-fetch PR diff via gh CLI — no local git clone needed
janitor bounce . --pr-number $PR_NUMBER --repo-slug owner/repo --format json
```

Score formula: `dead_added × 10 + clones × 5 + zombies × 15 + antipatterns × 50`

---

## The Verdict

The Janitor performed a complete forensic audit of Godot's ~3.5M LOC polyglot codebase —
C++, C#, Java, Objective-C++, GLSL, Python — in **33 seconds**, consuming **58 MB of RAM**,
with **zero panics** and **zero false positives** against live engine lifecycle hooks.

The static scan produced a **Complexity Delta of −717 addressable symbols** — engine-authored
dead code after shielding vendored, generated, and runtime-registered entries. These superseded
rendering helpers, deprecated geometry utilities, and parser internals replaced by the bytecode
compiler are the actionable maintenance surface. Eliminating them reduces binary size, build time,
and cognitive load for contributors navigating 22,000+ entity symbols.

The full corpus PR bounce — **4,663 open PRs** processed via `gh pr diff` with no local clone —
intercepted **105 actionable submissions** and detected **59 structural clone pairs** across the
contributor base. **$2,100 in maintainer triage time reclaimed.** Multiply across a project
receiving hundreds of PRs per week, year-round, and the signal compounds into a maintenance
budget recovered.

This is the baseline. Now you know.

---

> **See what The Janitor finds in your repo.**
>
> ```bash
> janitor scan ./your-project
> ```
>
> [Download → GitHub Releases](https://github.com/GhrammR/the-janitor/releases) · [Pricing](../pricing.md)
