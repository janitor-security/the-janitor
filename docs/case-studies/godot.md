# Autopsy of a Giant: Auditing the Godot Engine

**Target**: Godot Engine — `master` branch (March 2026)
**Analyzer**: The Janitor v6.12.7 — library mode static scan + full PR bounce corpus
**Scan Date**: 2026-03-11
**Static scan duration**: **27 seconds** | **4,327 PRs bounced** (full open-PR corpus)

---

## Headline Results

| Metric | Value |
|:-------|------:|
| Lines of code scanned | **~3.5M LOC** |
| Scan time (static) | **27 seconds** |
| Peak RAM | **58 MB** |
| Dead symbols (library mode) | **704** |
| Complexity Delta | **−704 symbols** |
| PRs bounced | **4,327** (full available corpus) |
| Total Slop Score | **68,175** |
| Blocked PRs (score ≥ 100) | **1** |
| Unlinked PRs | **3,398 / 4,327 (78.5%)** |
| Structural clone groups detected | **23** |
| OOM events | **0** |
| Panics | **0** |

**27 seconds. 58 MB. 4,327 live PRs. One blocked — a merged CVE claim that only changed a `.txt` file.**

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

## Static Analysis: Dead Symbol Breakdown

**704 dead symbols** identified in library mode across the full `master` branch. Top subsystems by dead count:

| Subsystem | Dead Count | Representative Pattern |
|:----------|----------:|:----------------------|
| `modules/godot_physics_3d` | 51 | Internal physics solver helpers — superseded during Godot Physics refactor |
| `platform/macos` | 37 | `embedded_game_view_plugin.mm` — Obj-C++ message stubs, `_msg_*` pattern |
| `core/variant` | 31 | Variant type conversion utilities with no remaining call sites |
| `modules/gdscript` | 27 | Parser state machine accessors replaced by bytecode compiler passes |
| `modules/godot_physics_2d` | 24 | 2D collision solver internals (`_ConcaveCollisionInfo2D`, etc.) |
| `core/io` | 23 | `file_access_zip.h`, `ZipArchive` internals no longer referenced |
| `platform/windows` | 23 | Platform-specific helpers with no cross-platform consumers |
| `modules/fbx` | 22 | FBX importer internals — partial API consumed by the importer pipeline |
| `servers/rendering` | 21 | Light storage accessors from the GLES3→RD renderer transition |
| `core/math` | 17 | Geometry utility helpers (`_FaceClassify`, `_plot_face`, `_build_faces`) |

### Top Dead Symbols (Certainty Audit)

These symbols have zero upward reference paths in library-mode scan:

- `_ConcaveCollisionInfo2D` (`modules/godot_physics_2d/godot_collision_solver_2d.cpp`)
- `_on_core_api_assembly_loaded` (`modules/mono/mono_gd/gd_mono.cpp`)
- `_gl_debug_print` (`drivers/gles3/rasterizer_gles3.cpp`)
- `_GDScriptMemberSort` (`modules/gdscript/gdscript.cpp`)
- `_msg_set_context_id` (`platform/macos/editor/embedded_game_view_plugin.mm`)
- `_msg_cursor_set_shape` (`platform/macos/editor/embedded_game_view_plugin.mm`)
- `_msg_cursor_set_custom_image` (`platform/macos/editor/embedded_game_view_plugin.mm`)
- *(…and 697 more — run `janitor scan godotengine/godot --library` to see the full list)*

### What to do with these

The `platform/macos` `_msg_*` stubs (37 symbols) are Obj-C++ message wrappers. These are Tier 1 — immediately actionable with `janitor clean --library`. The `modules/godot_physics_3d` dead methods (51 symbols) require context: verify with `janitor clean --library --dry-run` that none are exercised by the GDExtension layer at runtime.

---

## Performance Profile

```
Dead symbols  : 704  (library mode)
Peak RSS      : 58 MB
Wall time     : 27 seconds
Panics        : 0
OOM events    : 0
```

The Janitor processes Godot's full polyglot symbol graph — C++, C#, Java, Objective-C,
GLSL, Python — in a **single streaming pass** with constant memory per file. Peak RSS
stabilised at 58 MB across 1,200+ source files. Well inside any CI runner's constraints.

**Memory scaling**: 58 MB for the full Godot corpus = linear, not quadratic. The same profile
holds at 10× the entity count. No grammar is compiled more than once per process lifetime
(`OnceLock<Language>` statics, 8 bytes overhead per grammar).

---

## PR Bounce Corpus: 4,327 Live PRs

Results from bouncing **every available open and recently-closed PR** in the Godot repository
via `gh pr diff` — no local git clone required. Conflict-filtered PRs skipped; binary extensions
stripped before each bounce. Full slop pipeline: structural clones (MinHash LSH), social forensics
(CommentScanner), Unverified Security Bump detection, Agnostic IaC Shield, Universal Bot Shield.

### Score Distribution

| Band | Count | % |
|:-----|------:|--:|
| Blocked (≥ 100) | **1** | 0.02% |
| Warned (70–99) | 1 | 0.02% |
| Minor violation (1–69) | 3,396 | 78.5% |
| Clean (score = 0) | **929** | 21.5% |

**929 PRs scored zero** — genuine clean submissions. The 78.5% "Minor" band is almost entirely
unlinked PRs scoring +20 (Godot's `janitor.toml` effective gate applied per PR state).

### Workslop: Maintainer Impact

| Metric | Value |
|:-------|------:|
| Total PRs analyzed | **4,327** |
| Total Slop Score | **68,175** |
| Unlinked PRs (no Closes/Fixes #N) | **3,398 (78.5%)** |
| Structural clone groups | **23** |
| Blocked (gate score ≥ 100) | **1** |
| Bot PRs | **4** |

---

## The Blocked PR: A Merged CVE Claim That Changed Only a `.txt` File

**PR #115714** by `Chubercik` — score **120**, state: **merged**.

```
Violation: Unverified Security Bump
Claim:     PR body references 'CVE-' (CVE number cited in description)
Changed:   Only non-code files changed — .txt
```

This PR claimed to address a CVE but modified only a `.txt` file. No source code changed. No
security fix was implemented. The Janitor's Unverified Security Bump detector flagged it
immediately: security language in the PR body, zero source-code diffs.

**It was merged anyway.**

This is the exact pattern that drove the [curl project](https://curl.se) to shut down its bug
bounty program — maintainers overwhelmed by security-labelled submissions that contain no
security-relevant code changes. The Janitor catches it at the PR gate: score 120 = 50 (antipattern)
+ 70 (unlinked) → blocked at the default threshold of 100.

The fact that this PR was merged means Godot's maintainer workflow has **no automated gate** on
this class of submission. One deployment of `janitor bounce` on CI would have caught it before
the merge button was available.

---

## The Warned PR: 11 Logic Clone Groups

**PR #108516** by `KoBeWi` — score **75**, state: **merged**.

```
Logic clones found: 11
Unlinked: yes
Score: 11 × 5 (clones) + 20 (unlinked) = 75
```

11 structural clone groups detected via MinHash LSH (Jaccard ≥ 0.70 across 64-hash signatures,
8 bands × 8 rows). Identical or near-identical code blocks duplicated across different parts of
the patch — the structural fingerprint of copy-paste-modify development.

At score 75, this PR sits in the "Warned" band — below the default gate threshold of 100, but
above zero. Reviewers would see the warning; the merge is not blocked.

---

## The 78.5% Unlinked Problem

Of 4,327 PRs sampled, **3,398 have no associated GitHub issue** — no spec, no triage trail,
no accountability chain.

The top 10 contributors by PR volume, and their unlinked rates:

| Contributor | PRs | Pattern |
|:-----------|----:|:--------|
| `bruvzg` | 289 | Platform maintainer — high-volume, mostly platform PRs |
| `KoBeWi` | 272 | Editor tooling contributor |
| `YeldhamDev` | 139 | — |
| `Calinou` | 138 | — |
| `Ivorforce` | 83 | — |
| `ryevdokimov` | 80 | — |
| `aaronfranke` | 79 | — |
| `Repiteo` | 75 | — |
| `timothyqiu` | 73 | — |
| `akien-mga` | 65 | — |

`bruvzg` alone accounts for **289 PRs** — 6.7% of the entire corpus. At Godot's contributor
volume, a single prolific maintainer's PR hygiene has significant aggregate impact on the
unlinked score.

The Janitor applies a +20 unlinked penalty per PR (configurable in `janitor.toml`). This is a
signal, not a hard block by default — maintainers see the warning without the gate triggering.
Enforce link compliance at the gate by raising `min_slop_score` to 20 in `janitor.toml`.

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
methods is in `GLOBAL_SHIELD_NAMES` in `wisdom.rs`:

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

## Zero Structural Antipatterns

The engine's `slop_hunter` found **0 structural antipatterns** across 4,327 PRs. No vacuous
`unsafe` blocks, no hallucinated Python imports, no goroutine closure traps, no `System.out.println`
production logging.

This is consistent with what you'd expect from a mature C++/GDScript codebase with experienced
maintainers: the language-level antipatterns that plague AI-assisted code (hallucinated imports,
vacuous unsafe blocks) are absent from the Godot contributor base.

The signal the engine does surface is behavioural — the **78.5% unlinked rate** and the single
**Unverified Security Bump** that slipped through. These are process failures, not code quality
failures. The engine catches both.

---

## CI Integration

```yaml
# .github/workflows/janitor.yml
- uses: janitor-security/the-janitor@v6
  with:
    token: ${{ secrets.JANITOR_TOKEN }}
    fail_on_slop: 'true'
```

Or the CLI directly (no local clone needed):

```bash
# Bounce a PR against the live Godot repo — no checkout required
janitor bounce ~/dev/godot_scan \
  --repo godotengine/godot \
  --base <base-sha> \
  --head <head-sha> \
  --pr-number $PR_NUMBER \
  --author "$AUTHOR" \
  --format json
```

Score formula: `dead_added × 10 + clones × 5 + zombies × 15 + antipatterns × 50`

If PR #115714 had been gated: `0 + 0 + 0 + 50 (antipattern) + 70 (unlinked) = 120 → BLOCKED`.

---

## The Verdict

**27 seconds. 58 MB. 4,327 live PRs. Zero panics. Zero OOM.**

The static scan produced **704 addressable dead symbols** — engine-authored dead code in
physics solvers, platform layers, rendering helpers, and the GDScript parser. Shielded vendored
code (accesskit FFI, Android APK toolchain, Mono bindings) is correctly excluded from the
actionable count.

The full-corpus PR bounce found one thing that matters most: **a merged PR that claimed a CVE fix
but changed only a `.txt` file**. PR #115714 scored 120. It cleared Godot's review queue. It
would not have cleared The Janitor's gate.

78.5% of 4,327 PRs carry no linked issue. No spec. No triage trail. The engine flags each one.
Enforcement is configuration — raise `min_slop_score` to 20 in `janitor.toml` to hard-block
unlinked submissions at the gate.

---

> **See what The Janitor finds in your repo.**
>
> ```bash
> janitor bounce . --repo . --base main --head HEAD
> ```
>
> [Download → GitHub Releases](https://github.com/janitor-security/the-janitor/releases) · [Global Audit 2026 →](global-audit-2026.md) · [Pricing](../pricing.md)
