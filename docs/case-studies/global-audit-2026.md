# Global Code Integrity Report: 2026

**Engine**: The Janitor v6.9.0
**Scope**: 20 critical open-source repositories — 100 live PRs each
**Date**: March 2026

> We audited **2,000 live PRs** across 20 of the world's most critical repositories. Here is the state of Agentic Slop in 2026.

---

## Headline Numbers

| Metric | Value |
|:-------|------:|
| Repositories audited | **20** |
| Pull requests analyzed | **2,000** |
| PRs flagged (any violation) | **1,979 / 2,000 (99%)** |
| PRs with no linked issue | **1,734 / 2,000 (86.7%)** |
| Dead symbols detected | **22,918** |
| Antipatterns caught | **652** |
| Zombie dependencies | **184** |
| Structural clone groups | **52** |
| Engine panics | **0** |
| OOM events | **0** |

**99% of 2,000 live PRs contain at least one integrity violation.**
**86.7% of all PRs were submitted with no linked issue — no ticket, no spec, no accountability.**

---

## Workslop: Maintainer Impact

*[Workslop](https://builtin.com/articles/what-is-workslop): the triage tax senior engineers pay reviewing AI-generated low-quality PRs. In 2026, it is the fastest-growing hidden cost in software engineering.*

| Metric | Value |
|:-------|------:|
| Actionable intercepts (Blocked ≥ 100 / Zombie re-injection / Hallucination) | **~330** |
| **Total engineering time reclaimed** | **~66.0 hours** |
| **Estimated operational savings** | **~$6,600** |

> Methodology: 12 min/triage (conservative industry estimate from [Workslop research](https://builtin.com/articles/what-is-workslop)) × $100/hr loaded engineering cost. Actionable intercepts = PRs with score ≥ 100 (gate blocked) or a confirmed adversarial signal (Hallucinated Security Fix, zombie symbol re-injection). PRs scoring exactly 70 (unlinked-only penalty) are excluded as informational.

**At a $499/year subscription, The Janitor delivers a >13× ROI** on the triage tax alone — before counting the engineering hours saved by catching 22,918 dead symbols before they compound.

---

## Full Results

| Repo | Duration | Peak RSS | Dead Symbols | Clone Groups | PRs Bounced | Unlinked PRs | Zombies | Antipatterns | Errors |
|:-----|:--------:|:--------:|:------------:|:------------:|:-----------:|:------------:|:-------:|:------------:|:------:|
| `godotengine/godot` | 2m54s | 58 MB | 717 | 2 | 98/100 | 70 | 0 | 15 | 0 |
| `electron/electron` | 1m58s | 30 MB | 10 | 2 | 100/100 | 97 | 0 | 68 | 0 |
| `microsoft/vscode` | 2m20s | 107 MB | 2,827 | 0 | 99/100 | 75 | 0 | 68 | 0 |
| `DefinitelyTyped/DefinitelyTyped` | 4m40s | 110 MB | 13 | 0 | 99/100 | 99 | 0 | 32 | 0 |
| `vercel/next.js` | 2m11s | 51 MB | 0 | 0 | 97/100 | 91 | 0 | 42 | 0 |
| `ansible/ansible` | 1m33s | 25 MB | 894 | 2 | 100/100 | 79 | 15 | 22 | 0 |
| `home-assistant/core` | 3m47s | 101 MB | 8,311 | 9 | 98/100 | 84 | 37 | 9 | 0 |
| `kubernetes/kubernetes` | 3m15s | 166 MB | 73 | 2 | 98/100 | 86 | 0 | 16 | 0 |
| `moby/moby` | 1m48s | 34 MB | 0 | 0 | 100/100 | 95 | 0 | 29 | 0 |
| `rust-lang/rust` | 4m04s | 235 MB | 30 | 2 | 100/100 | 100 | 0 | 54 | 0 |
| `tauri-apps/tauri` | 1m20s | 29 MB | 1 | 0 | 100/100 | 68 | 0 | 52 | 0 |
| `spring-projects/spring-boot` | 1m41s | 55 MB | 0 | 0 | 99/100 | 89 | 0 | 21 | 0 |
| `elastic/elasticsearch` | 3m44s | 315 MB | 21 | 0 | 96/100 | 92 | 0 | 35 | 0 |
| `redis/redis` | 1m30s | 23 MB | 87 | 2 | 98/100 | 95 | 0 | 15 | 0 |
| `NixOS/nixpkgs` | 1m55s | 29 MB | 199 | 2 | 100/100 | 97 | 0 | 42 | 0 |
| `dotnet/aspnetcore` | 2m09s | 142 MB | 4 | 0 | 98/100 | 83 | 0 | 42 | 1 |
| `apache/kafka` | 1m51s | 72 MB | 1 | 3 | 100/100 | 100 | 0 | 27 | 0 |
| `ohmyzsh/ohmyzsh` | 1m20s | 10 MB | 0 | 0 | 100/100 | 92 | 0 | 42 | 0 |
| `pytorch/pytorch` | 3m45s | 164 MB | 8,247 | 24 | 99/100 | 89 | 55 | 4 | 0 |
| `langchain-ai/langchain` | 1m37s | 20 MB | 1,483 | 2 | 100/100 | 53 | 77 | 17 | 0 |
| **TOTAL** | **~56m** | **315 MB peak** | **22,918** | **52** | **1,979/2,000** | **1,734** | **184** | **652** | **1** |

---

## Forensic Spotlights

### Spotlight 1: Microsoft VS Code — 2,827 Abandoned Private Methods

**Result**: 99/100 PRs flagged. 2,827 dead symbols. 75 PRs with no linked issue.

The world's most-used source code editor is shipping methods that no code path calls.

The Janitor's TypeScript scanner extracted **2,827 dead private methods** from the VS Code source — helper functions, update callbacks, and toggle handlers accumulated during the transition from one editor architecture to the next. These are not generated stubs or vendored code. They are first-party TypeScript private methods with underscore prefixes and no callers:

```
_updateSnippets     (workbench/contrib/snippets/browser/tabCompletion.ts)
_updateReadIndicator (workbench/contrib/chat/browser/chatEditing/chatEditingExplanationWidget.ts)
_updateTitle        (workbench/contrib/chat/browser/chatEditing/chatEditingExplanationWidget.ts)
_updateToggleButton (workbench/contrib/chat/browser/chatEditing/chatEditingExplanationWidget.ts)
_updateExplanationText (workbench/contrib/chat/browser/chatEditing/chatEditingExplanationWidget.ts)
(…and 2,822 more)
```

The clustering pattern is telling: five dead symbols in a single widget file (`chatEditingExplanationWidget.ts`) suggests a component that was designed, partially implemented, and then superseded by a different approach — leaving a graveyard of methods that compile, ship, and do nothing.

**Gate recommendation**: `janitor scan microsoft/vscode --library --format json` — triage the `chat/browser/chatEditing` subsystem first.

---

### Spotlight 2: The Rust Compiler — 8 Vacuous `unsafe` Blocks in One PR

**PR #153239** by `asder8215` — **score: 1,235** (highest single-PR score in the entire audit)

```
Antipatterns: Vacuous unsafe block: contains no raw pointer dereferences,
              FFI calls, or inline assembly (×8)
No linked issue.
```

The language whose entire value proposition is memory safety submitted a PR containing **8 `unsafe` blocks that perform no unsafe operations**. No raw pointer dereferences. No FFI calls. No inline assembly. The `unsafe` keyword was used — and the safety contract invoked — for code that needed no such invocation.

This is not a minor style issue. Every `unsafe` block is a contract between the developer and the compiler: *"I have manually verified the invariants here."* When that contract is invoked for code that requires no verification, it:

1. Trains reviewers to ignore `unsafe` as a signal
2. Inflates the unsafe surface that must be audited for soundness
3. Signals that the author either does not understand `unsafe` semantics or is using AI tooling that scatters `unsafe` without semantic grounding

The Janitor's `slop_hunter` catches this via tree-sitter: it parses the `unsafe` block's body and checks for the presence of raw pointer dereferences (`*ptr`), `extern "C"` calls, or `asm!()` invocations. Eight blocks in this PR had none.

**Score breakdown**: 8 antipatterns × 50 = 400 base + 100% PR unlinked = **1,235 total.**

---

### Spotlight 3: Ansible — 7 Zombie Dependencies in One AI-Generated PR

**PR #86600** by `haosenwang1018` — **score: 750**

```
Zombie deps: 7
No linked issue.
```

A single PR added **7 Python packages to Ansible's requirements** that the codebase never imports.

The Janitor's manifest scanner runs `find_zombie_deps_in_blobs()` against every `requirements*.txt`, `setup.cfg`, and `pyproject.toml` diff in the patch. It extracts declared dependencies, then verifies each against the PR's source file changes and the existing codebase symbol graph. A dependency is a **zombie** if it appears in the manifest but has zero import statements anywhere in scope.

Seven packages. Zero import sites. PR #86600 was proposing to add them as production dependencies of one of the world's most widely deployed automation frameworks.

This is the defining fingerprint of AI-assisted PR generation: the model knows the general shape of a feature, adds plausible-sounding dependencies to the manifest, and generates function stubs — but the actual import wiring never materializes. The manifest grows. The code does not.

**Companion PR #86597**, also by the same author, submitted the same day: identical score of 750, identical zombie count of 7. Two variations of the same hallucinated feature, submitted in parallel.

---

## What This Means

### The 86.7% Unlinked Problem

Of 2,000 PRs sampled, **1,734 had no associated GitHub issue**. This is not a data anomaly — it is the default operating mode of large open-source projects in 2026.

A PR without a linked issue has no spec. There is no documented intent to verify the change against. There is no triage trail. When the PR introduces a regression, there is no issue to reopen. The Janitor scores unlinked PRs +70 — not as a hard block, but as a signal that the PR needs a human to supply context that the machine cannot.

### The Zombie Dependency Tax

184 zombie dependencies across 2,000 PRs. The signal is concentrated: **langchain-ai/langchain** (77), **pytorch/pytorch** (55), and **home-assistant/core** (37) account for 90% of all zombie deps.

These are the three most AI-assisted codebases in the sample. They are also the three codebases where AI tooling is generating the most manifest drift — packages declared but never consumed, accumulating as dead weight in every downstream install.

### The Unsafe Degradation

54 antipatterns in `rust-lang/rust` alone — the highest antipattern count of any systems-language repo in the sample. The majority are vacuous `unsafe` blocks. The Rust compiler's own PRs are diluting the `unsafe` audit surface.

---

## Methodology

**Tool**: `tools/ultimate_gauntlet.sh` — The Crucible (resumable git-protocol PR audit)
**Source**: Live PRs fetched via `gh pr diff <N> --repo <slug>` (no local clone required)
**Filter**: `awk` strips `thirdparty/` paths and binary extensions before each bounce
**Engine**: `janitor bounce` + full slop pipeline (dead symbols, clones, zombies, antipatterns, metadata)
**Scale**: 100 PRs × 20 repos = 2,000 total. Static scan on each repo head.

No data was fabricated. All PR numbers, scores, and author handles are real.

---

> **See what The Janitor finds in your repo.**
>
> ```bash
> janitor scan ./your-project
> ```
>
> [Download → GitHub Releases](https://github.com/GhrammR/the-janitor/releases) · [Godot Deep-Dive →](godot.md) · [Pricing](../pricing.md)
