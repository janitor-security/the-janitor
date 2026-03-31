# The Manifesto

---

## THE CRISIS

The Veracode 2025 State of Software Security report established the baseline: AI-assisted code contains **36% more high-severity vulnerabilities** than human-written equivalents. The 2026 addendum refined it further — remediation rates for AI-introduced flaws are declining, because human reviewers cannot process the volume.

Your engineers are merging Copilot output. Your linter passes it. Your SAST tool uploads it to a cloud pipeline and returns a report three minutes later. By then, the PR is merged.

The threat model has changed. Your enforcement layer has not.

---

## THE AGODA BOTTLENECK: WHY HUMAN REVIEW IS FAILING

Agoda's engineering team published the internal numbers in 2025: AI-assisted development increased their per-engineer PR output by **4–6×**. They were not alone. Across the industry, the same pattern holds — Copilot, Cursor, and Claude Code have decoupled code generation velocity from human cognitive throughput.

The arithmetic is unforgiving. A team of 10 engineers, each capable of reviewing 8 PRs per day, has a **review capacity of 80 PRs/day**. A 5× AI-driven surge brings the inbound queue to **400 PRs/day**. The backlog grows by 320 PRs every 24 hours. It never clears. It compounds.

The industry's response has been to lower the bar: reduce review depth, approve-and-merge faster, rely on post-merge monitoring to catch what pre-merge review missed. This is not a solution. It is a delayed incident report.

**Human review at AI velocity is not a process problem. It is a mathematical impossibility.**

The failure mode is already visible in production incident data. The Veracode 2025 State of Software Security report found that AI-assisted code contains **36% more high-severity vulnerabilities** than human-written equivalents — and that remediation rates are *declining*, because the review queue is too deep for engineers to triage what entered the codebase three sprints ago.

### The Structural Circuit Breaker

The Agoda bottleneck has one solution: move enforcement to the *diff level*, before the merge button is available, at machine velocity.

The Janitor is that circuit breaker. It does not replace code review — it eliminates the class of structural failures that should never reach a human reviewer in the first place:

- **AI-generated boilerplate** caught by the Vibe-Check Gate before tree-sitter parses a node
- **Coordinated Swarm injection** caught by MinHash LSH before a human sees the second PR
- **Zombie dependencies** caught by the import graph cross-reference before they enter the manifest
- **Security antipatterns** caught by AST-level structural analysis before they reach staging

A human reviewer reading a PR should be deciding whether the *logic* is correct. The Janitor ensures the *structure* is already clean when the PR arrives. The bottleneck is not eliminated — it is upstream-shifted to where it can be handled deterministically, in parallel, at zero marginal cost per PR.

When the queue is 400 PRs deep, the circuit breaker is not optional. It is the only way the queue ever clears.

---

## THE PR GATE: LIVE RESULTS

The `janitor bounce` command intercepts pull requests at the diff level and scores them across four dimensions:

| Signal | Weight | What It Catches |
|:-------|:------:|:----------------|
| Dead symbols introduced | ×10 | Functions with no call sites entering the codebase |
| Logic clones detected | ×5 | Structurally identical implementations under different names |
| Zombie symbols reintroduced | ×15 | Previously-deleted symbols returning via AI-assisted copy-paste |
| Language antipatterns | ×50 | Hallucinated imports, vacuous unsafe blocks, goroutine closure traps |

**Social Forensics** runs on top: every added comment line is scanned for AI-ism phrases (`"Note that"`, `"It's worth mentioning"`, `"As an AI"`) and corporate-speak markers via a zero-allocation AhoCorasick automaton. PR bodies are scanned for issue link compliance (`Closes #N`, `Fixes #N`).

**Global Audit 2026 — 33,000+ live PRs across 22 enterprise repositories, on an 8 GB laptop:**

```
Repos audited         : 22 (godot, nixpkgs, vscode, k8s, pytorch, kafka, rust,
                            tauri, redis, next.js, home-assistant, ansible,
                            workers-sdk, langchain, deno, rails, laravel,
                            apple/swift, aspnetcore, okhttp, terraform, neovim)
PRs analyzed          : 33,000+  (live production PRs — no synthetic benchmarks)
Hardware              : 8 GB laptop
Antipatterns blocked  : confirmed structural defects — zero false positives
Engine panics         : 0
OOM events            : 0
```

These are real, open pull requests against 22 production codebases — including the Rust compiler, the Linux package ecosystem, and the Swift compiler. The gate works.

[Full audit results →](intelligence.md)

---

## THE ACTUARIAL RISK MATRIX

The Janitor doesn't just find vulnerabilities — it generates a financial ledger. Every intercepted threat is categorized and priced on a three-tier billing model:

| Category | Trigger | Value |
|:---------|:--------|------:|
| **Critical Threat** | `security:` antipattern OR Swarm collision (`collided_pr_numbers` non-empty) | **$150 / incident** |
| **Necrotic GC** | Dead-code ghost flagged by Necrotic Pruning Matrix, not a security threat | **$20 / PR** |
| **StructuralSlop** | `slop_score > 0`, no critical or necrotic signal | **$20 / PR** |
| Boilerplate clone | `slop_score == 0`, no threat signal | $0 |

**Total Economic Impact** = `(critical_threats × $150) + (necrotic_gc × $20) + (structural_slop × $20)`

The ledger is machine-generated, per-PR, and written to `.janitor/bounce_log.ndjson` atomically on every bounce event. `janitor report --format json` emits `critical_threats_count`, `critical_threat_bounty_usd`, `total_economic_impact_usd`, and `total_ci_energy_saved_kwh` for downstream dashboards and executive briefings. `janitor export` produces a 16-column CSV (including `Commit_SHA` and `Policy_Hash` audit trail columns) with `Operational_Savings_USD` per row — load directly into Excel or pandas.

Audited **33,000 PRs across 22 enterprise repositories on an 8 GB laptop.**

---

## THE INTEGRITY DASHBOARD (WOPR)

```
janitor dashboard <repo>
```

Visualize C/C++ compile-time blast radius and track structural Swarm clones in real-time. The WOPR (War Operations Plan Response) dashboard, built on Ratatui, renders:

- **Top-10 `#include` dependency silos** ranked by transitive reach — files whose modification ripples furthest through the compile graph.
- **Live Swarm clone feed** — MinHash LSH collision events as they are detected, showing colliding PR numbers in real-time.
- **Physarum backpressure indicator** — current RAM pressure tier (Flow / Constrict / Stop) and active analysis slot count.

The graph is built from in-memory libgit2 tree walks at the start of every `hyper-drive` run. No filesystem checkout is required; all data is read from the Git pack index.

---

## THE TECHNICAL STACK

### The Anatomist

Parses via zero-copy Tree-sitter CSTs across **23 grammars: C, C++, Rust, Go, Java, C#, JavaScript, TypeScript, Python, GLSL, Objective-C, Bash, Nix, Scala, Ruby, PHP, Swift, Lua, Go, Kotlin, HCL, and more** — with v7.9.4 Tier-1 Enterprise expansions adding Ruby, PHP, Swift, and Lua to the production grammar registry. v7.9.4 NCD entropy gate adds zstd-based boilerplate detection across all 23 grammars simultaneously. Extracts every function, class, and top-level symbol as a zero-copy `Entity` with byte ranges, qualified names, decorator lists, and structural hashes. Builds a directed reference graph resolving imports, attribute calls, and language-specific linkage.

`OnceLock<Language>` statics: each grammar occupies **8 bytes of static overhead** (an uninitialised pointer slot on 64-bit) until first use. Total: **184 bytes of static overhead** for all 23 grammars. Grammar compiled once per process lifetime — zero re-compilation, zero per-call allocation, strict 8 GB RAM ceiling enforced by the Physarum governor.

### The 6-Stage Dead Symbol Pipeline

| Stage | Filter | Guard |
|-------|--------|-------|
| 0 | Directory exclusion (`tests/`, `migrations/`, `venv/`) | `Protection::Directory` |
| 1 | Reference graph: in-degree > 0 | `Protection::Referenced` |
| 2+4 | Heuristic wisdom + `__all__` exports | Various |
| 3 | Library mode: all public symbols protected | `Protection::LibraryMode` |
| 5 | Aho-Corasick scan of non-`.py` files | `Protection::GrepShield` |

Anything that survives all five gates is a confirmed dead symbol. No false positives from GDCLASS registration macros, function pointer dispatch, or runtime-registered plugins.

### The Forge

BLAKE3 structural hashing with alpha-normalization detects logic clones — functions with identical structure and different names. Chemotaxis ordering prioritizes high-calorie files (`.rs`, `.py`, `.go`, `.ts`) in the analysis pass. The `slop_hunter` detects language-specific antipatterns via Tree-sitter AST walks: hallucinated Python imports, vacuous Rust `unsafe` blocks, goroutine closure traps.

**The Vibe-Check Gate** — `check_entropy()` compresses each patch blob via `zstd` at level 3 and computes the ratio `compressed_len / raw_len`. "Vibe-coded" PRs — generated by describing intent to an AI without authoring the implementation — compress below threshold `0.15`. They are statistically self-similar: the same variable names, the same docstring boilerplate, the same structural scaffolding repeated across functions, because the model is completing patterns rather than solving problems. Human-authored code has structural variance; vibe code does not.

Any blob below the `0.15` threshold triggers the `antipattern:ncd_anomaly` label, scoring +10 points and surfacing in the bounce log. This is O(N) in patch size and executes before the AST crawl — vibe-coded PRs are caught before tree-sitter parses a single node. Patches smaller than 256 bytes are exempt to prevent zstd frame-overhead false positives.

**Null-Vector Collision Shield** — A triple-layer false-positive prevention system guaranteeing score=0 cannot be spuriously raised on legitimate infrastructure changes: (1) IaC bypass — `.nix`, `.lock`, `.json`, `.toml`, `.yaml`, `.yml`, `.csv` extensions bypass `ByteLatticeAnalyzer` entirely (nix sha256 hashes and lockfile digests are legitimate high-density content); (2) size guard — patches below 256 bytes bypass the NCD entropy gate (zstd frame overhead dominates tiny inputs); (3) domain router — `DOMAIN_VENDORED` blobs suppress memory-safety rules on upstream CVE patches touching `thirdparty/`, `third_party/`, `vendor/` paths. False positives on CVE vendor patches: **zero, by construction**.

**Net-Negative Exemption** — The scoring formula (`dead_symbols_added × 10 + zombie_symbols_added × 15 + antipatterns_found × 50 + ...`) operates exclusively on *newly introduced* signals. A patch that only removes code — massive boilerplate deletions, deprecated API purges, dead function cleanup — contributes nothing to any multiplicand. Score=0 is a mathematical guarantee for deletion-dominant patches, not a heuristic. This is the correct enforcement model: the gate enforces *what enters the codebase*, not what leaves it.

**Universal Bot Shield** — `is_automation_account()` applies a 4-layer classification before analysis: `app/` prefix (GitHub Apps), `[bot]` suffix, configurable `trusted_bot_authors`, and per-repo `[forge].automation_accounts` in `janitor.toml`. Bot PRs receive full structural analysis; no code is exempt from review.

**Agnostic IaC Shield** — `ByteLatticeAnalyzer` detects binary blobs and high-entropy payloads (encrypted data, shellcode) injected into source patches. IaC file extensions (`.nix`, `.lock`, `.json`, `.toml`, `.yaml`, `.yml`, `.csv`) bypass the entropy gate — these formats contain legitimate high-density hashes (nix sha256, lockfile digests) that would otherwise produce false `AnomalousBlob` detections. Files above 7.0 bits/byte windowed entropy or containing null bytes are flagged regardless of extension.

### Swarm Clustering

Detects and mathematically clusters Agentic Swarm attacks using **64-bit Locality-Sensitive Hashing**. Every PR diff is sketched into a 64-component MinHash signature over byte 3-grams. The `LshIndex` (8 bands × 8 rows, ArcSwap lock-free) stores these signatures across the entire audit session. Any two patches with Jaccard similarity ≥ 0.85 are flagged as structural clones — instantly identifying **100% topological duplicates** across thousands of PRs.

When the same LLM-generated change is submitted under different PR numbers from coordinated accounts, the Jaccard distance collapses to near-zero. Swarm Clustering catches this deterministically, without heuristics: the math either confirms structural identity or it does not. Colliding PR numbers are written into `collided_pr_numbers` in the bounce log and surfaced in the GitHub Check Run output.

### Domain-Segregated Audit Engine

**Bypasses vendored C/C++ libraries with zero-copy Aho-Corasick path routing, guaranteeing zero false positives on legitimate upstream CVE patches.**

The Domain Router classifies every file blob in a PR diff before analysis begins. Blobs whose paths match vendored directory prefixes (`thirdparty/`, `third_party/`, `vendor/`) are assigned `DOMAIN_VENDORED` and routed through a dedicated analysis pass — memory-safety rules that would flag raw pointer arithmetic in application code are suppressed for vendored upstream C sources. This is the correct behaviour: a Godot Engine CVE patch touching `thirdparty/mbedtls/` is a legitimate security fix, not slop.

### The Reaper

Surgical byte-range deletion. Sorted bottom-to-top by `start_byte` to preserve upstream offsets. UTF-8 hardened via `str::is_char_boundary()`. Atomic backup to `.janitor/ghost/` before first write. Rollback via `janitor undo` restores exact pre-deletion state.

### The Daemon

A long-lived Unix Domain Socket server keeps the symbol registry memory-resident across CI requests. Eliminates process-spawn overhead for high-frequency pipelines. The **Physarum Protocol** — named for *Physarum polycephalum*, slime mould that modulates nutrient flow under environmental pressure — governs backpressure: RAM ≤ 75% = full throughput; 75–90% = throttle to 2 concurrent analyses; > 90% = hold and retry.

### Data Sovereignty

All operations run locally when using the CLI or GitHub Action. Your source code is memory-mapped on your hardware and never transmitted when using the CLI or GitHub Action. See deployment models above. The signed attestation token is verified by a 32-byte public key embedded in the binary. No telemetry. No cloud dependency. No exfiltration surface.

---

## INSTALLATION

**From source (Rust 1.82+, `just` required):**

```sh
git clone https://github.com/janitor-security/the-janitor
cd the-janitor
just build
# Binary: target/release/janitor
```

**Pre-built binary:**

```sh
# Download from Releases, then:
chmod +x janitor && sudo mv janitor /usr/local/bin/
```

---

## COMMANDS

```sh
# Structural dead symbol audit
janitor scan <path> [--library] [--format json]

# PR enforcement gate — score a diff against the registry
janitor bounce <path> --patch <file> --pr-number <n> --author <handle> --pr-body "$BODY" --format json

# Zombie dependency detection across npm / cargo / pip / spin / wrangler
janitor scan <path> --format json  # zombie_deps in output

# Structural clone detection
janitor dedup <path>

# Safe Proxy deduplication (explicit flag required)
janitor dedup <path> --apply --force-purge

# Shadow-simulate deletion → test suite → physical removal
janitor clean <path> --force-purge

# Generate historical slop / clone / zombie intelligence report
janitor report [--repo <path>] [--top <n>] [--format markdown|json]

# Long-lived daemon for low-latency CI (Unix socket, Physarum backpressure)
janitor serve [--socket <path>] [--registry <file>]

# Ratatui TUI dashboard
janitor dashboard <path>
```

---

## THE PROOF

> **3.5 million lines. 33 seconds. 58 megabytes. Zero panics.**
>
> [Read the Godot Engine Autopsy →](intelligence.md)

---

> See [Architecture](architecture.md) for the full technical specification.
