<p align="center">
  <img src="assets/logo_text.svg" alt="The Janitor" width="80%" style="max-width: 800px; display: block; margin: 0 auto;">
</p>

![Janitor Terminal Demo](assets/janitor_demo.webp)

# The Janitor

**v7.1.14 — Rust-Native. Zero-Copy. Pro-Entropic Resilience at the Gate.**

---

> **Sonar finds style violations.**
> **The Janitor enforces structural integrity.**

> *82% of open Godot Engine pull requests contain no issue link. 20% introduce language antipatterns. Zero comment scanners caught it. The Janitor did — across 50 live PRs, in under 90 seconds.*

---

## THE CRISIS

The Veracode 2025 State of Software Security report established the baseline: AI-assisted code contains **36% more high-severity vulnerabilities** than human-written equivalents. The 2026 addendum refined it further — remediation rates for AI-introduced flaws are declining, because human reviewers cannot process the volume.

Your engineers are merging Copilot output. Your linter passes it. Your SAST tool uploads it to a cloud pipeline and returns a report three minutes later. By then, the PR is merged.

The threat model has changed. Your enforcement layer has not.

---

## THE ENFORCEMENT LAYER

The Janitor is not a linter. It is not a SAST scanner. It is a **structural enforcement layer** that runs on your hardware, in your pipeline, on every pull request — before the merge button is available.

Three capabilities your current toolchain cannot replicate:

### Zero-Copy Execution

Every analysis — reference graph construction, dead symbol detection, structural clone hashing — executes via **memory-mapped file access**. Your source code is never copied to heap, never serialized, never transmitted. No network call is made at any point in the dead-symbol pipeline. The analysis surface is your local machine. There is no exfiltration vector to audit.

**Benchmark:** Scanned the Godot Engine — **3.5 million lines of polyglot C++, C#, Java, Objective-C++, and Python** — in **33 seconds**, consuming **58 MB of peak RAM**. On a standard CI runner. With zero OOM events and zero panics.

Sonar's cloud pipeline cannot run in your air-gap. The Janitor runs everywhere.

### Zombie Dependency Detection

AI code generators hallucinate package imports. A Copilot-generated function adds `import requests` at the module level and uses it exactly once — inside a conditional branch that never executes in production. Standard linters do not detect this. Import graphs do not resolve it. Dependency reviewers do not see it.

The Janitor scans **`package.json`, `Cargo.toml`, `requirements.txt`, `spin.toml` (Fermyon WASM), and `wrangler.toml` (Cloudflare Workers)** against the live symbol reference graph. A package that appears in your manifest but never appears in a reachable import path is a **zombie dependency** — declared, installed, and billing you in attack surface.

Every PR that introduces a zombie dependency is flagged before merge.

### Cryptographic Integrity Bonds

When a pull request clears the slop gate, **Janitor Sentinel** — our GitHub App — automatically issues a **CycloneDX v1.5 CBOM** (Cryptography Bill of Materials) for the merge event. The CBOM records every cryptographic operation performed during the scan: the ML-DSA-65 (NIST FIPS 204) attestation signature, the BLAKE3 structural hashes, and the per-symbol audit entries covering `{timestamp}{file_path}{sha256_pre_cleanup}`.

No token flag. No manual step. The proof is issued by the SaaS on a clean merge — a chain of custody presentable to a SOC 2 auditor, a regulator, or an incident response team. Not a log. A bond.

### Zero-Friction GitHub Integration

![Janitor Sentinel Demo](assets/sentinel_demo.webp)

*Janitor Sentinel automatically downgrades vetoes when it detects safe patterns (e.g., Dependabot).*

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

**Global Audit 2026 — 2,090 live PRs across 22 Tier-1 repositories:**

```
Repos audited         : 22 (godot, nixpkgs, vscode, k8s, pytorch, kafka, rust,
                            tauri, redis, next.js, home-assistant, ansible,
                            workers-sdk, langchain, deno, rails, laravel,
                            apple/swift, aspnetcore, okhttp, terraform, neovim)
PRs analyzed          : 2,090
Total Slop Score      : 38,685
Antipatterns blocked  : 124 (confirmed structural defects — zero false positives)
Engine panics         : 0
OOM events            : 0
```

These are real, open pull requests against 22 production codebases — including the Rust compiler, the Linux package ecosystem, and the Swift compiler. The gate works.

[Full audit results →](ultimate_gauntlet_results.md)

---

## THE TECHNICAL STACK

### The Anatomist

Parses via zero-copy Tree-sitter CSTs across **23 grammars: C, C++, Rust, Go, Java, C#, JavaScript, TypeScript, Python, GLSL, Objective-C, Bash, Nix, Scala, Ruby, PHP, Swift, Lua, Go, Kotlin, HCL, and more** — with v7.1.14 Tier-1 Enterprise expansions adding Ruby, PHP, Swift, and Lua to the production grammar registry. v7.1.14 NCD entropy gate adds zstd-based boilerplate detection across all 23 grammars simultaneously. Extracts every function, class, and top-level symbol as a zero-copy `Entity` with byte ranges, qualified names, decorator lists, and structural hashes. Builds a directed reference graph resolving imports, attribute calls, and language-specific linkage.

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

**Pro-Entropic Resilience — NCD Entropy Gate** — `check_entropy()` compresses each patch blob via `zstd` at level 3 and computes the ratio `compressed_len / raw_len`. Any blob below threshold `0.15` (highly self-similar content) triggers the `HighGenerativeVerbosity` antipattern, scoring +50 and surfacing in the bounce log. This is O(N) in patch size and executes before the AST crawl — AI-generated boilerplate is caught before tree-sitter parses a single node. Patches smaller than 256 bytes are exempt to prevent zstd frame-overhead false positives.

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

Prior to v7.1.14, pipeline tools stripped vendored hunks from the diff before the engine ever saw them. The engine's domain router was starved of the blobs it needed to classify them correctly. The v7.1.14 ingestion pipeline purification removes all directory-based pre-filtering. Only unparseable binary-extension blobs (`.png`, `.so`, `.exe`, `.wasm`) are stripped before the engine. Everything else passes through raw so the domain router can make the correct call.

### The Reaper

Surgical byte-range deletion. Sorted bottom-to-top by `start_byte` to preserve upstream offsets. UTF-8 hardened via `str::is_char_boundary()`. Atomic backup to `.janitor/ghost/` before first write. Rollback via `janitor undo` restores exact pre-deletion state.

### The Daemon

A long-lived Unix Domain Socket server keeps the symbol registry memory-resident across CI requests. Eliminates process-spawn overhead for high-frequency pipelines. The **Physarum Protocol** — named for *Physarum polycephalum*, slime mould that modulates nutrient flow under environmental pressure — governs backpressure: RAM ≤ 75% = full throughput; 75–90% = throttle to 2 concurrent analyses; > 90% = hold and retry.

### Data Sovereignty

All operations run locally. Your source code is memory-mapped on your hardware and never transmitted. The signed attestation token is verified by a 32-byte public key embedded in the binary. No telemetry. No cloud dependency. No exfiltration surface.

---

## ECONOMICS

**The enforcement is free. The attestation is the product.**

| Tier | Cost | What You Get |
|:-----|:-----|:-------------|
| **Free** | $0 | Unlimited scan, clean, dedup, bounce, dashboard, report. No signed logs. |
| **[Team](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348)** | **$499/yr** | All free features + ML-DSA-65 Integrity Bonds + CycloneDX v1.5 CBOMs + CI/CD Compliance Attestation + Janitor Sentinel GitHub App. Up to 25 seats. |
| **[Industrial](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7)** | **Custom** | On-Premises Token Server + Keypair Rotation Protocol + SOC 2 Audit Support + Enterprise SLA. Unlimited seats. |

The cleanup is identical at every tier. What you are paying for is a cryptographically verifiable chain of custody that satisfies a regulator, an auditor, or an incident response team.

[**Activate Attestation → thejanitor.lemonsqueezy.com**](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7)

---

## INSTALLATION

**From source (Rust 1.82+, `just` required):**

```sh
git clone https://github.com/GhrammR/the-janitor
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
> [Read the Godot Engine Autopsy →](case-studies/godot.md)

---

> See [Security Posture](security.md) for the Shadow Tree isolation, atomic rollback protocol, and hermetic build details.
> See [Pricing & Licensing](pricing.md) for BUSL-1.1 terms and commercial tier details.
> See [Terms of Service](terms.md) · [Privacy Policy](privacy.md) for legal and data handling.
