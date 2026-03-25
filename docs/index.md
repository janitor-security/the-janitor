<p align="center">
  <img src="assets/logo_text.svg" alt="The Janitor" width="80%" style="max-width: 800px; display: block; margin: 0 auto;">
</p>

![Janitor Terminal Demo](assets/janitor_demo.webp)

# The Janitor

**v7.9.4 — Rust-Native. Zero-Copy. Pro-Entropic Resilience at the Gate.**

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

## Why Not CodeQL, Snyk, or SonarQube?

**CodeQL** is a graph-query engine optimised for known CVE patterns. It does not detect AI-generated structural anomalies, Swarm clone behaviour, or zombie dependency hallucinations — patterns that have no prior CVE record. It also adds 10–45 minutes to CI runtime on large repositories.

**Snyk** excels at known vulnerability databases. It generates false positives at scale on AI-assisted code because it is trained on pre-AI codebases. Teams that have deployed Copilot broadly report Snyk alert fatigue as the primary reason policies get disabled.

**SonarQube** flags style and complexity. It has no structural clone detection, no actuarial ledger, and no mechanism to distinguish an AI-generated PR from a human one. It does not know what an Agentic Swarm is.

The Janitor detects what the others cannot: structural patterns that have no CVE record, coordinated multi-author clone injection, and the entropy signatures of AI-generated boilerplate — deterministically, on your hardware, in under 33 seconds.

Three capabilities your current toolchain cannot replicate:

### Zero-Copy Execution

- **Zero retention**: source code is analysed in-memory and never persisted. No upload required when using the CLI or GitHub Action.

Every analysis — reference graph construction, dead symbol detection, structural clone hashing — executes via **memory-mapped file access**. No network call is made at any point in the dead-symbol pipeline. The analysis surface is your local machine. There is no exfiltration vector to audit.

**Zero-Upload Guarantee — both deployment models:**

| Model | Where analysis runs | Source code leaves your environment? |
|---|---|---|
| **CLI + GitHub Action** (`action.yml`) | Your GitHub Actions runner | **Never** |
| **Janitor Sentinel** (GitHub App) | Your GitHub Actions runner | **Never** — Governor receives only the score |

The Janitor engine runs entirely inside your own runner in both modes. The Governor (Sentinel's backend) receives a signed analysis result — not your source code. There is no server-side clone, no cloud SAST upload, no exfiltration vector.

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

## THE COMPETITIVE MOAT

### On-Device vs. Cloud Fabric

The market is filling with "AI Security Fabrics" — cloud-hosted LLM pipelines that ingest your source code, run probabilistic analysis, and return a verdict four minutes later. They are slow. They exfiltrate your code to a third-party inference cluster. And their probabilistic outputs produce alert fatigue at scale.

The Janitor is the opposite architecture. It is an **on-device structural firewall** — a Rust binary that memory-maps your diffs, applies deterministic analysis, and exits. No network call during the analysis path. No cloud ingestion. No LLM. Proven at **3.5 million lines in 33 seconds on an 8 GB laptop**. Your code never leaves your runner — in either the CLI or the GitHub App deployment model.

Cloud fabrics are an exfiltration vector wearing a security badge. The Janitor eliminates the attack surface instead of adding to it.

### Deterministic vs. Heuristic

LLM-based code review tools cannot *prove* anything. They pattern-match against training distributions and emit confidence scores. A sufficiently novel adversarial input — a well-structured but semantically dangerous diff — is invisible to a heuristic system trained on pre-AI codebases.

The Janitor does not guess. It uses **tree-sitter ASTs to prove structural identity**, **BLAKE3 hashing to prove clone equivalence**, **MinHash Jaccard to prove Swarm coordination**, and **ML-DSA-65 (NIST FIPS 204) to prove chain of custody**. The gate either passes or it does not. The math either confirms structural identity or it does not. There is no confidence interval. There is no false-positive budget. There is a proof — or the PR is blocked.

When a PR clears the gate, Janitor Sentinel issues a CycloneDX v1.5 CBOM: a cryptographically signed bill of materials covering every hash, every symbol, every decision point in the analysis. That is not a report. That is a bond you can present to a SOC 2 auditor.

### Agentic-Ready

The threat model is already changing. AI coding assistants are becoming autonomous agents — systems that open PRs without human authorship, coordinate across accounts, and submit structurally identical changes at a rate no human review queue can absorb. Copilot is the training run. The Swarm is the production workload.

Current toolchains were designed for human developers submitting a few PRs per day. They have no concept of a non-human contributor operating at machine velocity, no mechanism to detect coordinated structural injection across hundreds of PRs, and no policy layer that can distinguish a legitimate bot from a compromised Agentic pipeline.

The Janitor was built for this environment. **It is the deterministic enforcement gate that applies your architectural rules to non-human developers** — the same rules, at the same threshold, regardless of whether the author is a human engineer, a Copilot agent, or an autonomous Swarm. The `janitor.toml` governance manifest is version-controlled policy-as-code: your rules, enforced at the diff level, before the merge button is available.

When your team deploys AI engineers, the gate does not move.

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

[Full audit results →](ultimate_gauntlet_results.md)

---

## THE ACTUARIAL RISK MATRIX

The Janitor doesn't just find vulnerabilities — it generates a financial ledger. Every intercepted threat is categorized and priced on a two-tier billing model:

| Category | Trigger | Value |
|:---------|:--------|------:|
| **Critical Threat** | `security:` antipattern OR Swarm collision (`collided_pr_numbers` non-empty) | **$150 / incident** |
| **Necrotic GC** | Dead-code ghost flagged by Necrotic Pruning Matrix, not a security threat | **$20 / PR** |
| Boilerplate clone | Logic clone with no security signal | $0 |

**Total Economic Impact** = `(critical_threats × $150) + (gc_only × $20)`

The ledger is machine-generated, per-PR, and written to `.janitor/bounce_log.ndjson` atomically on every bounce event. `janitor report --format json` emits `critical_threats_count`, `ci_compute_saved_usd`, and `total_economic_impact_usd` for downstream dashboards and executive briefings. `janitor export` produces a 16-column CSV (including `Commit_SHA` and `Policy_Hash` audit trail columns) with `Operational_Savings_USD` per row — load directly into Excel or pandas.

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

**Pro-Entropic Resilience — NCD Entropy Gate** — `check_entropy()` compresses each patch blob via `zstd` at level 3 and computes the ratio `compressed_len / raw_len`. Any blob below threshold `0.15` (highly self-similar content) triggers the `antipattern:ncd_anomaly` label, scoring +10 points and surfacing in the bounce log. This is O(N) in patch size and executes before the AST crawl — AI-generated boilerplate is caught before tree-sitter parses a single node. Patches smaller than 256 bytes are exempt to prevent zstd frame-overhead false positives.

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

Prior to v7.9.4, pipeline tools stripped vendored hunks from the diff before the engine ever saw them. The engine's domain router was starved of the blobs it needed to classify them correctly. The v7.9.4 ingestion pipeline purification removes all directory-based pre-filtering. Only unparseable binary-extension blobs (`.png`, `.so`, `.exe`, `.wasm`) are stripped before the engine. Everything else passes through raw so the domain router can make the correct call.

### The Reaper

Surgical byte-range deletion. Sorted bottom-to-top by `start_byte` to preserve upstream offsets. UTF-8 hardened via `str::is_char_boundary()`. Atomic backup to `.janitor/ghost/` before first write. Rollback via `janitor undo` restores exact pre-deletion state.

### The Daemon

A long-lived Unix Domain Socket server keeps the symbol registry memory-resident across CI requests. Eliminates process-spawn overhead for high-frequency pipelines. The **Physarum Protocol** — named for *Physarum polycephalum*, slime mould that modulates nutrient flow under environmental pressure — governs backpressure: RAM ≤ 75% = full throughput; 75–90% = throttle to 2 concurrent analyses; > 90% = hold and retry.

### Data Sovereignty

All operations run locally when using the CLI or GitHub Action. Your source code is memory-mapped on your hardware and never transmitted when using the CLI or GitHub Action. See deployment models above. The signed attestation token is verified by a 32-byte public key embedded in the binary. No telemetry. No cloud dependency. No exfiltration surface.

---

## ENTERPRISE INTEGRATIONS

Every bounce event that trips the threat threshold fires an outbound webhook — signed with **HMAC-SHA256** and delivered with two headers your SIEM can verify without a shared secret rotation:

```
X-Janitor-Signature-256: sha256=<hex>
X-Janitor-Event: critical_threat | necrotic_flag
```

The payload is a full `BounceLogEntry` in JSON — PR number, author, score, antipattern IDs, collided PR numbers, commit SHA, and policy hash. Wire it to any receiver in under five minutes:

| Platform | How |
|---|---|
| **Slack** | Incoming Webhooks app → paste URL into `janitor.toml` `[webhook]` block |
| **Microsoft Teams** | Workflows connector → POST to Teams channel webhook URL |
| **Datadog** | Datadog HTTP Logs API endpoint (`https://http-intake.logs.datadoghq.com/api/v2/logs`) |
| **Splunk** | Splunk HTTP Event Collector (`https://<host>:8088/services/collector/event`) |
| **Any SIEM** | Any HTTPS endpoint that accepts a POST with a JSON body |

```toml
# janitor.toml
[webhook]
url    = "https://hooks.slack.com/services/T.../B.../..."
secret = "env:JANITOR_WEBHOOK_SECRET"
events = ["critical_threat", "necrotic_flag"]
```

Test your integration without waiting for a real PR:

```sh
janitor webhook-test --repo .
# info: webhook-test — HTTP 200 ✓ delivery confirmed
```

See the [governance documentation](governance.md#webhook-sub-table) for the full `[webhook]` field reference.

---

## ECONOMICS

**The enforcement is free. The attestation is the product.**

| Tier | Cost | What You Get |
|:-----|:-----|:-------------|
| **Free** | $0 | Unlimited scan, clean, dedup, bounce, dashboard, report. No signed logs. |
| **[Team](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348)** | **$499/yr** | All free features + ML-DSA-65 Integrity Bonds + CycloneDX v1.5 CBOMs + CI/CD Compliance Attestation + Janitor Sentinel GitHub App. Up to 25 seats. |
| **[Industrial](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7)** | **Custom** | On-Premises Token Server + Keypair Rotation Protocol + SOC 2 Audit Support + Enterprise SLA. Unlimited seats. |

The cleanup is identical at every tier. What you are paying for is a cryptographically verifiable chain of custody that satisfies a regulator, an auditor, or an incident response team.

<div align="center">

### [→ Get Janitor Sentinel — $499/yr](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348)

*API token delivered by email within seconds of payment. No per-seat limits.*

</div>

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
> [Read the Godot Engine Autopsy →](case-studies/godot.md)

---

> See [Security Posture](security.md) for the Shadow Tree isolation, atomic rollback protocol, and hermetic build details.
> See [Pricing & Licensing](pricing.md) for BUSL-1.1 terms and commercial tier details.
> See [Terms of Service](terms.md) · [Privacy Policy](privacy.md) for legal and data handling.
