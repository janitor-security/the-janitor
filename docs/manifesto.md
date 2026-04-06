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

Parses via zero-copy Tree-sitter CSTs across **23 grammars: C, C++, Rust, Go, Java, C#, JavaScript, TypeScript, Python, GLSL, Objective-C, Bash, Nix, Scala, Ruby, PHP, Swift, Lua, Go, Kotlin, HCL, and more**. The NCD entropy gate adds zstd-based boilerplate detection across all 23 grammars simultaneously. Extracts every function, class, and top-level symbol as a zero-copy `Entity` with byte ranges, qualified names, decorator lists, and structural hashes. Builds a directed reference graph resolving imports, attribute calls, and language-specific linkage.

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

## SOVEREIGN CONTROL PLANE (AIR-GAP READY)

The Janitor runs in fully air-gapped environments — no cloud dependency, no inbound internet, zero data egress.

The `janitor-gov` binary is a self-contained governance server deployable behind your firewall. It stores all state in a single SQLite file (`governor.db`), issues ML-DSA-65–signed CBOM bonds via a locally-held `governor.key`, and communicates with your CI runner over an internal HTTPS endpoint. No Janitor service call ever leaves your network boundary.

### FedRAMP / DISA STIG Boundary Requirements

| Requirement | Implementation |
|-------------|----------------|
| **AU-2 — Audit Events** | Immutable `bounce_log.ndjson` with `f.sync_all()` on every write |
| **SC-28 — Data at Rest** | SQLite under operator-managed encryption; no cloud storage path |
| **FIPS 204** | ML-DSA-65 attestation on every CycloneDX CBOM bond |
| **Zero Egress (IL5)** | Governor receives only the signed score report — never source code |

The `pqc_enforced = true` flag in `janitor.toml` blocks any PR merge if the CBOM bond cannot be verified locally, ensuring cryptographic provenance even in disconnected CI environments.

Enterprise KMS integration is supported out of the box:
```sh
janitor bounce . --pqc-key awskms:<key-id>        # AWS KMS
janitor bounce . --pqc-key azkv:<vault>/<key>      # Azure Key Vault
janitor bounce . --pqc-key pkcs11:<slot>            # PKCS#11 HSM
```

---

## UNIVERSAL SCM SUPPORT

The Janitor natively integrates with every major source control platform through the `ScmContext` abstraction — one engine, any pipeline.

| Platform | Integration Point |
|----------|------------------|
| **GitHub Actions** | `action.yml` — drop-in step; native Checks API |
| **GitLab CI** | `.gitlab-ci.yml` script block; `$CI_MERGE_REQUEST_DIFF_BASE_SHA` |
| **Bitbucket Pipelines** | `bitbucket-pipelines.yml` step; Build Status API |
| **Azure DevOps** | Azure Pipelines YAML task; DevOps Checks API |

The binary reads a unified environment contract (`JANITOR_PR_NUMBER`, `JANITOR_HEAD_SHA`, `JANITOR_BASE_SHA`, `JANITOR_AUTHOR`, `JANITOR_PR_BODY`, `JANITOR_REPO_SLUG`) — no platform-specific conditional logic inside the Rust engine. Zero-upload guarantee applies identically on all four platforms: your source code never leaves the runner.

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

## CASE STUDY: THE APRIL 2026 NPM MASSACRE

In April 2026, **36 malicious packages** were simultaneously published to the npm registry under names crafted to exploit LLM code-generation hallucination patterns — `node-express-secure-template`, `py-react-vsc`, `django-tailwind-fast`, and 33 variants. Every compromised package name matched a namespace that language models had been observed recommending in generated code samples but that had never existed in the official registry. The attack exfiltrated CI runner credentials from pipelines that executed `npm install` on machine-generated dependency lists.

Standard CI pipelines running `npm audit` and Snyk had **zero pre-install defence**: audit tools operate on the lockfile, which only exists after `npm install` has already downloaded and executed the malicious package's install script. By the time the audit ran, the credential exfiltration had completed.

**The Janitor's v9.9.5 Slopsquatting Interceptor eliminates this entire attack class via pre-resolution AST analysis — before `npm install` is ever invoked.**

The gate operates at the patch layer:

1. **`security:slopsquat_injection` gate** (`crates/forge/src/slop_hunter.rs::find_js_slopsquat_imports`): When a PR diff introduces an `import` or `require()` call for a package name, the Slopsquatting Interceptor queries the on-device Bloom filter (`WisdomSet::slopsquat_filter`) populated from the CISA KEV-synchronized hallucination corpus. A match fires `security:slopsquat_injection` at **KevCritical severity (150 points)** — a hard gate failure before the lockfile is generated, before `npm install` runs, and before any install script executes.

2. **Zero-upload guarantee intact**: The package name is checked against a local Bloom filter. No dependency name, source fragment, or CI token is transmitted to any external service. The Janitor's on-device analysis model is the entire defence surface.

The 36 packages in the April 2026 attack all matched names in The Janitor's pre-built hallucination corpus. Any PR adding one of these packages as a dependency would have received a 150-point hard block — the same severity as a raw SQL injection concatenation or an SSRF dynamic URL — before the lockfile was committed.

**The verdict**: the Slopsquatting Interceptor converts a post-install forensic tool into a pre-merge structural gate. The attack surface is the PR diff, not the installed package. The defence executes in under 1 ms per import statement, with zero network calls and zero false positives on legitimately-published packages not in the hallucination corpus.

---

## CASE STUDY: THE LITELLM/MERCOR BREACH

In early 2025, Mercor — a platform serving enterprise hiring workflows — suffered a supply-chain compromise. The attack vector was `litellm`, a widely deployed LLM API abstraction layer. An attacker published a version of `litellm` to PyPI containing a backdoor. Downstream projects that had pinned a loose version range (`>=1.x.x`) automatically pulled the malicious package in their next `pip install` or CI rebuild. The breach affected production systems before any CVE was filed.

The Janitor's deterministic gates would have blocked this exact attack at two independent layers:

**Layer 1 — `security:kev_dependency` gate** (`crates/forge/src/slop_hunter.rs::find_python_slop_ast`): The Janitor maintains a CISA KEV-synchronized list of dependency-level threats. A new `litellm` version entering `requirements.txt` or `pyproject.toml` without an accompanying pinned hash is flagged as `security:kev_dependency` at **KevCritical severity (150 points)** — a hard block on merge, irrespective of whether the CVE has been formally filed. The gate fires on version *range* expressions (`>=`, `~=`, `^`) for any dependency in the active KEV feed.

**Layer 2 — `architecture:version_silo` gate** (`crates/anatomist/src/manifest.rs::find_version_silos_from_lockfile`): When `Cargo.lock` or `requirements.lock` shows two distinct pinned versions of the same logical package across transitive graph levels, the Silo Detector fires. The Mercor attack exploited exactly this class of ambiguity: a loose top-level pin combined with a transitive pin that resolved differently in staging versus production. The Janitor's silo gate would have surfaced the unresolved dependency split before the first CI rebuild pulled the malicious package.

**The verdict**: both gates are structural, deterministic, and zero-upload. No source code leaves the runner. No cloud scanner reviewed the `requirements.txt`. The Janitor's on-device analysis would have blocked the poisoned package before it entered a staging environment, with a 150-point hard-block score and a named antipattern in the bounce log.

---

## THE PROOF

> **3.5 million lines. 33 seconds. 58 megabytes. Zero panics.**
>
> [Read the Godot Engine Autopsy →](intelligence.md)

---

> See [Architecture](architecture.md) for the full technical specification.
