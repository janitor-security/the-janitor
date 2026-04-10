---
hide:
  - toc
---

<p align="center">
  <img src="assets/logo_text.svg" alt="The Janitor" width="80%" style="max-width: 800px; display: block; margin: 0 auto;">
</p>

![Janitor Terminal Demo](assets/janitor_demo.webp)

# The Janitor

**v10.0.0-rc.16 — Parse-Forest Engine & Deterministic Structural Firewall. 23/23 grammar AST coverage (100%). Attosecond-grade integrity for the AI-assisted development economy.**

---

> **Sonar finds style violations.**
> **The Janitor enforces structural integrity.**

> *82% of open Godot Engine pull requests contain no issue link. 20% introduce language antipatterns. Zero comment scanners caught it. The Janitor did — across 50 live PRs, in under 90 seconds.*

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

### Datacenter Sustainability

By intercepting structural slop at the AST level, The Janitor prevents wasted CI/CD cycles, reclaiming kilowatt-hours of grid capacity from agentic churn. Every actionable intercept eliminates one CI run that would have consumed approximately **0.1 kWh** of datacenter energy (basis: 15-minute average CI run at 400 W). The cumulative energy ledger is tracked per-repository in the Workslop report under **CI Energy Reclaimed**.

---

## THE SHADOW AI CRISIS

Forrester's 2025 AI Developer Tools survey established a number that should alarm every CISO: **78% of developers use AI coding tools regardless of corporate policy.** Shadow AI is not a fringe phenomenon. It is the operating condition.

The standard corporate response — policy memos, access controls, approval workflows — fails for a structural reason: the gap between writing code and merging it has collapsed. A developer who pastes a function from ChatGPT and commits it has bypassed every review control designed for a human contributor typing in an IDE. The code enters the branch. The lint passes. The PR opens. The merge button is available.

**The Janitor is the only Hard-Point Defense that operates at the runner level.**

It does not audit the developer's tool selection. It does not require a policy acknowledgement. It is not a training module. It is a circuit breaker installed at the single point where all code — whether AI-generated, AI-assisted, or human-authored — must pass before it enters the main branch: the pull request gate.

When a Shadow AI user opens a PR, the Janitor gate fires against the diff — not the developer, not their toolchain, not their intent. The math either confirms structural integrity or it does not. The gate passes or it blocks. The policy is enforced at the runner, not at the user.

| Control Layer | Where it fires | Bypassed by Shadow AI? |
|:---|:---|:---:|
| Policy memo | Developer awareness | **Yes** |
| IDE plugin (Copilot filter) | Developer machine | **Yes** |
| SAST cloud upload | CI pipeline, after commit | **Yes** |
| **The Janitor (Hard-Point Defense)** | **Runner, before merge** | **No** |

The Janitor enforces your architectural rules at the one choke point that Shadow AI cannot route around.

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

### The Doorman Fallacy

A Doorman checks if you are wearing shoes. He does not x-ray your briefcase.

Lightweight linters — ESLint, Pylint, Clippy — check if a PR compiles and conforms to style guides. They are Doormen. They operate on the surface: syntax, formatting, known CVE patterns. They are excellent at what they do. They do not do what The Janitor does.

The Janitor conducts a **structural autopsy**. It does not check formatting. It does not run a known-bad signature database. It maps the reference graph, hashes every function body with BLAKE3, runs a MinHash Jaccard swarm collision check across your entire PR history, and issues a ML-DSA-65 (NIST FIPS 204) signed cryptographic bond for every clean merge.

The Doorman Fallacy is the belief that *more Doormen solve the Doorman problem*. They do not. A stack of five linters — each using 5 MB of RAM to pattern-match against pre-AI threat signatures — does not cover 90% of the threat surface. It covers the same 10% five times. The structural category of AI-generated slop has no CVE record. It is invisible to every tool trained on pre-AI codebases.

You do not need a tool that uses 5 MB of RAM to ignore 90% of the threat.

**You need a tool that uses 60 MB of RAM to guarantee FIPS 204 provenance.**

The Janitor is the only gate in the pipeline that conducts a structural autopsy instead of a wardrobe check. It is 60 MB at peak on a 3.5-million-line polyglot repository. It exits in 33 seconds. And it issues a quantum-safe attestation bond that your Doormen cannot produce if they run until the heat death of the universe.

### Agentic-Ready

The threat model is already changing. AI coding assistants are becoming autonomous agents — systems that open PRs without human authorship, coordinate across accounts, and submit structurally identical changes at a rate no human review queue can absorb. Copilot is the training run. The Swarm is the production workload.

Current toolchains were designed for human developers submitting a few PRs per day. They have no concept of a non-human contributor operating at machine velocity, no mechanism to detect coordinated structural injection across hundreds of PRs, and no policy layer that can distinguish a legitimate bot from a compromised Agentic pipeline.

The Janitor was built for this environment. **It is the deterministic enforcement gate that applies your architectural rules to non-human developers** — the same rules, at the same threshold, regardless of whether the author is a human engineer, a Copilot agent, or an autonomous Swarm. The `janitor.toml` governance manifest is version-controlled policy-as-code: your rules, enforced at the diff level, before the merge button is available.

When your team deploys AI engineers, the gate does not move.

---

## GOOGLE-READY PQC ATTESTATION

Google announced in early 2026 that all internal cryptographic operations must be quantum-safe ahead of schedule, with external-facing systems following suit. **NIST FIPS 204 (ML-DSA-65)** — the Module Lattice Digital Signature algorithm — is the mandated post-quantum standard. The migration window is shorter than most security teams have budgeted for.

Every **CycloneDX v1.5 CBOM** issued by Janitor Sentinel is signed with **ML-DSA-65** today.

| Claim | Implementation |
|---|---|
| Signature algorithm | **ML-DSA-65** (NIST FIPS 204 — Module Lattice Digital Signature) |
| Hash algorithm | **BLAKE3** (256-bit) for structural hashes and per-symbol audit entries |
| Format | **CycloneDX v1.5 CBOM** — Cryptography Bill of Materials |
| Issuance trigger | Clean merge — automatic, no token flag or manual step |
| Audit target | SOC 2 Type II, NIST CSF 2.0, quantum-readiness audit |

Your compliance artifacts are **ahead of the mandate**. Most enterprises will not complete their PQC migration before Google's accelerated deadline. Every PR that clears the Janitor gate today produces a quantum-safe attestation bond — a chain of custody you will not need to retrofit later.

This is not a migration plan. It is an artifact. The CBOM records the ML-DSA-65 attestation signature, the BLAKE3 structural hashes, and the per-symbol audit entries covering `{timestamp}{file_path}{sha256_pre_cleanup}`. A regulator or incident response team can verify the chain of custody without trusting the issuing system — the math stands alone.

**The only PQC-signed CBOM that fires automatically on every clean PR merge. No configuration. No certificate authority. No migration project.**

---

## DEFEATING AUTONOMOUS PR TAMPERING

On **March 24, 2026**, GitHub rolled out a feature that allows any repository maintainer to assign an open pull request directly to Copilot for autonomous modification. Copilot then reads the PR, plans changes, and pushes commits — without a human writing a single line. The PR author remains the original human opener; the new commits are signed by `copilot[bot]`.

This is not a dependency bump. This is an autonomous agent rewriting your source code inside an open PR, at machine velocity, with no human authorship of the resulting commits.

**The Janitor applies a mandatory +50 point AgenticOrigin surcharge to every PR where Copilot coding agent activity is detected:**

| Detection signal | Trigger |
|---|---|
| PR author is `copilot[bot]` or `github-copilot[bot]` | Author field matches Copilot coding agent handles |
| PR author is `app/copilot` or `app/github-copilot` | GitHub App prefix format |
| PR body contains `Co-authored-by: Copilot` trailer | Copilot pushed commits onto a human-authored PR |

The +50 surcharge means a Copilot-modified PR must be **structurally flawless** to pass the default 100-point gate. One Critical antipattern (50 pts) plus the surcharge (50 pts) equals exactly 100 — a gate failure. A structurally clean Copilot PR scores 50 and passes. **The gate enforces a higher bar, not a blanket block.**

The surcharge fires as `antipattern:agentic_origin` in the bounce log, CBOM, and SIEM webhook payload — providing a full audit trail of every PR where autonomous coding agent activity was detected and gated.

Copilot is not the last. Devin, Cursor Agent, and equivalents follow the same pattern: non-human commits on human PRs, at machine velocity, bypassing the review queue. The AgenticOrigin gate is the enforcement layer that moves with the threat.

---

## GROUND TRUTH VS. THE VIBE RADAR

The market has a new category: **Vibe Radar**. These are tools — cloud-hosted or local — that use LLMs to review pull requests, describe what the code does, and emit an opinion. The opinion sounds authoritative. It is probabilistic. It cannot be audited. It cannot be reproduced. And it is blind to the structural category of threat that AI-generated code actually introduces.

The Vibe Radar is a model reading code with a model. Every finding it surfaces is a confidence interval. Every clean verdict it issues is a bet against the model's training distribution. The attack surface it misses is the one that wasn't in the training data — which is, definitionally, the entire category of novel AI-generated antipatterns.

**The Janitor is not a Vibe Radar. It is a proof system.**

| Property | Vibe Radar (LLM review) | The Janitor (AST structural firewall) |
|:---|:---:|:---:|
| Output type | Probabilistic opinion | Deterministic proof |
| Reproducible verdict | No — model non-determinism | Yes — same diff, same score, always |
| Detects phantom hallucinations | No — calls a hallucinated function, gets a hallucinated analysis | Yes — `security:phantom_hallucination` cross-references base registry |
| Detects Swarm coordination | No | Yes — MinHash LSH at Jaccard ≥ 0.85 across full PR history |
| Source code egress | Yes — sent to inference cluster | No — memory-mapped on your runner |
| Auditable | No | Yes — BLAKE3 hashes, ML-DSA-65 signed CBOM, policy hash |
| Speed | 2–8 minutes per PR | Under 33 seconds for 3.5M-line repos |

A Vibe Radar will catch many things. It will not catch what matters most: a structurally intact PR that calls a function your codebase does not define, introduces a clone of a symbol that was deleted two sprints ago, or submits the same structural scaffold from twenty accounts in a coordinated Swarm.

Those patterns have no CVE record. They are invisible to tools trained on pre-AI codebases. They are invisible to probabilistic reviewers that cannot prove structural identity. They are not invisible to The Janitor — because The Janitor does not guess.

**The Vibe Radar tells you what it thinks. The Janitor tells you what it proved.**

---

## THE MAINTAINER SHIELD

Open-source maintainers are experiencing **death by a thousand slops**.

The Agoda engineering team published the numbers in 2025: AI-assisted development increased per-engineer PR output by **4–6×**. On a team of 10 engineers, that is 400 inbound PRs per day against a human review capacity of 80. The backlog grows by 320 PRs every 24 hours. It never clears. It compounds.

The failure mode is not malice. It is **context bloat**.

AI coding agents suffer a predictable structural degradation as their context windows extend to handle larger codebases. Signal-to-noise ratio collapses. The agent generates structurally self-similar functions that pass superficial review. It hallucinates imports that compile but never execute. It reintroduces previously deleted dead symbols — because the deletion happened three sprints ago and the context window has rolled past it. It submits the same structural scaffold across a dozen PRs from a dozen accounts — not a coordinated attack, just a model completing the same pattern it has seen ten thousand times.

Each PR is individually plausible. Collectively, they are **death by a thousand slops** — a flood that overwhelms every human review heuristic precisely because each individual PR clears the bar that human review was designed to catch.

**The 100-point Slop Gate is the definitive defense.**

| Signal | Weight | What it stops |
|:-------|:------:|:--------------|
| Logic clones detected | ×5 | Structurally identical implementations — the context-bloat signature |
| Zombie symbols reintroduced | ×10 | Previously deleted symbols returning via AI copy-paste |
| Language antipatterns | ×50 | Hallucinated imports, unsafe blocks, injection vectors |
| Unlinked PR | ×20 | Agent PRs that bypass issue-tracking hygiene |
| AgenticOrigin surcharge | +50 flat | Autonomous coding agents held to a zero-defect structural standard |

The gate is not a reviewer. It is a circuit breaker. It does not replace human judgment — it eliminates the structural category of slop that should never reach a human reviewer in the first place. When the queue is 400 PRs deep, the circuit breaker is not optional.

A single Critical antipattern from a context-bloated agent PR scores 50 points. The AgenticOrigin surcharge adds 50 more. The PR fails at exactly the gate threshold — deterministically, in under 33 seconds, before the merge button is available.

**The Slop Gate moves with the threat. When your team deploys AI engineers, the gate does not move.**

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

See the [setup documentation](setup.md#webhook-sub-table) for the full `[webhook]` field reference.

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

> See [The Manifesto](manifesto.md) for the full crisis framing, actuarial ledger, and technical stack.
> See [Architecture](architecture.md) for the engine specification.
> See [Setup](setup.md) for Janitor Sentinel configuration and CI integration.
> See [Terms of Service](terms.md) · [Privacy Policy](privacy.md) for legal and data handling.

---

## Pricing

### Free Tier

No account required. No time limit. No LOC cap.

| Capability | Included |
|:-----------|:--------:|
| `janitor scan` — dead symbol detection | ✓ |
| `janitor clean` — shadow simulation + physical removal | ✓ |
| `janitor dedup` — structural clone detection | ✓ |
| `janitor bounce` — PR slop gate (JSON output for CI) | ✓ |
| `janitor dashboard` — Ratatui TUI | ✓ |
| **PQC-Signed Audit Logs** | — |
| **CI/CD Compliance Attestation** | — |
| **Janitor Sentinel** (GitHub App automation) | — |

### Team Specialist — $499 / year

Includes all Free tier capabilities, plus:

| Capability | Included |
|:-----------|:--------:|
| **PQC-Signed Audit Logs** — every cleanup event signed with ML-DSA-65 (NIST FIPS 204) | ✓ |
| **CI/CD Compliance Attestation** — `--token` flag activates signed reports in CI | ✓ |
| **Janitor Sentinel** — GitHub App that runs `janitor bounce` on every PR | ✓ |
| **Shared Credit Pool** — team-level token across all CI runners | ✓ |
| Up to 25 seats on a single license | ✓ |

[**Activate — $499/yr →**](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348)

### Industrial Core — Custom

Includes all Team capabilities, plus:

- **On-Premises Token Server** — dedicated verifying key for air-gapped deployments
- **Keypair Rotation Protocol** — satisfies SOC 2 Type II change-management requirements
- **Enterprise SLA** — 4-hour emergency rotation SLA for confirmed compromises
- **Unlimited seats** on a single organization license

[**Contact sales → sales@thejanitor.app**](mailto:sales@thejanitor.app)

---

## License (BUSL-1.1)

**The Janitor** is licensed under the [Business Source License 1.1 (BUSL-1.1)](https://spdx.org/licenses/BUSL-1.1.html).

- **Non-production use** — free, unrestricted: local scanning, evaluation, research, open-source projects.
- **Production / commercial use** — requires a commercial license when embedding in a SaaS product or issuing attestations to customers.

**Change Date**: `2030-02-15`. License converts automatically to **MIT** on that date, in perpetuity.

### Token Gate

Destructive operations (`janitor clean`, `janitor dedup --apply`) require a valid purge token — a base64-encoded ML-DSA-65 (NIST FIPS 204) signature of the string `JANITOR_PURGE_AUTHORIZED`. The binary embeds **only** the 32-byte verifying key. The signing key never leaves thejanitor.app.

On an invalid or missing token, the CLI prints `ACCESS DENIED` and exits with code `1`. No partial work is performed.

**License questions:** legal@thejanitor.app
**Commercial inquiries:** sales@thejanitor.app

<!-- Keywords: AI Security Firewall, Zero-Upload SAST, PQC CBOM, Structural AST Analysis, Kubernetes Audit, Vibe Coding Defense, AI Pull Request Gate, Supply Chain Attack Detection, Swarm Detection, Dead Symbol GC, LLM Boilerplate Detection, NCD Entropy Gate, CycloneDX CBOM, SARIF Security Report, Zombie Dependency Scanner -->
