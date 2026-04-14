---
hide:
  - toc
---

<p align="center">
  <img src="assets/logo_text.svg" alt="The Janitor" width="80%" style="max-width: 800px; display: block; margin: 0 auto;">
</p>

![Janitor Terminal Demo](assets/janitor_demo.webp)

# The Janitor

**v10.1.2 — Structural Firewall for AI-Generated Code. 23 Grammars. Dual-PQC Attestation. SLSA Level 4 Reproducible Builds. Zero-Upload. On-Device.**

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

When a pull request clears the slop gate, **Janitor Sentinel** — our GitHub App — automatically issues a **CycloneDX v1.6 CBOM** (Cryptography Bill of Materials) for the merge event. The CBOM records every cryptographic operation performed during the scan: the **Dual-PQC** attestation signature (ML-DSA-65 NIST FIPS 204 + SLH-DSA NIST FIPS 205), the SHA-384 structural hashes, and the per-symbol audit entries.

No token flag. No manual step. The proof is issued on a clean merge — a chain of custody presentable to a SOC 2 auditor, a regulator, or an incident response team. Not a log. A bond.

### SLSA Level 4 Reproducible Builds

Every release binary is built with deterministic compiler flags and verified via Docker-based dual-build comparison — proving bit-for-bit identity across independent build environments. Supply chain integrity is not a claim. It is a proof.

### Jira ASPM Integration

Native Jira sync with fingerprint-based deduplication. The first bounce creates a Jira issue; subsequent bounces with the same structural fingerprint skip creation. Credential preflight validates environment before sync, gracefully degrading to local-only operation when Jira is unavailable.

### Native Multi-SCM Support

Commit-status publishing for **GitHub**, **GitLab**, and **Azure DevOps** — auto-detected from CI environment variables. No additional configuration required beyond standard CI tokens.

### Zero-Friction GitHub Integration

![Janitor Sentinel Demo](assets/sentinel_demo.webp)

*Janitor Sentinel automatically downgrades vetoes when it detects safe patterns (e.g., Dependabot).*

### Datacenter Sustainability

By intercepting structural slop at the AST level, The Janitor prevents wasted CI/CD cycles, reclaiming kilowatt-hours of grid capacity from agentic churn. Every actionable intercept eliminates one CI run that would have consumed approximately **0.1 kWh** of datacenter energy. The cumulative energy ledger is tracked per-repository in the Workslop report under **CI Energy Reclaimed**.

---

## THE SHADOW AI CRISIS

Forrester's 2025 AI Developer Tools survey established a number that should alarm every CISO: **78% of developers use AI coding tools regardless of corporate policy.** Shadow AI is not a fringe phenomenon. It is the operating condition.

The standard corporate response — policy memos, access controls, approval workflows — fails for a structural reason: the gap between writing code and merging it has collapsed. A developer who pastes a function from ChatGPT and commits it has bypassed every review control designed for a human contributor typing in an IDE.

**The Janitor is the only Hard-Point Defense that operates at the runner level.**

It does not audit the developer's tool selection. It is not a training module. It is a circuit breaker installed at the single point where all code — whether AI-generated, AI-assisted, or human-authored — must pass before it enters the main branch: the pull request gate.

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

The Janitor is the opposite architecture. It is an **on-device structural firewall** — a Rust binary that memory-maps your diffs, applies deterministic analysis, and exits. No network call during the analysis path. No cloud ingestion. No LLM. Proven at **3.5 million lines in 33 seconds on an 8 GB laptop**. Your code never leaves your runner.

Cloud fabrics are an exfiltration vector wearing a security badge. The Janitor eliminates the attack surface instead of adding to it.

### Deterministic vs. Heuristic

LLM-based code review tools cannot *prove* anything. They pattern-match against training distributions and emit confidence scores. A sufficiently novel adversarial input — a well-structured but semantically dangerous diff — is invisible to a heuristic system trained on pre-AI codebases.

The Janitor does not guess. It uses **tree-sitter ASTs to prove structural identity**, **BLAKE3 hashing to prove clone equivalence**, **MinHash Jaccard to prove Swarm coordination**, and **Dual-PQC (ML-DSA-65 FIPS 204 + SLH-DSA FIPS 205) to prove chain of custody**. The gate either passes or it does not. There is no confidence interval. There is no false-positive budget. There is a proof — or the PR is blocked.

When a PR clears the gate, Janitor Sentinel issues a CycloneDX v1.6 CBOM: a cryptographically signed bill of materials covering every hash, every symbol, every decision point in the analysis. That is not a report. That is a bond you can present to a SOC 2 auditor.

### The Doorman Fallacy

A Doorman checks if you are wearing shoes. He does not x-ray your briefcase.

Lightweight linters — ESLint, Pylint, Clippy — check if a PR compiles and conforms to style guides. They are Doormen. They operate on the surface: syntax, formatting, known CVE patterns. They do not do what The Janitor does.

The Janitor conducts a **structural autopsy**. It maps the reference graph, hashes every function body with BLAKE3, runs a MinHash Jaccard swarm collision check across your entire PR history, and issues a Dual-PQC signed cryptographic bond for every clean merge.

**You need a tool that uses 60 MB of RAM to guarantee FIPS 204 + FIPS 205 provenance.**

### Agentic-Ready

The threat model is already changing. AI coding assistants are becoming autonomous agents — systems that open PRs without human authorship, coordinate across accounts, and submit structurally identical changes at a rate no human review queue can absorb. Copilot is the training run. The Swarm is the production workload.

The Janitor was built for this environment. **It is the deterministic enforcement gate that applies your architectural rules to non-human developers** — the same rules, at the same threshold, regardless of whether the author is a human engineer, a Copilot agent, or an autonomous Swarm.

When your team deploys AI engineers, the gate does not move.

---

## GOOGLE-READY PQC ATTESTATION

Google announced in early 2026 that all internal cryptographic operations must be quantum-safe ahead of schedule. **NIST FIPS 204 (ML-DSA-65)** and **NIST FIPS 205 (SLH-DSA-SHAKE-192s)** are the mandated post-quantum standards.

Every **CycloneDX v1.6 CBOM** issued by Janitor Sentinel is signed with **Dual-PQC** today.

| Claim | Implementation |
|---|---|
| Signature algorithm | **Dual-PQC**: ML-DSA-65 (FIPS 204) + SLH-DSA-SHAKE-192s (FIPS 205) |
| Audit hash algorithm | **SHA-384** (FIPS 180-4) for ledger integrity; **BLAKE3** for structural clone hashing |
| Format | **CycloneDX v1.6 CBOM** — Cryptography Bill of Materials |
| Issuance trigger | Clean merge — automatic, no token flag or manual step |
| Build provenance | **SLSA Level 4** — bit-for-bit reproducible release binaries |
| Audit target | SOC 2 Type II, NIST CSF 2.0, FedRAMP High, DoD IL5/IL6 |

Your compliance artifacts are **ahead of the mandate**. Every PR that clears the Janitor gate today produces a quantum-safe attestation bond — a chain of custody you will not need to retrofit later.

**The only Dual-PQC-signed CBOM that fires automatically on every clean PR merge. No configuration. No certificate authority. No migration project.**

---

## DEFEATING AUTONOMOUS PR TAMPERING

On **March 24, 2026**, GitHub rolled out a feature that allows any repository maintainer to assign an open pull request directly to Copilot for autonomous modification. Copilot then reads the PR, plans changes, and pushes commits — without a human writing a single line.

**The Janitor applies a mandatory +50 point AgenticOrigin surcharge to every PR where Copilot coding agent activity is detected:**

| Detection signal | Trigger |
|---|---|
| PR author is `copilot[bot]` or `github-copilot[bot]` | Author field matches Copilot coding agent handles |
| PR author is `app/copilot` or `app/github-copilot` | GitHub App prefix format |
| PR body contains `Co-authored-by: Copilot` trailer | Copilot pushed commits onto a human-authored PR |

The +50 surcharge means a Copilot-modified PR must be **structurally flawless** to pass the default 100-point gate. A structurally clean Copilot PR scores 50 and passes. **The gate enforces a higher bar, not a blanket block.**

---

## GROUND TRUTH VS. THE VIBE RADAR

The market has a new category: **Vibe Radar**. These are tools that use LLMs to review pull requests, describe what the code does, and emit an opinion. The opinion sounds authoritative. It is probabilistic. It cannot be audited. It cannot be reproduced.

**The Janitor is not a Vibe Radar. It is a proof system.**

| Property | Vibe Radar (LLM review) | The Janitor (AST structural firewall) |
|:---|:---:|:---:|
| Output type | Probabilistic opinion | Deterministic proof |
| Reproducible verdict | No — model non-determinism | Yes — same diff, same score, always |
| Detects phantom hallucinations | No | Yes — `security:phantom_hallucination` cross-references base registry |
| Detects Swarm coordination | No | Yes — MinHash LSH at Jaccard ≥ 0.85 across full PR history |
| Source code egress | Yes — sent to inference cluster | No — memory-mapped on your runner |
| Auditable | No | Yes — SHA-384 ledger, Dual-PQC signed CBOM, policy hash |
| Speed | 2–8 minutes per PR | Under 33 seconds for 3.5M-line repos |

**The Vibe Radar tells you what it thinks. The Janitor tells you what it proved.**

---

## THE MAINTAINER SHIELD

Open-source maintainers are experiencing **death by a thousand slops**.

AI-assisted development increased per-engineer PR output by **4–6×**. On a team of 10 engineers, that is 400 inbound PRs per day against a human review capacity of 80. The backlog grows by 320 PRs every 24 hours. It never clears. It compounds.

**The 100-point Slop Gate is the definitive defense.**

| Signal | Weight | What it stops |
|:-------|:------:|:--------------|
| Logic clones detected | ×5 | Structurally identical implementations — the context-bloat signature |
| Zombie symbols reintroduced | ×10 | Previously deleted symbols returning via AI copy-paste |
| Language antipatterns | ×50 | Hallucinated imports, unsafe blocks, injection vectors |
| Unlinked PR | ×20 | Agent PRs that bypass issue-tracking hygiene |
| AgenticOrigin surcharge | +50 flat | Autonomous coding agents held to a zero-defect structural standard |

The gate is not a reviewer. It is a circuit breaker. When the queue is 400 PRs deep, the circuit breaker is not optional.

**The Slop Gate moves with the threat. When your team deploys AI engineers, the gate does not move.**

---

## ENTERPRISE INTEGRATIONS

Every bounce event that trips the threat threshold fires an outbound webhook — signed with **HMAC-SHA256**:

```
X-Janitor-Signature-256: sha256=<hex>
X-Janitor-Event: critical_threat | necrotic_flag
```

| Platform | How |
|---|---|
| **Slack** | Incoming Webhooks app → paste URL into `janitor.toml` `[webhook]` block |
| **Microsoft Teams** | Workflows connector → POST to Teams channel webhook URL |
| **Datadog** | Datadog HTTP Logs API endpoint |
| **Splunk** | Splunk HTTP Event Collector |
| **Jira** | Native ASPM sync with fingerprint deduplication |
| **Any SIEM** | Any HTTPS endpoint that accepts a POST with a JSON body |

```toml
# janitor.toml
[webhook]
url    = "https://hooks.slack.com/services/T.../B.../..."
secret = "env:JANITOR_WEBHOOK_SECRET"
events = ["critical_threat", "necrotic_flag"]
```

See the [setup documentation](setup.md#webhook-sub-table) for the full `[webhook]` field reference.

---

## ECONOMICS

**The enforcement is free. The attestation is the product.**

| Tier | Cost | What You Get |
|:-----|:-----|:-------------|
| **Free** | $0 | Unlimited scan, clean, dedup, bounce, dashboard, report. No signed logs. |
| **[Team](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348)** | **$499/yr** | All free features + Dual-PQC Integrity Bonds (ML-DSA-65 + SLH-DSA) + CycloneDX v1.6 CBOMs + CI/CD Compliance Attestation + Janitor Sentinel GitHub App. No per-seat limits. |
| **Sovereign / Air-Gap** | **Custom (Starting at $49,900/yr)** | Everything in Team + SLSA Level 4 reproducible builds + Wasm BYOR rule mounting + Offline Decision Capsules + Air-Gap Intel Transfers + Jira ASPM dedup + Native SCM (GitLab, AzDO) + SOC 2 Type II packages + Dedicated SLA. |
| **[Industrial](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7)** | **Custom** | On-Premises Token Server + Keypair Rotation Protocol + SOC 2 Audit Support + Enterprise SLA. No per-seat limits. |

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
| **Dual-PQC Signed Audit Logs** | — |
| **CI/CD Compliance Attestation** | — |
| **Janitor Sentinel** (GitHub App automation) | — |

### Team Specialist — $499 / year

Includes all Free tier capabilities, plus:

| Capability | Included |
|:-----------|:--------:|
| **Dual-PQC Signed Audit Logs** — ML-DSA-65 (FIPS 204) + SLH-DSA (FIPS 205) | ✓ |
| **CI/CD Compliance Attestation** — `--token` flag activates signed reports in CI | ✓ |
| **Janitor Sentinel** — GitHub App that runs `janitor bounce` on every PR | ✓ |
| **Shared Credit Pool** — team-level token across all CI runners | ✓ |
| **No per-seat limits** — run on every developer machine and CI runner under one license | ✓ |

[**Activate — $499/yr →**](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348)

### Sovereign / Air-Gap — Starting at $49,900 / year

Includes all Team capabilities, plus:

- **SLSA Level 4 Reproducible Builds** — bit-for-bit deterministic release binaries with Docker verification
- **Dual-PQC CycloneDX v1.6 CBOMs** — ML-DSA-65 + SLH-DSA signed Software Bills of Materials
- **Wasm BYOR Rule Mounting** — private governance modules with BLAKE3 integrity pinning
- **Offline Replayable Decision Capsules** — tamper-evident audit replay without network access
- **Air-Gap Intel Transfers** — SHA-384 + Ed25519 signed wisdom bundles for IL5/IL6 environments
- **Jira ASPM Sync** — fingerprint-based deduplication with credential preflight
- **Native SCM Publishing** — GitLab + Azure DevOps commit-status verdicts
- **SOC 2 Type II attestation packages** on request
- **Dedicated SLA** — 4-hour emergency rotation SLA for confirmed compromises

[**Contact sales → sales@thejanitor.app**](mailto:sales@thejanitor.app)

### Industrial Core — Custom

Includes all Sovereign capabilities, plus:

- **On-Premises Token Server** — dedicated verifying key for air-gapped deployments
- **Keypair Rotation Protocol** — satisfies SOC 2 Type II change-management requirements
- **Enterprise SLA** — 4-hour emergency rotation SLA for confirmed compromises
- **No per-seat limits** — one organization license covers all developers and CI runners

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

<!-- Keywords: AI Security Firewall, Zero-Upload SAST, PQC CBOM, Structural AST Analysis, FedRAMP High, DoD IL6, Vibe Coding Defense, AI Pull Request Gate, Supply Chain Attack Detection, Swarm Detection, Dead Symbol GC, SLSA Level 4, Reproducible Builds, Dual-PQC, ML-DSA-65, SLH-DSA, CycloneDX CBOM, SARIF Security Report, Zombie Dependency Scanner, Jira ASPM -->
