# GitHub Marketplace Listing Content

> Not in MkDocs nav — content asset only. Copy-paste into GitHub Marketplace listing form.

---

## Short Description (120 chars max)

Free structural firewall for AI-generated PRs. Detects security antipatterns and zombie deps. Your code never leaves your runner.

---

## Full Description

### The Problem

AI-assisted development has fundamentally changed the pull request economy. Tools like
Copilot, Cursor, and Claude produce syntactically valid code that passes linting and
compiles without warnings — but carries hidden structural defects. Security antipatterns
slip through. Functions are copy-pasted across fifty PRs from the same swarm. Dead
dependencies resurface. None of this is caught by GitHub Actions workflows, status
checks, or human reviewers who are moving at AI speed.

The result: technical debt that compounds silently, security antipatterns that land in
main, and a review process that is theatre rather than substance.

### What Janitor Sentinel Does

Sentinel is a **zero-upload** structural firewall. The Janitor engine runs entirely
inside your own GitHub Actions runner — your source code never leaves your infrastructure.
The Governor (Sentinel's backend) only receives a scored analysis result, not the code.

Each PR is evaluated using a zero-disk-checkout merge simulation against the actual diff
— not the full file — across 23 programming languages using tree-sitter AST analysis.

**Security antipatterns** are detected by name:

- C: `gets()`, `strcpy()`, `sprintf()`, `scanf()` — buffer overflow families
- YAML: wildcard `hosts: ["*"]` in VirtualService/Ingress/HTTPRoute/Gateway
- HCL/Terraform: open CIDR `0.0.0.0/0` in ingress rules
- Python: `subprocess(..., shell=True)` injection vectors
- JavaScript/TypeScript: `innerHTML` assignment sinks
- AWS: S3 public ACL grants

**Swarm clone detection** uses MinHash LSH (8 bands × 8 rows) to find PRs that share
≥85% structural similarity — the fingerprint of AI-generated patch floods where dozens
of contributors submit nearly identical changes.

**NCD verbosity gate** uses zstd compression to detect machine-generated boilerplate:
if a patch compresses to <15% of its original size, it is flagged as a verbosity bomb.

**Zombie dependency detection** scans Cargo.toml, package.json, requirements.txt, and
go.mod for dependencies that were previously removed and are being re-introduced.

**What the developer sees**: a GitHub Check Run with the Integrity Score, inline PR
annotations via Code Scanning (GHAS), and a CycloneDX v1.5 CBOM bond signed with
ML-DSA-65 (FIPS 204) for every clean PR.

**Policy control**: drop a `janitor.toml` at the repository root to configure the score
threshold, issue-link requirements, refactor bonuses, and automation account exemptions.
See the [governance documentation](https://thejanitor.app/governance).

### The Proof

33,000+ PRs audited across 22 enterprise repositories in the gauntlet corpus:
Godot Engine, NixOS/nixpkgs, Kubernetes, VSCode, PyTorch, Apache Kafka, rust-lang/rust,
Tauri, Redis, Next.js, Home Assistant, Ansible, Cloudflare Workers SDK, LangChain, Deno,
Rails, Laravel, Apple/Swift, ASP.NET Core, OkHttp, Terraform, Neovim.

In the Godot Engine audit: 82% of human-authored PRs were unlinked (no issue reference).
In NixOS/nixpkgs: the full automation shield correctly classified all `r-ryantm` and
NixOS CI bot PRs as automation — zero false positives against 32 consecutive bot PRs.

Scans 3.5M LOC in <33 seconds on a 2019 Dell Inspiron with 8GB RAM. This is not a
cloud-scale service pretending to be a developer tool. It runs on the hardware you own.

### Pricing

**The Janitor CLI is free.** Install it from the GitHub Marketplace at no cost.
The core firewall engine — AST analysis, security antipattern detection, zombie
dependency scanning, clone detection — runs entirely on your own runner with no
usage limits and no per-seat fees.

**Janitor Sentinel (Enterprise)** is available directly at
[https://thejanitor.app](https://thejanitor.app) for teams that need the
Governor backend: centralized Check Run gating, SARIF Code Scanning integration,
CycloneDX CBOM attestation bonds, and `janitor.toml` policy-as-code enforcement
across an organization.

| Tier | Price | What you get |
|---|---|---|
| **Janitor CLI** | **Free** | Core firewall engine on your runner. No limits. |
| **Sentinel Enterprise** | $499/yr (via [thejanitor.app](https://thejanitor.app)) | Governor backend, Check Run gating, SARIF, CBOM bonds, org policy |

No per-seat limits at either tier.

---

## Screenshots Required

The following four screenshots need to be captured before submitting to the Marketplace:

1. **Check Run — failure case**: A PR check run showing "Janitor: Code Quality Gate
   Failed" with the full integrity summary (antipatterns found, score formula, threat
   classification).

2. **Check Run — success case**: A PR check run showing "Janitor: Clean — PQC Bond
   Issued" with the Vouch Identity Verified banner (if applicable).

3. **Code Scanning annotations (SARIF)**: The GitHub PR diff view showing inline SARIF
   annotations from Sentinel (e.g. a `gets()` or open-CIDR finding highlighted in the
   diff gutter).

4. **janitor.toml policy-as-code**: A repository's `janitor.toml` in the GitHub UI,
   showing the policy-as-code configuration committed alongside the code it governs
   (score threshold, issue-link requirement, automation account exemptions).
