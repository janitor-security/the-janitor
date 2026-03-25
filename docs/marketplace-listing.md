# GitHub Marketplace Listing Content

> Not in MkDocs nav — content asset only. Copy-paste into GitHub Marketplace listing form.

---

## Metadata

- **Category (Primary)**: Security
- **Category (Secondary)**: AI Assisted
- **Support Contact**: sales@thejanitor.app
- **Source Repository**: https://github.com/janitor-security/the-janitor

---

## Short Description (120 chars max)

Free structural firewall for AI-generated PRs. Detects security antipatterns and zombie deps. Your code never leaves your runner.

---

## Introductory Description

Janitor Sentinel is a zero-upload structural firewall for AI-generated pull requests.
The Janitor engine runs entirely inside your own GitHub Actions runner — your source
code never leaves your infrastructure. The Governor backend receives only a scored
analysis result, not your code.

Every pull request is evaluated against 23 programming languages using tree-sitter
AST analysis, MinHash clone detection, and entropy-based anomaly classification.
Findings are surfaced as a GitHub Check Run and inline SARIF annotations in the PR diff.

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

### Capabilities

**Security antipattern detection** — named rules, not heuristics:

- C/C++: `gets()`, `strcpy()`, `sprintf()`, `scanf()` — buffer overflow families
- YAML: wildcard `hosts: ["*"]` in VirtualService / Ingress / HTTPRoute / Gateway
- HCL/Terraform: open CIDR `0.0.0.0/0` in ingress rules; S3 public ACL grants
- Python: `subprocess(..., shell=True)` — shell injection vectors
- JavaScript/TypeScript: `innerHTML` assignment sinks

**Swarm clone detection** — MinHash LSH (8 bands × 8 rows) identifies PRs sharing
≥85% structural AST similarity. Flags AI-generated patch floods before they merge.

**NCD verbosity gate** — zstd compression ratio detects machine-generated boilerplate.
A patch that compresses to <15% of its original size is flagged as a verbosity bomb.

**Zombie dependency detection** — scans `Cargo.toml`, `package.json`,
`requirements.txt`, and `go.mod` for dependencies previously removed and being
re-introduced.

**Entropy anomaly classification** — `ByteLatticeAnalyzer` flags blobs with entropy
outside the natural code range (2.0–5.5 bits/byte) without requiring grammar support.
Language-agnostic binary and generated-code detection.

**23-language AST support** — Rust, Python, JavaScript, TypeScript, Go, C, C++, Java,
Ruby, PHP, Lua, Nix, Swift, Scala, C#, HCL, YAML, Bash, and more via tree-sitter.

### Benefits

- **Zero-upload privacy** — your source code is never transmitted to any third-party
  server. The engine runs on your runner; the Governor receives only the score.
- **No per-seat limits** — the free CLI tier is uncapped. Scan every PR in every repo.
- **Stateless by design** — the Governor resolves the Check Run via the GitHub API on
  every report. No in-memory state, no race conditions on deploy.
- **Policy as code** — drop a `janitor.toml` at the repository root. Score threshold,
  issue-link requirements, refactor bonuses, and automation account exemptions are all
  version-controlled alongside the code they govern.
- **Instant SARIF integration** — findings appear as inline Code Scanning annotations
  in the PR diff with no additional configuration.

### Getting Started

1. Install the action from the GitHub Marketplace.
2. Add the workflow to your repository:

```yaml
name: Janitor Firewall
on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: read
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: janitor-security/the-janitor@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          installation_id: ${{ vars.JANITOR_INSTALLATION_ID }}
```

3. The engine builds from source on your runner, extracts the PR diff, and POSTs the
   scored result to the Governor. The Governor issues the "Janitor Integrity Check"
   Check Run on the PR.

For Team Tier governance (automated Check Run gating, CBOM bonding, org-wide policy),
see https://thejanitor.app.

### Example Findings

**Security: buffer overflow vector (C)**
```
antipattern:security:c_gets — gets() detected in src/io/reader.c:47
Score contribution: +50 pts | Threat class: Critical
```

**IaC: open ingress (Terraform)**
```
antipattern:security:open_cidr — 0.0.0.0/0 ingress in infra/sg.tf:23
Score contribution: +50 pts | Threat class: Critical
```

**Zombie dependency (Cargo.toml)**
```
zombie:dep:openssl — previously removed dependency re-introduced
Score contribution: +10 pts
```

**Swarm clone (structural similarity)**
```
clone:ast_similarity — PR shares 91% AST topology with PR #4821
Score contribution: +5 pts per clone pair
```

### The Proof

33,000+ PRs audited across 22 enterprise repositories in the gauntlet corpus:
Godot Engine, NixOS/nixpkgs, Kubernetes, VSCode, PyTorch, Apache Kafka, rust-lang/rust,
Tauri, Redis, Next.js, Home Assistant, Ansible, Cloudflare Workers SDK, LangChain, Deno,
Rails, Laravel, Apple/Swift, ASP.NET Core, OkHttp, Terraform, Neovim.

In the Godot Engine audit: 82% of human-authored PRs were unlinked (no issue reference).
In NixOS/nixpkgs: the automation shield correctly classified all `r-ryantm` and NixOS CI
bot PRs as automation — zero false positives against 32 consecutive bot PRs.

Scans 3.5M LOC in <33 seconds on a 2019 Dell Inspiron with 8 GB RAM.

---

## Pricing

**The Marketplace listing is free.** The Janitor CLI installs at no cost with no usage
limits and no per-seat fees. The full firewall engine — AST analysis, security
antipattern detection, zombie dependency scanning, clone detection — runs on your own
runner indefinitely.

**Team Tier ($499/yr)** is available directly at
[https://thejanitor.app](https://thejanitor.app). It unlocks:

- Automated Sentinel governance via the Governor backend
- GitHub Check Run gating (pass/fail on the PR)
- Inline SARIF Code Scanning annotations
- CycloneDX v1.5 CBOM attestation bonds (PQC-signed)
- `janitor.toml` policy-as-code enforcement across your organization
- Email support

| Tier | Price | What you get |
|---|---|---|
| **Janitor CLI** | **Free** | Core firewall engine on your runner. No limits. |
| **Team Tier** | $499/yr via [thejanitor.app](https://thejanitor.app) | Governor backend, Check Run gating, SARIF, CBOM bonds, org policy |

---

## Screenshot Manifest

Four screenshots are required for the Marketplace submission:

1. **Failure Case** — A PR Check Run showing "Janitor: Code Quality Gate Failed" with
   the full integrity summary: antipatterns detected (by rule ID), threat classification
   (Critical / Necrotic / Boilerplate), and the score formula breakdown.

2. **Success Case** — A PR Check Run showing "Janitor: Clean — PQC Bond Issued" with
   the integrity score at zero and the Vouch Identity Verified banner confirming the
   CycloneDX attestation bond was issued.

3. **SARIF Code Scanning Annotations** — The GitHub PR diff view showing inline Code
   Scanning annotations from Sentinel (e.g. a `gets()` finding or an open-CIDR rule
   highlighted in the diff gutter with the rule ID and remediation hint).

4. **janitor.toml Policy-as-Code** — A repository's `janitor.toml` open in the GitHub
   file browser, showing the policy configuration committed alongside the code it
   governs: `min_slop_score`, `require_issue_link`, automation account exemptions.

---

## Links

- **Source**: https://github.com/janitor-security/the-janitor
- **Documentation**: https://thejanitor.app/docs
- **Governance**: https://thejanitor.app/governance
- **Privacy**: https://thejanitor.app/privacy
- **Terms**: https://thejanitor.app/terms
- **Support**: sales@thejanitor.app
