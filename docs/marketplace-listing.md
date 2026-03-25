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

## Introductory Description (415 chars)

Janitor Sentinel is a zero-upload structural firewall for AI-generated PRs. The engine runs entirely on your GitHub Actions runner; source code never leaves your infrastructure. The Governor receives scores, not code. Each PR is evaluated against 23 languages using tree-sitter AST analysis, MinHash clone detection, and NCD entropy gates. Findings surface as GitHub Check Runs and inline SARIF annotations.

---

## Detailed Description (1,680 chars)

## Capabilities
- **Zero-Upload:** Scan code locally on your runner. Only metadata reaches the cloud.
- **Structural Detection:** 50+ AST antipatterns (gets/strcpy, open CIDR, innerHTML) across 23 languages.
- **AI Swarm Interception:** MinHash LSH identifies structural clones across multiple authors.
- **Bot Defense:** Calibrated NCD gates detect machine-generated boilerplate verbosity.
- **Zombie Deps:** Scans manifests for previously removed dependencies resurfacing.

## Benefits
- **CISO Approved:** Code never leaves your secure boundary. Governor is stateless.
- **Zero Noise:** Math-based proof, no regex guessing. No false positives on bot accounts.
- **8GB Law Performance:** Scans 3.5M LOC in <33s on standard hardware.

## Getting Started
**Plan:** Team Tier ($499/yr) at thejanitor.app. Marketplace listing is Free.
**Permissions:** Requires `security_events: write` for inline alerts.

```yaml
- uses: janitor-security/the-janitor@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    installation_id: ${{ vars.JANITOR_INSTALLATION_ID }}
```

## Example Findings
- `security:unsafe_string_function` — gets() detected (line 4).
- `security:compiled_payload` — cryptominer URI detected (line 5).
- `architecture:zombie_dep` — package 'log4j' resurfaced.

## The Proof
Audited 33,000+ PRs across 22 enterprise repos (Kubernetes, NixOS, Godot).

## Pricing
- **Janitor CLI (Free):** Core engine on your runner. Uncapped.
- **Team Tier ($499/yr):** Sentinel governance, PQC CBOM bonds, and org-wide policy. Available directly at https://thejanitor.app.

---

## Screenshot Manifest

Four screenshots required for Marketplace submission:

1. **Failure Case** — PR Check Run: "Janitor: Code Quality Gate Failed" with rule IDs, threat class, and score formula.
2. **Success Case** — PR Check Run: "Janitor: Clean — PQC Bond Issued" with integrity score at zero.
3. **SARIF Annotations** — PR diff view with inline Code Scanning annotations (e.g. `gets()` or open-CIDR rule highlighted in the diff gutter).
4. **janitor.toml Policy** — Repository `janitor.toml` in the GitHub file browser showing `min_slop_score`, `require_issue_link`, and automation exemptions.

---

## Links

- **Source**: https://github.com/janitor-security/the-janitor
- **Documentation**: https://thejanitor.app/docs
- **Governance**: https://thejanitor.app/governance
- **Privacy**: https://thejanitor.app/privacy
- **Terms**: https://thejanitor.app/terms
- **Support**: sales@thejanitor.app
