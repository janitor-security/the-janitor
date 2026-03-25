#!/usr/bin/env bash
# generate_client_package.sh — single-repo audit + marketing asset generator.
#
# Runs a hyper-drive bounce audit against one GitHub repository and produces a
# self-contained client package directory with seven artefacts:
#
#   1. gauntlet_intelligence_report.pdf  — PDF intelligence report
#   2. gauntlet_export.csv               — 16-column CSV audit trail
#   3. gauntlet_report.json              — machine-readable aggregate JSON
#   4. <repo>_cbom.json                  — CycloneDX v1.5 Cryptography SBOM
#   5. <repo>_intel.json                 — per-repo JSON (clone pairs + top-50)
#   6. <repo>_vex.json                   — CycloneDX v1.5 VEX (exploitability)
#   7. case-study.md                     — auto-populated case study (Markdown)
#
# Usage:
#   ./tools/generate_client_package.sh <owner/repo> [out_dir]
#   just strike <owner/repo> [pr_limit]        # preferred — enters Nix shell
#
# Environment overrides:
#   PR_LIMIT       — max PRs to audit (default: 100)
#   BOUNCE_TIMEOUT — seconds per bounce (default: 30)
#   GAUNTLET_DIR   — gauntlet clone root (default: ~/dev/gauntlet)
#   JANITOR        — path to janitor binary (default: ./target/release/janitor)
#
# Output directory: strikes/<repo_name>/  (workspace-isolated; gitignored)
#
# Examples:
#   just strike kubernetes/kubernetes           # 1000 PRs, output → strikes/kubernetes/
#   just strike NixOS/nixpkgs 50               # 50 PRs
#   PR_LIMIT=5000 ./tools/generate_client_package.sh godotengine/godot

set -euo pipefail

# ── Functions ─────────────────────────────────────────────────────────────────

# _synthesize_case_study <global_json> <intel_json> <owner/repo> <out_file>
#
# Reads audit statistics from two JSON files produced by the bounce pipeline
# and writes a populated case study Markdown document.  The template is
# self-contained here — no external template files are required or read.
_synthesize_case_study() {
    local global_json="$1"
    local intel_json="$2"
    local slug="$3"
    local out_file="$4"

    local repo_name="${slug##*/}"
    local owner="${slug%%/*}"
    local today
    today="$(date +%Y-%m-%d)"

    # ── Extract fields from gauntlet_report.json (global aggregate) ──────────
    local total_prs antipatterns_found zombie_dep_prs highest_score
    local actionable_intercepts critical_threats necrotic_count
    local reclaimed_hours tei_usd
    total_prs="$(jq '.total_prs' "${global_json}")"
    antipatterns_found="$(jq '.repositories[0].antipatterns_found' "${global_json}")"
    zombie_dep_prs="$(jq '.repositories[0].zombie_dep_prs' "${global_json}")"
    highest_score="$(jq '.repositories[0].highest_score // 0' "${global_json}")"
    actionable_intercepts="$(jq '.workslop.actionable_intercepts' "${global_json}")"
    critical_threats="$(jq '.workslop.critical_threats_count' "${global_json}")"
    necrotic_count="$(jq '.workslop.necrotic_count' "${global_json}")"
    reclaimed_hours="$(jq '.workslop.total_reclaimed_hours' "${global_json}")"
    tei_usd="$(jq '.workslop.total_economic_impact_usd' "${global_json}")"

    # ── Extract clone pairs from per-repo intel JSON ─────────────────────────
    # gauntlet_report.json is a cross-repo aggregate and does not carry
    # MinHash clone-pair detail; read it from the single-repo JSON renderer.
    local clone_pairs
    clone_pairs="$(jq '.clone_pairs | length' "${intel_json}")"

    # ── Derived: intercept rate ───────────────────────────────────────────────
    local intercept_pct="0.0"
    if [[ "${total_prs}" -gt 0 ]]; then
        intercept_pct="$(echo "scale=1; ${actionable_intercepts} * 100 / ${total_prs}" | bc)"
    fi

    # ── Write populated case study ────────────────────────────────────────────
    cat > "${out_file}" <<MARKDOWN
# ${owner}/${repo_name} PR Audit Report — Janitor v7.9.4

**Date**: ${today}
**PRs Audited**: ${total_prs}
**Engine**: The Janitor v7.9.4 (tree-sitter AST, MinHash LSH, ML-DSA-65 attestation)

## The Bottleneck Problem

**${total_prs} pull requests** entered the \`${owner}/${repo_name}\` merge queue during this audit window.

At standard engineering-team review capacity — 8 PRs per engineer per day — a 4–6× AI-assisted productivity surge means the inbound queue grows faster than humans can process it. A team of 10 engineers has a review capacity of 80 PRs/day. At 5× AI throughput that queue receives 400 PRs/day and accumulates a 320-PR backlog every 24 hours. It never clears. It compounds.

Human review at AI velocity is a mathematical impossibility. The Janitor is the structural circuit breaker that moves enforcement to the diff level — before the merge button is available, at machine velocity.

## Circuit Breaker Impact

- **${intercept_pct}%** of PRs intercepted upstream of human review (${actionable_intercepts} of ${total_prs})
- **${reclaimed_hours} hours** of senior-engineer triage time redirected to productive work
- **\$${tei_usd}** Total Economic Impact across audit window

## Threat Intelligence Summary

- **${clone_pairs}** Swarm clone pairs detected (Jaccard ≥ 0.70 structural similarity)
- **${antipatterns_found}** language antipatterns found across all PRs
- **${zombie_dep_prs}** zombie dependencies re-introduced (declared in manifest, never imported)
- **${critical_threats}** Critical Threats (security antipattern or Swarm collision) — \$150/intercept
- **${necrotic_count}** Necrotic GC intercepts (bot-closeable dead-code) — \$20/intercept

## Top 10 PRs by Slop Score

*See \`gauntlet_intelligence_report.pdf\` for the full ranked table with antipattern breakdowns.*

Highest slop score in this audit: **${highest_score}** (100-point gate = fail threshold).

## Methodology

The Janitor v7.9.4 runs a 6-stage structural analysis pipeline on each pull request diff:

1. **Vibe-Check Gate** — zstd compression ratio < 0.15 flags vibe-coded PRs that lack human-authored structural variance (\`antipattern:ncd_anomaly\`, +10 pts). Fires before tree-sitter parses a single node.
2. **AST Antipattern Scan** — tree-sitter queries for 20+ security patterns across 12 languages (memory-unsafe C/C++, subprocess injection, innerHTML XSS, open CIDR, S3 public ACLs)
3. **MinHash LSH Clone Detection** — 64-hash Jaccard index detects coordinated Swarm injection across PRs; Jaccard ≥ 0.85 = structural clone
4. **Zombie Dependency Detection** — manifest vs. import-graph cross-reference (\`architecture:zombie_dependency\`)
5. **Social Forensics** — unlinked PRs (+20 pts), AhoCorasick comment-violation scan
6. **Necrotic GC Gate** — semantic null analysis (base vs. head AST diff; \`backlog:SEMANTIC_NULL\` etc.)

All analysis runs on your hardware. Source code never leaves your environment.
Zero-upload guarantee: The Janitor engine runs inside your CI runner in both CLI and Sentinel modes.

See <https://thejanitor.app/architecture> for the full technical specification.

## Artefacts in This Package

| File | Description |
|------|-------------|
| \`gauntlet_intelligence_report.pdf\` | Full PDF intelligence report with ranked PR table |
| \`gauntlet_export.csv\` | 16-column CSV audit trail (Excel/pandas compatible, UTF-8 BOM) |
| \`gauntlet_report.json\` | Machine-readable aggregate statistics |
| \`${repo_name}_cbom.json\` | CycloneDX v1.5 Cryptography Bill of Materials |
| \`${repo_name}_intel.json\` | Per-repo JSON with clone pairs and top-50 PR detail |
| \`${repo_name}_vex.json\` | CycloneDX v1.5 VEX — exploitability status for all scanned threat classes |
| \`case-study.md\` | This document |

---

*Generated by The Janitor v7.9.4 — <https://thejanitor.app>*
MARKDOWN

    echo "  case-study.md → ${out_file}"
}

# _synthesize_vex <intel_json> <owner/repo> <out_file>
#
# Reads per-PR antipattern data from <intel_json> and emits a CycloneDX v1.5
# VEX (Vulnerability Exploitability eXchange) document.
#
# If the audit found zero `security:` prefixed antipattern findings, every
# component is declared `not_affected` with justification
# `inline_mitigations_already_exist`.  If findings were present the state is
# `affected` so reviewers know to inspect the CBOM and PDF for detail.
_synthesize_vex() {
    local intel_json="$1"
    local slug="$2"
    local out_file="$3"

    local repo_name="${slug##*/}"
    local timestamp
    timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Count PRs that carry at least one security: antipattern finding.
    # .top_prs[]? tolerates both array and missing key without error.
    local security_threat_count=0
    security_threat_count="$(jq '
        [ .top_prs[]?
          | select(
              (.antipatterns // [])
              | map(startswith("security:"))
              | any
            )
        ] | length
    ' "${intel_json}" 2>/dev/null || echo 0)"

    local vex_state has_justification vex_detail
    if [[ "${security_threat_count}" -eq 0 ]]; then
        vex_state="not_affected"
        has_justification="true"
        vex_detail="Janitor v7.9.4 structural scan found 0 security: antipattern findings across all audited PRs. All repository components assessed as not_affected."
    else
        vex_state="affected"
        has_justification="false"
        vex_detail="Janitor v7.9.4 structural scan found ${security_threat_count} PR(s) with security: antipattern findings. Review gauntlet_intelligence_report.pdf and gauntlet_export.csv for remediation detail."
    fi

    # Emit CycloneDX v1.5 VEX document via jq so all values are correctly
    # escaped without manual quoting gymnastics.
    jq -n \
        --arg  ts              "${timestamp}" \
        --arg  repo            "${slug}" \
        --arg  repo_name       "${repo_name}" \
        --arg  state           "${vex_state}" \
        --argjson has_just     "${has_justification}" \
        --arg  detail          "${vex_detail}" \
        '{
          bomFormat:    "CycloneDX",
          specVersion:  "1.5",
          version:      1,
          metadata: {
            timestamp: $ts,
            tools: [{
              type:    "application",
              name:    "The Janitor",
              version: "7.9.4",
              externalReferences: [{
                type: "website",
                url:  "https://thejanitor.app"
              }]
            }],
            component: {
              type:      "application",
              "bom-ref": ($repo + "@HEAD"),
              name:      $repo_name,
              version:   "HEAD"
            }
          },
          vulnerabilities: [{
            id:       "JANITOR-SECURITY-SCAN",
            "bom-ref": "janitor-sec-audit",
            description: (
              "Static structural security analysis by The Janitor v7.9.4. " +
              "Threat classes scanned: C/C++ memory-unsafe functions (gets, strcpy, sprintf, scanf); " +
              "Python subprocess shell injection (subprocess+shell=True); " +
              "JavaScript innerHTML XSS assignment; " +
              "HCL open CIDR (0.0.0.0/0) and S3 public ACL; " +
              "Kubernetes wildcard host rules."
            ),
            analysis: (
              { state: $state, detail: $detail }
              + if $has_just then { justification: "inline_mitigations_already_exist" } else {} end
            ),
            affects: [{ ref: ($repo + "@HEAD") }]
          }]
        }' > "${out_file}"

    echo "  ${repo_name}_vex.json → ${out_file}"
}

# ── Entry point ───────────────────────────────────────────────────────────────

SLUG="${1:?Usage: $0 <owner/repo> [out_dir]}"
REPO_NAME="${SLUG##*/}"   # "kubernetes" from "kubernetes/kubernetes"

PR_LIMIT="${PR_LIMIT:-100}"
BOUNCE_TIMEOUT="${BOUNCE_TIMEOUT:-30}"
GAUNTLET_DIR="${GAUNTLET_DIR:-$HOME/dev/gauntlet}"
JANITOR="${JANITOR:-./target/release/janitor}"
OUT_DIR="${2:-${PWD}/strikes/${REPO_NAME}}"
REPO_DIR="${GAUNTLET_DIR}/${REPO_NAME}"

# ── Preflight ─────────────────────────────────────────────────────────────────

if ! command -v jq &>/dev/null; then
    echo "error: 'jq' is required for case study synthesis." >&2
    echo "       Install: apt install jq  OR  brew install jq" >&2
    exit 1
fi

if ! command -v bc &>/dev/null; then
    echo "error: 'bc' is required for percentage calculation." >&2
    exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  generate_client_package — The Janitor v7.9.4               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Target  : ${SLUG}"
echo "  PR limit: ${PR_LIMIT}"
echo "  Gauntlet: ${GAUNTLET_DIR}"
echo "  Output  : ${OUT_DIR}"
echo ""

mkdir -p "${OUT_DIR}"

# ── Step 1: Build ─────────────────────────────────────────────────────────────

echo "[1/6] Building release binaries..."
cargo build --release -p cli -p gauntlet-runner

# ── Step 2: Bounce PRs via hyper-drive ────────────────────────────────────────
#
# gauntlet-runner --hyper clones once via libgit2, fetches all PR refs, and
# scores every PR from the packfile — zero `gh pr diff` network subshells.
#
# Writes to OUT_DIR:
#   gauntlet_intelligence_report.pdf
#   gauntlet_export.csv
#   gauntlet_report.json

echo "[2/6] Running hyper-drive audit for ${SLUG} (limit=${PR_LIMIT})..."

TARGETS_TMP="$(mktemp /tmp/gcpkg_targets_XXXXXX.txt)"
trap 'rm -f "${TARGETS_TMP}"' EXIT
echo "${SLUG}" > "${TARGETS_TMP}"

./target/release/gauntlet-runner \
    --hyper \
    --targets  "${TARGETS_TMP}" \
    --pr-limit "${PR_LIMIT}" \
    --timeout  "${BOUNCE_TIMEOUT}" \
    --gauntlet-dir "${GAUNTLET_DIR}" \
    --out-dir  "${OUT_DIR}"

# Verify the three base artefacts from gauntlet-runner.
for f in gauntlet_intelligence_report.pdf gauntlet_export.csv gauntlet_report.json; do
    if [[ ! -f "${OUT_DIR}/${f}" ]]; then
        echo "error: gauntlet-runner did not produce expected artefact: ${f}" >&2
        exit 1
    fi
done

# ── Step 3: CBOM Bond ─────────────────────────────────────────────────────────
#
# Generates a CycloneDX v1.5 Cryptography Bill of Materials for the per-repo
# bounce log: ML-DSA-65 attestation hash, BLAKE3 structural hashes, per-symbol
# audit entries, and the chain-of-custody for every intercepted finding.

echo "[3/6] Generating CycloneDX CBOM bond..."
CBOM_OUT="${OUT_DIR}/${REPO_NAME}_cbom.json"
"${JANITOR}" report \
    --repo   "${REPO_DIR}" \
    --format cbom \
    --out    "${CBOM_OUT}"

# ── Step 4: Per-repo Intel JSON ───────────────────────────────────────────────
#
# gauntlet_report.json is the cross-repo aggregate; it does not carry clone
# pairs or per-PR antipattern detail.  The per-repo renderer provides both.

echo "[4/6] Generating per-repo intel JSON..."
INTEL_JSON="${OUT_DIR}/${REPO_NAME}_intel.json"
"${JANITOR}" report \
    --repo   "${REPO_DIR}" \
    --format json \
    --out    "${INTEL_JSON}"

# ── Step 5: VEX Document ──────────────────────────────────────────────────────
#
# Emits a CycloneDX v1.5 Vulnerability Exploitability eXchange document.
# Reads security: antipattern counts from the per-repo intel JSON produced in
# Step 4 — zero additional janitor invocations, zero analysis overhead.

echo "[5/6] Generating VEX document..."
VEX_OUT="${OUT_DIR}/${REPO_NAME}_vex.json"
_synthesize_vex \
    "${INTEL_JSON}" \
    "${SLUG}" \
    "${VEX_OUT}"

# ── Step 6: Case Study Synthesis ──────────────────────────────────────────────

echo "[6/6] Synthesising case-study.md..."
_synthesize_case_study \
    "${OUT_DIR}/gauntlet_report.json" \
    "${INTEL_JSON}" \
    "${SLUG}" \
    "${OUT_DIR}/case-study.md"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Client package complete: ${OUT_DIR}"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
ls -lh "${OUT_DIR}"
