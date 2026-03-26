#!/usr/bin/env bash
# publish_forensic_strike.sh — Execute a forensic strike and publish the evidence.
#
# Performs four atomic operations:
#
#   1. Execute — runs `just strike <repo> 1000` to produce 7 artefacts in
#                strikes/<repo_name>/
#   2. Create  — provisions a new public GitHub repository at
#                janitor-security/<repo_name>-audit-YYYY via the gh CLI
#   3. Publish — initialises a fresh git history from the strike artefacts
#                (case-study.md → README.md), commits, and pushes
#   4. Index   — appends a markdown link to docs/intelligence.md on the main
#                website so the audit appears in the published Intelligence
#                Reports index
#
# Usage:
#   ./tools/publish_forensic_strike.sh <owner/repo>
#   ./tools/publish_forensic_strike.sh godotengine/godot
#   ./tools/publish_forensic_strike.sh kubernetes/kubernetes
#
# Environment overrides:
#   PR_LIMIT       — max PRs to audit (default: 1000)
#   STRIKES_DIR    — base directory for strike output (default: ./strikes)
#   AUDIT_ORG      — GitHub organisation to publish under (default: janitor-security)
#   SKIP_STRIKE    — set to "1" to skip the just-strike step (reuse existing artifacts)
#
# Prerequisites:
#   - gh CLI authenticated with push access to ${AUDIT_ORG}
#   - jq, bc, pandoc, texlive in PATH (satisfied by `just shell` / Nix devShell)
#   - git configured with user.name and user.email

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

SLUG="${1:?Usage: $0 <owner/repo>   e.g. godotengine/godot}"
REPO_NAME="${SLUG##*/}"          # "godot" from "godotengine/godot"
PR_LIMIT="${PR_LIMIT:-1000}"
STRIKES_DIR="${STRIKES_DIR:-${PWD}/strikes}"
AUDIT_ORG="${AUDIT_ORG:-janitor-security}"
SKIP_STRIKE="${SKIP_STRIKE:-0}"

YEAR="$(date +%Y)"
AUDIT_REPO="${REPO_NAME}-audit-${YEAR}"
FULL_AUDIT_SLUG="${AUDIT_ORG}/${AUDIT_REPO}"
STRIKE_DIR="${STRIKES_DIR}/${REPO_NAME}"
INTELLIGENCE_MD="${PWD}/docs/intelligence.md"
TODAY="$(date +%Y-%m-%d)"

# ── Preflight ─────────────────────────────────────────────────────────────────

for cmd in gh git jq bc; do
    if ! command -v "${cmd}" &>/dev/null; then
        echo "error: '${cmd}' is required but not found in PATH." >&2
        exit 1
    fi
done

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  publish_forensic_strike — The Janitor v7.9.4               ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Target     : ${SLUG}"
echo "  PR limit   : ${PR_LIMIT}"
echo "  Strike dir : ${STRIKE_DIR}"
echo "  Publish to : https://github.com/${FULL_AUDIT_SLUG}"
echo "  Index      : docs/intelligence.md"
echo ""

# ── Step 1: Execute the Strike ────────────────────────────────────────────────

if [[ "${SKIP_STRIKE}" == "1" ]]; then
    echo "[1/4] Skipping strike (SKIP_STRIKE=1) — using existing artefacts in ${STRIKE_DIR}"
    if [[ ! -d "${STRIKE_DIR}" ]]; then
        echo "error: SKIP_STRIKE=1 but strike directory does not exist: ${STRIKE_DIR}" >&2
        exit 1
    fi
else
    echo "[1/4] Executing forensic strike against ${SLUG} (limit=${PR_LIMIT})..."
    PR_LIMIT="${PR_LIMIT}" just strike "${SLUG}" "${PR_LIMIT}"
fi

# Verify all 7 expected artefacts are present.
EXPECTED_ARTIFACTS=(
    "gauntlet_intelligence_report.pdf"
    "gauntlet_export.csv"
    "gauntlet_report.json"
    "${REPO_NAME}_cbom.json"
    "${REPO_NAME}_intel.json"
    "${REPO_NAME}_vex.json"
    "case-study.md"
)
echo ""
echo "  Verifying artefacts in ${STRIKE_DIR} ..."
for f in "${EXPECTED_ARTIFACTS[@]}"; do
    if [[ ! -f "${STRIKE_DIR}/${f}" ]]; then
        echo "error: expected artefact missing: ${STRIKE_DIR}/${f}" >&2
        exit 1
    fi
    echo "    ✓ ${f}"
done

# ── Step 2: Create the Dossier (public GitHub repository) ─────────────────────

echo ""
echo "[2/4] Provisioning public repository: ${FULL_AUDIT_SLUG} ..."

# Idempotent: skip creation if the repo already exists.
if gh repo view "${FULL_AUDIT_SLUG}" &>/dev/null; then
    echo "  Repository already exists — skipping creation."
else
    gh repo create "${FULL_AUDIT_SLUG}" \
        --public \
        --description "Janitor v7.9.4 forensic audit — ${SLUG} (${TODAY})" \
        --add-readme=false
    echo "  Created: https://github.com/${FULL_AUDIT_SLUG}"
fi

# ── Step 3: Publish the Evidence ──────────────────────────────────────────────

echo ""
echo "[3/4] Publishing evidence to https://github.com/${FULL_AUDIT_SLUG} ..."

PUBLISH_DIR="$(mktemp -d /tmp/janitor_publish_XXXXXX)"
trap 'rm -rf "${PUBLISH_DIR}"' EXIT

# Copy all 7 artefacts into the staging directory.
cp "${STRIKE_DIR}/gauntlet_intelligence_report.pdf" "${PUBLISH_DIR}/"
cp "${STRIKE_DIR}/gauntlet_export.csv"              "${PUBLISH_DIR}/"
cp "${STRIKE_DIR}/gauntlet_report.json"             "${PUBLISH_DIR}/"
cp "${STRIKE_DIR}/${REPO_NAME}_cbom.json"           "${PUBLISH_DIR}/"
cp "${STRIKE_DIR}/${REPO_NAME}_intel.json"          "${PUBLISH_DIR}/"
cp "${STRIKE_DIR}/${REPO_NAME}_vex.json"            "${PUBLISH_DIR}/"
# case-study.md → README.md (GitHub renders README.md on the repo homepage)
cp "${STRIKE_DIR}/case-study.md"                    "${PUBLISH_DIR}/README.md"

# Initialise a fresh git history (force-push will overwrite on re-run).
git -C "${PUBLISH_DIR}" init -b main
git -C "${PUBLISH_DIR}" add .
git -C "${PUBLISH_DIR}" \
    -c user.email="ops@thejanitor.app" \
    -c user.name="Janitor Intelligence" \
    commit -m "Janitor v7.9.4 forensic audit — ${SLUG} (${TODAY}, ${PR_LIMIT} PRs)"

git -C "${PUBLISH_DIR}" remote add origin \
    "https://github.com/${FULL_AUDIT_SLUG}.git"
git -C "${PUBLISH_DIR}" push --force origin main

echo "  Published: https://github.com/${FULL_AUDIT_SLUG}"

# ── Step 4: Update the Global Intelligence Index ──────────────────────────────

echo ""
echo "[4/4] Updating docs/intelligence.md ..."

# Bootstrap the file if it does not yet exist.
if [[ ! -f "${INTELLIGENCE_MD}" ]]; then
    cat > "${INTELLIGENCE_MD}" <<'HEADER'
# Intelligence Reports

Published forensic audits by The Janitor — structural PR analysis across open-source repositories.

Each report is a full evidence package: PDF intelligence report, 16-column CSV audit trail, CycloneDX CBOM, VEX exploitability assessment, and Swarm clone-pair data.

| Repository | Date | Audit Package |
|---|---|---|
HEADER
    echo "  Created docs/intelligence.md"
fi

# Append the new row. The link points to the public GitHub repository.
printf '| %s | %s | [%s](https://github.com/%s) |\n' \
    "${SLUG}" \
    "${TODAY}" \
    "${AUDIT_REPO}" \
    "${FULL_AUDIT_SLUG}" \
    >> "${INTELLIGENCE_MD}"

echo "  Appended: ${SLUG} → https://github.com/${FULL_AUDIT_SLUG}"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Forensic strike published."
echo ""
echo "  Evidence  : https://github.com/${FULL_AUDIT_SLUG}"
echo "  Index     : docs/intelligence.md (deploy with: just deploy-docs)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
