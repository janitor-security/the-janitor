#!/usr/bin/env bash
set -euo pipefail

# Usage: ./tools/campaign.sh <targets_file> <format>
#   targets_file  — one URL or NPM package per line; lines starting with # are skipped
#   format        — output format passed to `janitor hunt --format` (e.g. auth0 or bugcrowd)
#
# Output: campaigns/<timestamp>/<safe_target_name>.md

TARGETS_FILE="${1?Usage: campaign.sh <targets_file> <format>}"
FORMAT="${2?Usage: campaign.sh <targets_file> <format>}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
JANITOR_BIN="${PROJECT_ROOT}/target/release/janitor"

if [ ! -f "${JANITOR_BIN}" ]; then
    echo "FATAL: janitor binary not found at ${JANITOR_BIN}. Run 'just build' first." >&2
    exit 1
fi

if [ ! -f "${TARGETS_FILE}" ]; then
    echo "FATAL: targets file not found: ${TARGETS_FILE}" >&2
    exit 1
fi

TIMESTAMP="$(date +%Y%m%dT%H%M%S)"
CAMPAIGN_DIR="${PROJECT_ROOT}/campaigns/${TIMESTAMP}"
mkdir -p "${CAMPAIGN_DIR}"

echo "[campaign] Started: ${CAMPAIGN_DIR}"
echo "[campaign] Format:  ${FORMAT}"

while IFS= read -r target || [ -n "${target}" ]; do
    # Skip blank lines and comments.
    [[ -z "${target}" || "${target}" == \#* ]] && continue

    # Derive a filesystem-safe output name from the target (max 64 chars).
    safe_name="$(printf '%s' "${target}" | tr -dc 'a-zA-Z0-9._-' | cut -c1-64)"
    if [ -z "${safe_name}" ]; then
        safe_name="target_${RANDOM}"
    fi
    out_file="${CAMPAIGN_DIR}/${safe_name}.md"

    echo "[campaign] Scanning: ${target} → $(basename "${out_file}")"
    "${JANITOR_BIN}" hunt . --sourcemap "${target}" \
        --filter '.[] | select(.id | startswith("security:"))' \
        --format "${FORMAT}" > "${out_file}" 2>&1 || true
done < "${TARGETS_FILE}"

echo "[campaign] Complete: ${CAMPAIGN_DIR}"
