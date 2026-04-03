#!/usr/bin/env bash
# omni_coverage_mapper.sh — Recon: extract all unique file extensions across
# the top 15 enterprise repositories, sorted by frequency of occurrence.
#
# Usage: ./tools/omni_coverage_mapper.sh [output_dir]
# Output: stdout — sorted frequency table of file extensions
#         <output_dir>/ext_freq.txt (default: /tmp/omni_mapper_out)
set -euo pipefail

REPOS=(
    "NixOS/nixpkgs"
    "godotengine/godot"
    "DefinitelyTyped/DefinitelyTyped"
    "Homebrew/homebrew-core"
    "rust-lang/rust"
    "kubernetes/kubernetes"
    "microsoft/vscode"
    "facebook/react"
    "vercel/next.js"
    "tensorflow/tensorflow"
    "aquasecurity/trivy"
    "axios/axios"
    "tj-actions/changed-files"
    "nrwl/nx"
    "aquasecurity/trivy-action"
)

CLONE_BASE="/tmp/omni_mapper"
OUTPUT_DIR="${1:-/tmp/omni_mapper_out}"

mkdir -p "${CLONE_BASE}"
mkdir -p "${OUTPUT_DIR}"

EXT_FREQ_FILE="${OUTPUT_DIR}/ext_freq.txt"
: > "${EXT_FREQ_FILE}"

echo "[omni_coverage_mapper] Starting recon across ${#REPOS[@]} repositories"
echo "[omni_coverage_mapper] Clone base: ${CLONE_BASE}"
echo "[omni_coverage_mapper] Output:     ${OUTPUT_DIR}"
echo ""

for repo in "${REPOS[@]}"; do
    name="${repo//\//__}"
    dest="${CLONE_BASE}/${name}"
    echo "[clone] ${repo} → ${dest}"

    if [[ -d "${dest}/.git" ]]; then
        echo "  [skip] Already cloned — using cached"
    else
        git clone \
            --depth 1 \
            --filter=blob:none \
            --sparse \
            "https://github.com/${repo}.git" \
            "${dest}" \
            2>&1 | tail -3
        # Sparse checkout: expand all paths so we get the full tree manifest
        # (no file content downloaded — blob:none keeps disk usage minimal)
        git -C "${dest}" sparse-checkout set --no-cone '/*' 2>/dev/null || true
    fi

    echo "  [scan] Extracting extensions from ${dest}"
    # Extract extensions from all tracked file names (no content read)
    git -C "${dest}" ls-files \
        | awk -F'.' 'NF>1 { print tolower($NF) }' \
        >> "${EXT_FREQ_FILE}"
done

echo ""
echo "[omni_coverage_mapper] Sorting extension frequency table..."

SORTED="${OUTPUT_DIR}/ext_freq_sorted.txt"
sort "${EXT_FREQ_FILE}" \
    | uniq -c \
    | sort -rn \
    > "${SORTED}"

echo ""
echo "=== TOP 50 EXTENSIONS BY FREQUENCY ==="
head -50 "${SORTED}"

echo ""
echo "[omni_coverage_mapper] Full table: ${SORTED}"
echo "[omni_coverage_mapper] Done."
