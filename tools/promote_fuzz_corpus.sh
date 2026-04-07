#!/usr/bin/env bash
# promote_fuzz_corpus.sh — Promote libFuzzer crash/timeout artifacts to signed
# Crucible exhaustion fixtures under crates/crucible/fixtures/exhaustion/.
#
# Usage:
#   tools/promote_fuzz_corpus.sh <ARTIFACT_DIR>
#
# Each file in ARTIFACT_DIR is hashed (BLAKE3 / sha256sum fallback) and copied
# to fixtures/exhaustion/<hex_hash> with a deterministic filename.  Duplicate
# artifacts (same hash) are silently skipped.  The resulting fixture set is
# exercised by the Crucible `exhaustion_corpus_no_panic` regression test.
#
# Requirements: sha256sum or b3sum (BLAKE3); cp; mkdir
set -euo pipefail

ARTIFACT_DIR="${1:-}"
if [[ -z "${ARTIFACT_DIR}" ]]; then
    echo "error: usage: $0 <ARTIFACT_DIR>" >&2
    exit 1
fi

if [[ ! -d "${ARTIFACT_DIR}" ]]; then
    echo "error: artifact directory does not exist: ${ARTIFACT_DIR}" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEST_DIR="${REPO_ROOT}/crates/crucible/fixtures/exhaustion"

mkdir -p "${DEST_DIR}"

PROMOTED=0
SKIPPED=0

for artifact in "${ARTIFACT_DIR}"/*; do
    [[ -f "${artifact}" ]] || continue

    # Compute a deterministic filename from the file's content hash.
    if command -v b3sum &>/dev/null; then
        file_hash="$(b3sum --no-names "${artifact}")"
    else
        file_hash="$(sha256sum "${artifact}" | awk '{print $1}')"
    fi

    dest_file="${DEST_DIR}/${file_hash}"

    if [[ -e "${dest_file}" ]]; then
        echo "skip: ${artifact} → already promoted as ${file_hash}"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    cp "${artifact}" "${dest_file}"
    echo "promoted: ${artifact} → fixtures/exhaustion/${file_hash}"
    PROMOTED=$((PROMOTED + 1))
done

echo ""
echo "Corpus promotion complete: ${PROMOTED} new, ${SKIPPED} duplicate(s)."
echo "Run 'cargo test -p crucible exhaustion_corpus_no_panic' to verify fixtures."
