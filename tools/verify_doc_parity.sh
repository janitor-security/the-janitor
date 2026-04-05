#!/usr/bin/env bash
set -euo pipefail

# verify_doc_parity.sh — Documentation Parity Gate
#
# Extracts the canonical version from Cargo.toml and verifies that
# README.md and docs/index.md both contain the exact version string.
# Exits 1 if either file is stale, blocking `just audit` and any release.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

VERSION="$(grep '^version' "${REPO_ROOT}/Cargo.toml" | head -1 | sed 's/version = "\(.*\)"/\1/')"

if [[ -z "${VERSION}" ]]; then
    echo "error: could not extract version from Cargo.toml" >&2
    exit 1
fi

echo "→ Verifying doc parity for v${VERSION}"

FAIL=0

if ! grep -q "v${VERSION}" "${REPO_ROOT}/docs/index.md"; then
    echo "✗ docs/index.md does not contain v${VERSION}" >&2
    FAIL=1
fi

if ! grep -q "v${VERSION}" "${REPO_ROOT}/README.md"; then
    echo "✗ README.md does not contain v${VERSION}" >&2
    FAIL=1
fi

if [[ "${FAIL}" -eq 1 ]]; then
    echo "" >&2
    echo "PARITY BREACH: run 'just sync-versions' to fix stale version strings." >&2
    exit 1
fi

echo "✓ Documentation parity verified: v${VERSION}"
