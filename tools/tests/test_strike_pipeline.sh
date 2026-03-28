#!/usr/bin/env bash
# tools/tests/test_strike_pipeline.sh — Strike & Publish pipeline regression tests.
#
# Tests every contractual invariant of generate_client_package.sh and
# publish_forensic_strike.sh without performing live network calls or
# touching real GitHub repositories.
#
# Run directly:
#   ./tools/tests/test_strike_pipeline.sh
#
# Run via just:
#   just test-strike-pipeline
#
# Exit codes:
#   0 — all tests passed
#   1 — one or more tests failed

set -euo pipefail

# ── Test harness ──────────────────────────────────────────────────────────────

PASS=0
FAIL=0

pass() { echo "[PASS] $1"; (( PASS++ )) || true; }
fail() { echo "[FAIL] $1 — $2" >&2; (( FAIL++ )) || true; }

assert_eq() {
    local name="$1" got="$2" want="$3"
    if [[ "${got}" == "${want}" ]]; then
        pass "${name}"
    else
        fail "${name}" "got '${got}', want '${want}'"
    fi
}

assert_contains() {
    local name="$1" haystack="$2" needle="$3"
    if echo "${haystack}" | grep -qF "${needle}"; then
        pass "${name}"
    else
        fail "${name}" "'${needle}' not found in output"
    fi
}

assert_exit_zero() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        pass "${name}"
    else
        fail "${name}" "command exited non-zero: $*"
    fi
}

assert_exit_nonzero() {
    local name="$1"; shift
    if "$@" >/dev/null 2>&1; then
        fail "${name}" "expected non-zero exit from: $*"
    else
        pass "${name}"
    fi
}

# ── Resolve paths ──────────────────────────────────────────────────────────────

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
JANITOR="${REPO_ROOT}/target/release/janitor"
GEN_SCRIPT="${REPO_ROOT}/tools/generate_client_package.sh"
PUB_SCRIPT="${REPO_ROOT}/tools/publish_forensic_strike.sh"

echo "══════════════════════════════════════════════════════════════"
echo "  Strike Pipeline — Regression Tests"
echo "  Repo root : ${REPO_ROOT}"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── Test Group 1: Binary contract ─────────────────────────────────────────────

echo "── Group 1: Binary contract ──────────────────────────────────"

if [[ ! -f "${JANITOR}" ]]; then
    fail "binary exists" "Run 'cargo build --release -p cli' first: ${JANITOR}"
else
    pass "binary exists at target/release/janitor"

    # --version must exit 0 and emit a two-word version string.
    VERSION_OUT="$("${JANITOR}" --version 2>/dev/null)"
    assert_exit_zero   "--version exits 0"          "${JANITOR}" --version
    assert_contains    "--version contains 'janitor'" "${VERSION_OUT}" "janitor"
    VERSION_WORD="$(echo "${VERSION_OUT}" | awk '{print $2}')"
    if echo "${VERSION_WORD}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
        pass "--version emits semver word (got: ${VERSION_WORD})"
    else
        fail "--version semver format" "got '${VERSION_WORD}', want X.Y.Z"
    fi

    # --help must exit 0.
    assert_exit_zero "--help exits 0" "${JANITOR}" --help
fi

echo ""

# ── Test Group 2: Script hygiene ──────────────────────────────────────────────

echo "── Group 2: Script hygiene ───────────────────────────────────"

for script in "${GEN_SCRIPT}" "${PUB_SCRIPT}"; do
    name="$(basename "${script}")"

    # Must be executable.
    if [[ -x "${script}" ]]; then
        pass "${name} is executable"
    else
        fail "${name} is executable" "chmod +x ${script}"
    fi

    # Must open with set -euo pipefail.
    if grep -q 'set -euo pipefail' "${script}"; then
        pass "${name} has set -euo pipefail"
    else
        fail "${name} has set -euo pipefail" "missing failure discipline"
    fi

    # Must NOT contain bare '--version 2>&1' pattern (stderr noise bleeds into version string).
    if grep -q -- '--version 2>&1' "${script}"; then
        fail "${name} version capture discards stderr" \
            "use '--version 2>/dev/null' to avoid error text in JANITOR_VERSION"
    else
        pass "${name} version capture redirects stderr correctly"
    fi

    # Every version capture must have a fallback '|| echo "dev"' guard.
    VERSION_CAPTURES="$(grep -c '"${JANITOR}" --version' "${script}" || true)"
    FALLBACK_CAPTURES="$(grep -c '|| echo "dev"' "${script}" || true)"
    if [[ "${VERSION_CAPTURES}" -le "${FALLBACK_CAPTURES}" ]]; then
        pass "${name} all version captures have fallback guard (${VERSION_CAPTURES}/${FALLBACK_CAPTURES})"
    else
        fail "${name} missing fallback guard" \
            "${VERSION_CAPTURES} captures but only ${FALLBACK_CAPTURES} fallbacks"
    fi
done

echo ""

# ── Test Group 3: generate_client_package.sh argument contract ────────────────

echo "── Group 3: generate_client_package.sh argument contract ─────"

# Must fail immediately with a usage message when called with no arguments.
GEN_ERR="$("${GEN_SCRIPT}" 2>&1 || true)"
assert_contains "no-arg error message contains 'Usage'" "${GEN_ERR}" "Usage"

# Must fail when called with an invalid slug (no slash).
BAD_SLUG_ERR="$(bash "${GEN_SCRIPT}" "noslash" 2>&1 || true)"
# The error propagates either from bash's required-param check or from
# SLUG validation inside the script.
if [[ "${BAD_SLUG_ERR}" == *"Usage"* ]] || [[ "${BAD_SLUG_ERR}" == *"noslash"* ]]; then
    pass "invalid slug triggers error output"
else
    fail "invalid slug triggers error output" \
        "got: ${BAD_SLUG_ERR:0:120}"
fi

echo ""

# ── Test Group 4: publish_forensic_strike.sh argument contract ────────────────

echo "── Group 4: publish_forensic_strike.sh argument contract ─────"

# Must fail with a usage message when called with no arguments.
PUB_ERR="$("${PUB_SCRIPT}" 2>&1 || true)"
assert_contains "no-arg error message contains 'Usage'" "${PUB_ERR}" "Usage"

# SKIP_STRIKE=1 with a non-existent directory must fail and report the path.
NONEXIST_DIR="$(mktemp -d /tmp/janitor_test_XXXXXX)"
rmdir "${NONEXIST_DIR}"   # remove so it does not exist
SKIP_ERR="$(SKIP_STRIKE=1 STRIKES_DIR="${NONEXIST_DIR}" bash "${PUB_SCRIPT}" "owner/repo" 2>&1 || true)"
assert_contains "SKIP_STRIKE=1 + missing dir produces error" "${SKIP_ERR}" "error"

echo ""

# ── Test Group 5: Artefact manifest integrity ─────────────────────────────────

echo "── Group 5: Artefact manifest integrity ──────────────────────"

# The EXPECTED_ARTIFACTS array in publish_forensic_strike.sh must cover all 7
# artefacts that generate_client_package.sh produces.  Extract both lists and
# compare the non-repo-specific names.

GENERATED=$(grep -A8 'EXPECTED_ARTIFACTS=(' "${PUB_SCRIPT}" | grep '"' | sed 's/.*"\(.*\)".*/\1/')
GENERIC_EXPECTED="gauntlet_intelligence_report.pdf gauntlet_export.csv gauntlet_report.json case-study.md"
for artifact in ${GENERIC_EXPECTED}; do
    if echo "${GENERATED}" | grep -qF "${artifact}"; then
        pass "artefact manifest covers ${artifact}"
    else
        fail "artefact manifest covers ${artifact}" "not found in EXPECTED_ARTIFACTS"
    fi
done

echo ""

# ── Summary ───────────────────────────────────────────────────────────────────

TOTAL=$(( PASS + FAIL ))
echo "══════════════════════════════════════════════════════════════"
if [[ "${FAIL}" -eq 0 ]]; then
    echo "  Strike Pipeline Tests: ${PASS}/${TOTAL} — SANCTUARY INTACT."
    exit 0
else
    S=""
    [[ "${FAIL}" -gt 1 ]] && S="S"
    echo "  Strike Pipeline Tests: ${PASS}/${TOTAL} — ${FAIL} FAILURE${S}." >&2
    exit 1
fi
