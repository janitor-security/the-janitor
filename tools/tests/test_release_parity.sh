#!/usr/bin/env bash
set -euo pipefail

JUSTFILE="${1:-justfile}"
RELEASE_DOC="${2:-.agent_governance/commands/release.md}"

fail() {
    echo "release parity failure: $*" >&2
    exit 1
}

[[ -f "${JUSTFILE}" ]] || fail "missing justfile at ${JUSTFILE}"
[[ -f "${RELEASE_DOC}" ]] || fail "missing release doc at ${RELEASE_DOC}"

# Law 0: per-prompt commit mandate.
grep -Fq 'git commit -a -m' "${RELEASE_DOC}" \
    || fail "release doc missing the per-prompt git commit -a mandate (Law 0)"
grep -Fq 'EVERY' "${RELEASE_DOC}" \
    || fail "release doc missing the EVERY-prompt emphasis for the commit mandate"

# Law II: test-threads=4 mandate.
grep -Fq 'cargo test --workspace -- --test-threads=4' "${RELEASE_DOC}" \
    || fail "release doc missing the --test-threads=4 mandate (Law II)"
if grep -Fq 'cargo test --workspace -- --test-threads=1' "${RELEASE_DOC}"; then
    fail "release doc still references --test-threads=1 — conflicts with Law II"
fi

# Step order inside the commanded release execution block. The ordered block
# starts at "## Release Execution Order" — earlier mentions of the same
# tokens in exceptions or Law sections do not count.
exec_block_start="$(grep -n '^## Release Execution Order' "${RELEASE_DOC}" | head -1 | cut -d: -f1)"
[[ -n "${exec_block_start}" ]] || fail "release doc is missing the Release Execution Order section"
doc_test_line="$(awk -v start="${exec_block_start}" 'NR > start && /cargo test --workspace -- --test-threads=4/ { print NR; exit }' "${RELEASE_DOC}")"
doc_audit_line="$(awk -v start="${exec_block_start}" 'NR > start && /^just audit$/ { print NR; exit }' "${RELEASE_DOC}")"
doc_fastrelease_line="$(awk -v start="${exec_block_start}" 'NR > start && /just fast-release <version>/ { print NR; exit }' "${RELEASE_DOC}")"
[[ -n "${doc_test_line}" ]] || fail "release execution block does not schedule the test gate"
[[ -n "${doc_audit_line}" ]] || fail "release execution block does not schedule just audit"
[[ -n "${doc_fastrelease_line}" ]] || fail "release execution block does not schedule fast-release"
(( doc_test_line < doc_audit_line )) || fail "release doc does not preserve test -> audit order"
(( doc_audit_line < doc_fastrelease_line )) || fail "release doc does not preserve audit -> fast-release order"

# Hard prohibitions that must survive every rewrite.
grep -Fq 'Co-authored-by' "${RELEASE_DOC}" \
    || fail "release doc dropped the Co-authored-by prohibition"
grep -Fq 'force-push' "${RELEASE_DOC}" \
    || fail "release doc dropped the force-push prohibition"
grep -Fq -- '--no-verify' "${RELEASE_DOC}" \
    || fail "release doc dropped the --no-verify prohibition"

# Justfile fast-release structural guarantees.
release_exec_line="$(grep -n 'exec just fast-release "{{version}}"' "${JUSTFILE}" | head -1 | cut -d: -f1)"
[[ -n "${release_exec_line}" ]] || fail "release recipe does not delegate to fast-release"

preflight_line="$(grep -n 'gpg --batch --yes --pinentry-mode error --clearsign' "${JUSTFILE}" | head -1 | cut -d: -f1)"
sync_line="$(grep -n 'just sync-versions' "${JUSTFILE}" | head -1 | cut -d: -f1)"
audit_line="$(grep -n 'just audit' "${JUSTFILE}" | tail -1 | cut -d: -f1)"
build_line="$(grep -n 'cargo build --release -p cli' "${JUSTFILE}" | tail -1 | cut -d: -f1)"
git_add_line="$(grep -n 'git add crates/ tools/ docs/ \.agent_governance/ Cargo.toml Cargo.lock README.md mkdocs.yml justfile action.yml' "${JUSTFILE}" | head -1 | cut -d: -f1)"
commit_line="$(grep -n 'git commit -S -m "chore: release v{{version}}"' "${JUSTFILE}" | head -1 | cut -d: -f1)"
tag_line="$(grep -n 'git tag -s v{{version}} -m "release v{{version}}"' "${JUSTFILE}" | head -1 | cut -d: -f1)"

[[ -n "${preflight_line}" ]] || fail "fast-release is missing the GPG pre-flight gate"
[[ -n "${sync_line}" ]] || fail "fast-release is missing sync-versions"
[[ -n "${audit_line}" ]] || fail "fast-release is missing audit"
[[ -n "${build_line}" ]] || fail "fast-release is missing the cli-only cargo build"
[[ -n "${git_add_line}" ]] || fail "fast-release staging sequence drifted (git add)"
[[ -n "${commit_line}" ]] || fail "fast-release staging sequence drifted (git commit)"
[[ -n "${tag_line}" ]] || fail "fast-release is missing the signed tag step"

(( preflight_line < sync_line )) || fail "pre-flight no longer precedes sync-versions"
(( sync_line < audit_line )) || fail "sync-versions no longer precedes audit"
(( audit_line < build_line )) || fail "audit no longer precedes build"
(( build_line < git_add_line )) || fail "build no longer precedes git add"
(( git_add_line < commit_line )) || fail "git add no longer precedes commit"
(( commit_line < tag_line )) || fail "commit no longer precedes tag"

# The justfile audit recipe must match Law II — no lingering --test-threads=1.
if grep -Fq 'cargo test --workspace -- --test-threads=1' "${JUSTFILE}"; then
    fail "justfile audit still invokes --test-threads=1 — conflicts with release doc Law II"
fi

echo "release parity OK"
