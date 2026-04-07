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

doc_audit_line="$(grep -n 'just audit' "${RELEASE_DOC}" | head -1 | cut -d: -f1)"
doc_fast_release_line="$(grep -n 'just fast-release <v>' "${RELEASE_DOC}" | head -1 | cut -d: -f1)"
[[ -n "${doc_audit_line}" ]] || fail "release doc does not require just audit"
[[ -n "${doc_fast_release_line}" ]] || fail "release doc does not require just fast-release <v>"
(( doc_audit_line < doc_fast_release_line )) || fail "release doc does not preserve audit -> fast-release order"
grep -Fq 'You MUST NEVER use `just release`' "${RELEASE_DOC}" \
    || fail "release doc does not forbid just release"

release_exec_line="$(grep -n 'exec just fast-release "{{version}}"' "${JUSTFILE}" | head -1 | cut -d: -f1)"
[[ -n "${release_exec_line}" ]] || fail "release recipe does not delegate to fast-release"

preflight_line="$(grep -n 'gpg --batch --yes --pinentry-mode error --clearsign' "${JUSTFILE}" | head -1 | cut -d: -f1)"
sync_line="$(grep -n 'just sync-versions' "${JUSTFILE}" | head -1 | cut -d: -f1)"
audit_line="$(grep -n 'just audit' "${JUSTFILE}" | tail -1 | cut -d: -f1)"
build_line="$(grep -n 'cargo build --release --workspace' "${JUSTFILE}" | tail -1 | cut -d: -f1)"
commit_line="$(grep -n 'git add crates/ tools/ docs/ \.agent_governance/ Cargo.toml Cargo.lock README.md mkdocs.yml justfile action.yml && git commit -S -m "chore: release v{{version}}"' "${JUSTFILE}" | head -1 | cut -d: -f1)"
tag_line="$(grep -n 'git tag -s v{{version}} -m "release v{{version}}"' "${JUSTFILE}" | head -1 | cut -d: -f1)"

[[ -n "${preflight_line}" ]] || fail "fast-release is missing the GPG pre-flight gate"
[[ -n "${sync_line}" ]] || fail "fast-release is missing sync-versions"
[[ -n "${audit_line}" ]] || fail "fast-release is missing audit"
[[ -n "${build_line}" ]] || fail "fast-release is missing cargo build"
[[ -n "${commit_line}" ]] || fail "fast-release staging sequence drifted"
[[ -n "${tag_line}" ]] || fail "fast-release is missing the signed tag step"

(( preflight_line < sync_line )) || fail "pre-flight no longer precedes sync-versions"
(( sync_line < audit_line )) || fail "sync-versions no longer precedes audit"
(( audit_line < build_line )) || fail "audit no longer precedes build"
(( build_line < commit_line )) || fail "build no longer precedes commit"
(( commit_line < tag_line )) || fail "commit no longer precedes tag"

if grep -Eq 'git commit -a|git add \.' "${JUSTFILE}"; then
    fail "release surface is no longer allowlisted"
fi

echo "release parity OK"
