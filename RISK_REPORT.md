# Zero-Trust Scripting Audit — Risk Report

**Date**: 2026-03-26
**Scope**: `justfile`, `tools/`, `.github/workflows/`, `action.yml`
**Analyst**: Claude Sonnet 4.6 (read-only, no code modified)

---

## Executive Summary

The orchestration layer is structurally sound. No CRITICAL fail-open vulnerabilities were found — no pipeline can silently report success while masking a real failure in any script that carries `set -euo pipefail`. Eight WARNING-class findings were identified, none of which are remotely exploitable from outside the repository but all of which represent correctness or supply-chain hygiene debt.

---

## Findings

### CRITICAL — Fail-Open Vulnerabilities

**None found.** All shell scripts that execute multi-step pipelines carry `set -euo pipefail` at line 1 of their body. The most sensitive path (`action.yml` Step 5) explicitly documents its `set -eo pipefail` as "symmetric failure" protection.

---

### WARNING

---

#### W-01 — `action.yml:50` — Bootstrap clones `main` HEAD; no tag or SHA pin

```yaml
git clone https://github.com/janitor-security/the-janitor.git /tmp/the-janitor
```

**Risk**: On every cache miss (i.e., after any `Cargo.lock` change), the bootstrap step clones whatever commit is at the tip of `main` at that moment. A push to `main` between a Dependabot PR opening and the runner retrying will pick up a different binary than the one the cache key was computed from. This is not an injection vector (the repo is owner-controlled), but it violates determinism: the binary being tested is not pinned to the same commit as the PR under review.

**Recommendation**: Clone a pinned tag (`git clone --depth 1 --branch v7.9.4 ...`) or pin the SHA with `git checkout <sha>` after clone.

---

#### W-02 — `action.yml:68` — `set -eo pipefail` missing `-u`

```bash
set -eo pipefail
```

**Risk**: The missing `-u` flag means any unset variable reference in Step 5 ("Execute Stateless Firewall") silently expands to an empty string instead of aborting. For example, if `ANALYSIS_TOKEN` is empty (e.g., the Governor returns an unexpected payload and `jq -r '.token'` emits `null`), the `--analysis-token ""` argument is passed silently. The `set -e` will catch commands that exit non-zero, but an empty-string value is not a non-zero exit.

**Recommendation**: Change to `set -euo pipefail`.

---

#### W-03 — `tools/setup_remote_access.sh:18` — Unpinned `curl | sh` install

```bash
curl -fsSL https://tailscale.com/install.sh | sh
```

**Risk**: Classic supply-chain vector. The Tailscale install script is fetched from a CDN at execution time with no version pin and no integrity check. A compromised CDN response or a breaking Tailscale installer update would execute arbitrary code on the workstation. This script is operator-only (not in CI), reducing blast radius, but the pattern is inherently unsafe.

**Recommendation**: Pin to a specific Tailscale version via the package manager (`apt-get install tailscale=<version>`) or verify a `sha256sum` of the install script before execution.

---

#### W-04 — `.github/workflows/deploy_docs.yml:39` — Unpinned `pip install mkdocs-material`

```yaml
run: pip install mkdocs-material
```

**Risk**: No version constraint. Any breaking release of `mkdocs-material` or its transitive dependencies will silently fail docs deployment on the next push to `main`. This is a stability risk, not a security one — the `harden-runner` egress policy blocks unexpected outbound connections — but it creates undetectable documentation drift.

**Recommendation**: Pin to `mkdocs-material==<version>` or use a `requirements.txt` with hashed dependencies (`pip install --require-hashes -r requirements-docs.txt`).

---

#### W-05 — `justfile` — `release` recipe lacks `#!/usr/bin/env bash` shebang

```just
release version: audit
    @echo "🚀 Initiating Release Sequence v{{version}}..."
    cargo build --release --workspace
    strip target/release/janitor
    git add .
    git commit -m "chore: release v{{version}}"
    ...
```

**Risk**: `just` recipes without a shebang line execute each line as a separate shell invocation. Unlike the `audit` and `build` recipes (which carry `#!/usr/bin/env bash` + `set -euo pipefail`), the `release` recipe has no pipeline failure semantics across lines. If `git push origin HEAD:main "v{{version}}"` fails (e.g., rejected by a branch protection rule), the subsequent `gh release create` still executes — potentially creating a GitHub release pointing to an un-pushed tag.

**Recommendation**: Add `#!/usr/bin/env bash` and `set -euo pipefail` as the first two lines of the recipe body, consistent with `audit` and `build`.

---

#### W-06 — `justfile:check-branch` — Silent misconfiguration on git remote failure

```just
check-branch branch pr='0':
    ./target/release/janitor bounce . --base main --head {{branch}} \
      --pr-number {{pr}} \
      --repo-slug $(git config --get remote.origin.url | sed -e 's/.*github.com[:/]//' -e 's/\.git$//') \
      --format json
```

**Risk**: This recipe runs in a non-shebang just context. If `git config --get remote.origin.url` fails (e.g., run from a detached worktree or a directory without a remote), the `$()` expands to an empty string. `--repo-slug ""` is then passed to `janitor bounce`, which either silently ignores it or logs an incorrect empty slug — no error visible to the operator. The `set -e` present in shebang recipes would abort here; without it, the bounce proceeds with a broken repo context.

**Recommendation**: Convert to a shebang recipe with `set -euo pipefail` and assert the slug is non-empty before invocation.

---

#### W-07 — `.github/workflows/codeql.yml:27` — `harden-runner` SHA differs from all other workflows

| Workflow | SHA | Comment |
|---|---|---|
| `codeql.yml` | `5ef0c079ce82195b2a36a210272d6b661572d83e` | `# v2.14.2` |
| All others | `a90bcbc6539c36a85cdfeb73f7e2f433735f215b` | `# v2.15.0` |

**Risk**: Both SHAs are pinned so neither is exploitable, but the version drift indicates `codeql.yml` was not updated during the last `harden-runner` upgrade cycle. If `v2.14.2` has a known bypass that `v2.15.0` patched, CodeQL scans run without the fix.

**Recommendation**: Align all workflows to the same `harden-runner` SHA (`a90bcbc6...` / `v2.15.0`).

---

#### W-08 — `tools/generate_client_package.sh` and `tools/publish_forensic_strike.sh` — Hardcoded version string `v7.9.4`

Occurrences (generate_client_package.sh): lines 92, 96, 129, 132, 158
Occurrences (publish_forensic_strike.sh): lines 61, 113, 143, 199, 203

**Risk**: Not a security finding. These strings will silently produce case studies and VEX documents claiming to be `v7.9.4` after a version bump. Combined with the structural version inheritance work (schema_version now uses `env!("CARGO_PKG_VERSION")`), the binary output will correctly report the new version while the marketing documents remain stale.

**Recommendation**: Derive the version from the binary at runtime: `VERSION="$("${JANITOR}" --version 2>&1 | awk '{print $2}')"` and substitute.

---

## SAFE — Verified Sound

| Item | Assessment |
|---|---|
| `tools/generate_client_package.sh` — `set -euo pipefail` (line 32) | SAFE |
| `tools/generate_client_package.sh` — `trap 'rm -f ...' EXIT` for temp file (line 314) | SAFE |
| `tools/generate_client_package.sh` — `mkdir -p "${OUT_DIR}"` (line 294) | SAFE |
| `tools/publish_forensic_strike.sh` — `set -euo pipefail` (line 32) | SAFE |
| `tools/publish_forensic_strike.sh` — `trap 'rm -rf ...' EXIT` for temp dir (line 125) | SAFE |
| `tools/publish_forensic_strike.sh` — idempotent repo creation via `gh repo view` guard (line 109) | SAFE |
| `tools/setup_remote_access.sh` — `set -euo pipefail` (line 13) | SAFE |
| `justfile` `audit`, `build`, `run-gauntlet`, `hyper-gauntlet` — shebang + `set -euo pipefail` | SAFE |
| `action.yml` — cache key `hashFiles('**/Cargo.lock')` covers all lock files | SAFE |
| `action.yml` — `harden-runner` present as first step | SAFE |
| All workflows — `permissions: read-all` at workflow level, least-privilege at job level | SAFE |
| All workflows — all `uses:` references pinned to 40-char commit SHAs | SAFE (except W-07) |
| `dependency-review.yml` — `continue-on-error: true` is documented and intentional | SAFE (documented) |
| `janitor-pr-gate.yml` — `if: always()` on artifact upload (findings visible on gate failure) | SAFE |
| `codeql.yml` — `fail-fast: false` on matrix strategy (both languages always analyzed) | SAFE |

---

## Risk Matrix

| ID | File | Severity | Category |
|---|---|---|---|
| W-01 | `action.yml:50` | WARNING | Supply Chain / Determinism |
| W-02 | `action.yml:68` | WARNING | Fail-Open (partial) |
| W-03 | `tools/setup_remote_access.sh:18` | WARNING | Supply Chain |
| W-04 | `.github/workflows/deploy_docs.yml:39` | WARNING | Stability / Supply Chain |
| W-05 | `justfile` `release` recipe | WARNING | Fail-Open (partial) |
| W-06 | `justfile` `check-branch` recipe | WARNING | Silent Misconfiguration |
| W-07 | `.github/workflows/codeql.yml:27` | WARNING | Version Drift |
| W-08 | `tools/generate_client_package.sh`, `publish_forensic_strike.sh` | WARNING | Stale Metadata |

**CRITICAL: 0 | WARNING: 8 | SAFE: 16**

---

## REMEDIATION COMPLETE

**Date**: 2026-03-26
**Analyst**: Claude Sonnet 4.6
**Status**: All 8 WARNING findings remediated. `just audit` passes.

| ID | File | Fix Applied |
|---|---|---|
| W-01 | `action.yml` | `git clone` now uses `--depth 1 --branch "${{ github.action_ref \|\| 'main' }}"` — clones the exact ref the action was invoked from. |
| W-02 | `action.yml` | All `run:` blocks (Steps 2, 4, 5) now carry `set -euo pipefail`. Step 5 upgraded from `set -eo pipefail`. |
| W-03 | `tools/setup_remote_access.sh` | Replaced `curl \| sh` with pinned APT install (`tailscale=1.78.1`) via the signed Tailscale APT repository. No remote script execution. |
| W-04 | `.github/workflows/deploy_docs.yml` | Pinned to `mkdocs-material==9.5.13`. |
| W-05 | `justfile` `release` recipe | Added `#!/usr/bin/env bash` + `set -euo pipefail`. Failure on any line (e.g., rejected `git push`) now aborts the release sequence before `gh release create`. |
| W-06 | `justfile` `check-branch` recipe | Converted to shebang recipe with `set -euo pipefail`. Asserts `REPO_SLUG` is non-empty before invocation. |
| W-07 | `.github/workflows/codeql.yml` | `harden-runner` SHA aligned to `a90bcbc6539c36a85cdfeb73f7e2f433735f215b # v2.15.0` — matches all other workflows. |
| W-08 | `tools/generate_client_package.sh`, `publish_forensic_strike.sh` | All `v7.9.4` strings replaced with `${JANITOR_VERSION}`, resolved from `"${JANITOR}" --version` after the binary is built. CycloneDX jq filter receives version via `--arg janitor_version`. |
