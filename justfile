set shell := ["bash", "-c"]
export PATH := env_var("HOME") + "/.local/bin:" + env_var("PATH")

# ── Hermetic shell ───────────────────────────────────────────────────────────
# Drop into the Nix development environment defined in flake.nix.
# All tools (Rust, pandoc, ffmpeg, gh, jq) are pinned to exact versions.
shell:
	nix develop

# 1. INITIALIZATION
init:
	@echo "🏗️ Constructing Sovereign Workspace..."
	@echo '[workspace]' > Cargo.toml
	@echo 'resolver = "2"' >> Cargo.toml
	@echo 'members = ["crates/*"]' >> Cargo.toml
	@echo '' >> Cargo.toml
	@echo '[workspace.package]' >> Cargo.toml
	@echo 'version = "5.2.0-SOVEREIGN"' >> Cargo.toml
	@echo 'edition = "2024"' >> Cargo.toml
	mkdir -p crates
	cargo new --lib crates/anatomist
	cargo new --lib crates/reaper
	cargo new --lib crates/shadow
	cargo new --lib crates/oracle
	cargo new --lib crates/vault
	cargo new --lib crates/common
	cargo new --bin crates/cli
	@echo "✅ Workspace initialized. Tabs enforced."

# 2. DEVELOPMENT
# If Nix is installed and we are NOT already inside the Nix dev shell,
# re-exec this recipe under `nix develop` so the pinned toolchain is used.
# Inside the Nix shell IN_NIX_SHELL is set by nix itself, preventing loops.
audit:
	#!/usr/bin/env bash
	set -euo pipefail
	if [[ -z "${IN_NIX_SHELL:-}" ]] && command -v nix &>/dev/null; then
	    echo "↳ Entering Nix hermetic shell for reproducible audit..."
	    exec nix develop --command just audit
	fi
	echo "🔍 Auditing Codebase..."
	cargo fmt --all -- --check
	cargo clippy --workspace -- -D warnings
	cargo check --workspace
	cargo test --workspace -- --test-threads=1
	bash ./tools/tests/test_release_parity.sh
	./tools/verify_doc_parity.sh
	echo "✅ System Clean."

build:
	#!/usr/bin/env bash
	set -euo pipefail
	if [[ -z "${IN_NIX_SHELL:-}" ]] && command -v nix &>/dev/null; then
	    echo "↳ Entering Nix hermetic shell for reproducible build..."
	    exec nix develop --command just build
	fi
	cargo build --release --workspace

clean:
	cargo clean
	find . -name "*.rkyv" -not -path "./.git/*" -delete
	@echo "💥 Target directory and rkyv artefacts vaporized."

# 3. AUTHENTICATION
auth-refresh:
	@echo "Auth is stateless — token injected at runtime via --token flag."

# 4. RELEASE PROTOCOL
#
# Prerequisites: set [workspace.package].version in root Cargo.toml, then run:
#   just release <X.Y.Z>   (bare version — recipe prepends 'v' for tags)
#
# Pipeline: fast-release (pre-flight → sync → audit → build/tag/push/release/deploy)
#
release version:
	#!/usr/bin/env bash
	set -euo pipefail
	echo "🚀 Initiating Release Sequence v{{version}}..."
	exec just fast-release "{{version}}"

# 4b. VERSION SYNC — reads [workspace.package].version from Cargo.toml and updates
#     the headline version string in README.md and docs/index.md.
#     Called automatically by fast-release.
#
sync-versions:
	#!/usr/bin/env bash
	set -euo pipefail
	VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/')
	echo "→ Syncing docs to v${VERSION}"
	VERSION="${VERSION}" perl -0pi -e 's/\*\*v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\s+—/**v$ENV{VERSION} —/g; s/The Janitor v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?/The Janitor v$ENV{VERSION}/g; s#(shields\.io/(?:badge|static/v1)[^)]*?)v\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?#$1v$ENV{VERSION}#g' README.md docs/index.md
	echo "✅ Version sync complete: v${VERSION}"

# 4c. FAST RELEASE — identical to `release` but skips the audit prerequisite.
#
# Use this when `just audit` has already been run explicitly in the same session.
# The AI release sequence (`.claude/commands/release.md`) calls `just audit` once
# as Step 3, then calls `just fast-release` as Step 4 to avoid a redundant re-audit.
#
fast-release version:
	#!/usr/bin/env bash
	set -euo pipefail
	echo "🚀 Initiating Fast Release Sequence v{{version}}..."
	if [[ -n "${JANITOR_GPG_PASSPHRASE:-}" ]]; then
	    PRESET_BIN="$(command -v gpg-preset-passphrase 2>/dev/null \
	        || find /usr/lib/gnupg /usr/libexec/gnupg /opt/homebrew/libexec/gpg \
	               -name gpg-preset-passphrase -print -quit 2>/dev/null || true)"
	    if [[ -n "${PRESET_BIN}" ]]; then
	        printf '%s' "${JANITOR_GPG_PASSPHRASE}" | "${PRESET_BIN}" --preset EA20B816F8A1750EB737C4E776AE1CBD050A171E
	    fi
	fi
	if ! printf 'janitor-release-preflight' | gpg --batch --yes --pinentry-mode error --clearsign --local-user 4D68C2E93C07B38131E1CD2C7643B04E9C8FE26F >/dev/null 2>&1; then
	    echo "error: GPG signing key is locked; run gpg-unlock or export JANITOR_GPG_PASSPHRASE before just fast-release {{version}}" >&2
	    exit 1
	fi
	just sync-versions
	just audit
	cargo build --release --workspace
	strip target/release/janitor
	# SLSA Level 4: compute SHA-384 digest (and optional ML-DSA-65 sig) for binary provenance.
	# Produces target/release/janitor.sha384 always; target/release/janitor.sig if JANITOR_PQC_KEY is set.
	SIGN_ARGS=(target/release/janitor)
	if [[ -n "${JANITOR_PQC_KEY:-}" ]]; then
	    SIGN_ARGS+=(--pqc-key "${JANITOR_PQC_KEY}")
	fi
	./target/release/janitor sign-asset "${SIGN_ARGS[@]}"
	# Idempotency guard — check local and remote before any mutation (Law: idempotency.md).
	if git rev-parse "v{{version}}" >/dev/null 2>&1 \
	   || git ls-remote --tags origin "refs/tags/v{{version}}" | grep -q .; then
	    echo "Idempotency guard: Release v{{version}} already exists. Halting gracefully."
	    exit 0
	fi
	git add crates/ tools/ docs/ .agent_governance/ Cargo.toml Cargo.lock README.md mkdocs.yml justfile action.yml && git commit -S -m "chore: release v{{version}}"
	git tag -s v{{version}} -m "release v{{version}}"
	MAJOR="$(echo "{{version}}" | cut -d. -f1)"
	git tag -fa "v${MAJOR}" -m "v${MAJOR} → v{{version}}"
	git push origin HEAD:main "v{{version}}"
	git push origin "v${MAJOR}" --force
	if gh release view "v{{version}}" >/dev/null 2>&1; then
	    echo "Idempotency guard: GitHub Release v{{version}} already exists. Skipping gh release create."
	else
	    RELEASE_ASSETS=(target/release/janitor target/release/janitor.sha384)
	    [ -f target/release/janitor.sig ] && RELEASE_ASSETS+=(target/release/janitor.sig)
	    gh release create v{{version}} \
	        --generate-notes \
	        --title "The Janitor v{{version}}" \
	        "${RELEASE_ASSETS[@]}"
	fi
	just deploy-docs
	echo "💀 Release v{{version}} deployed."

# 5. SINGLE-REPO FORENSIC STRIKE
#
# Runs the full 7-artefact forensic pipeline against one repository:
#   PDF intelligence report + 16-col CSV audit trail + aggregate JSON
#   + CycloneDX CBOM + per-repo intel JSON + VEX document + case-study.md
#
# Delegates entirely to tools/generate_client_package.sh which handles
# the build, hyper-drive bounce, attestation, and synthesis steps.
# Output lands in strikes/<repo_name>/ (workspace-isolated).
#
# Usage:
#   just strike godotengine/godot          # 1000 PRs (default)
#   just strike kubernetes/kubernetes 5000 # custom PR limit
#   just strike NixOS/nixpkgs 50
#
strike repo pr_limit='1000':
	PR_LIMIT={{pr_limit}} ./tools/generate_client_package.sh {{repo}}

# 6a. FUZZ CORPUS PROMOTION — minimize libFuzzer crash/timeout artifacts and
#     install them as deterministic Crucible exhaustion fixtures.
#
# Usage:
#   just promote-fuzz <ARTIFACT_DIR>
#
promote-fuzz artifact_dir:
	#!/usr/bin/env bash
	set -euo pipefail
	bash ./tools/promote_fuzz_corpus.sh "{{artifact_dir}}"

# 6b. PUBLISH FORENSIC STRIKE — execute strike + publish evidence + update intelligence index
#
# Wraps publish_forensic_strike.sh.  Runs generate_client_package.sh internally,
# so there is no need to call `just strike` separately first.
#
# Usage:
#   just publish-strike vercel/next.js
#   just publish-strike godotengine/godot
#   SKIP_STRIKE=1 just publish-strike godotengine/godot   # reuse existing artefacts
#
publish-strike repo:
	./tools/publish_forensic_strike.sh {{repo}}

# 6c. STRIKE PIPELINE TESTS — regression harness for generate_client_package.sh
#     and publish_forensic_strike.sh
#
# Verifies: binary --version contract, script hygiene, argument contract,
# artefact manifest integrity.  Requires a built release binary.
#
# Usage:
#   just test-strike-pipeline
#
test-strike-pipeline:
	./tools/tests/test_strike_pipeline.sh

# 7. DOCUMENTATION
deploy-docs:
	#!/usr/bin/env bash
	set -euo pipefail
	for attempt in 1 2 3; do
	    if uv run --with "mkdocs-material<9.6" --with "mkdocs<2" mkdocs gh-deploy --force; then
	        exit 0
	    fi
	    if [[ "${attempt}" -eq 3 ]]; then
	        exit 1
	    fi
	    echo "warning: gh-pages deploy race detected; retrying in 2s (attempt ${attempt}/3 failed)" >&2
	    sleep 2
	done

# 8. LOCAL BRANCH INTEGRITY CHECK
#
# Fast pre-merge verification of a local branch against main.
# Runs the full bounce pipeline (git-native mode) without any network calls
# or cloning — reads directly from the local packfile.
#
# Usage:
#   just check-branch dependabot/cargo/serde-1.0.200
#   just check-branch my-feature-branch 42          # with PR number for log entry
#
check-branch branch pr='0':
	#!/usr/bin/env bash
	set -euo pipefail
	REPO_SLUG="$(git config --get remote.origin.url | sed -e 's/.*github.com[:/]//' -e 's/\.git$//')"
	[[ -n "${REPO_SLUG}" ]] || { echo "error: could not resolve repo slug from git remote" >&2; exit 1; }
	BASE_SHA="$(git rev-parse main)"
	# Resolve branch to a commit SHA.  Resolution order:
	#   1. Local branch ref (already checked out)
	#   2. Remote-tracking ref (already fetched)
	#   3. Locally cached PR ref from a prior fetch
	#   4. Fetch via GitHub pull-request ref (works even when branch names
	#      differ from the remote due to encoding, e.g. hyphens vs underscores
	#      in Dependabot branch names)
	PR_NUM="{{pr}}"
	HEAD_SHA="$(git rev-parse --verify "{{branch}}" 2>/dev/null \
	    || git rev-parse --verify "refs/remotes/origin/{{branch}}" 2>/dev/null \
	    || { [[ "${PR_NUM}" != "0" ]] && git rev-parse --verify "refs/remotes/origin/pr/${PR_NUM}" 2>/dev/null; } \
	    || { [[ "${PR_NUM}" != "0" ]] && git fetch --quiet origin "+refs/pull/${PR_NUM}/head:refs/remotes/origin/pr/${PR_NUM}" 2>/dev/null && git rev-parse "refs/remotes/origin/pr/${PR_NUM}"; } \
	    || true)"
	[[ -n "${HEAD_SHA}" ]] || { echo "error: could not resolve SHA for branch '{{branch}}' (pr={{pr}})" >&2; exit 1; }
	./target/release/janitor bounce . --repo . --base "${BASE_SHA}" --head "${HEAD_SHA}" \
	    --pr-number {{pr}} --repo-slug "${REPO_SLUG}" --format json

# 9. WINDOWS SYNC
sync:
	@echo "🪟 Syncing to Windows mount..."
	rsync -av --delete \
		--exclude 'target' \
		--exclude '.git' \
		--exclude '.janitor/shadow_src' \
		. /mnt/c/Projects/the-janitor/
	@echo "✅ Windows sync complete."
