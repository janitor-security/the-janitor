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
	cargo test --workspace
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
bump-version version:
	@echo "📈 Bumping version to {{version}}..."
	# Rust manifests — workspace root + all crates + tools
	sed -i 's/^version = ".*"/version = "{{version}}"/' Cargo.toml
	find crates tools -name "Cargo.toml" -exec sed -i 's/^version = ".*"/version = "{{version}}"/' {} +
	# Markdown docs — v-prefixed version strings (README.md, docs/index.md)
	sed -i 's/v[0-9]\+\.[0-9]\+\.[0-9]\+\(-[a-zA-Z0-9]\+\)\?/v{{version}}/g' README.md
	sed -i 's/v[0-9]\+\.[0-9]\+\.[0-9]\+\(-[a-zA-Z0-9]\+\)\?/v{{version}}/g' docs/index.md
	# ARCHITECTURE.md — two VERSION patterns: header (**VERSION:** x) and footer (**VERSION: x**)
	sed -i 's/\*\*VERSION:\*\* [0-9]\+\.[0-9]\+\.[0-9]\+\(-[a-zA-Z0-9]\+\)\?/\*\*VERSION:\*\* {{version}}/' ARCHITECTURE.md
	sed -i 's/\*\*VERSION: [0-9]\+\.[0-9]\+\.[0-9]\+\(-[a-zA-Z0-9]\+\)\?\*\*/\*\*VERSION: {{version}}\*\*/' ARCHITECTURE.md
	# CLAUDE.md — local working doc (gitignored); update if present
	sed -i 's/\*\*Current Version\*\*: `[0-9]\+\.[0-9]\+\.[0-9]\+`/\*\*Current Version\*\*: `{{version}}`/' CLAUDE.md 2>/dev/null || true
	cargo check > /dev/null 2>&1 || true
	@echo "✅ Manifests updated."

release version: audit (bump-version version)
	@echo "🚀 Initiating Release Sequence v{{version}}..."
	cargo build --release --workspace
	strip target/release/janitor
	git add .
	git commit -m "chore: release v{{version}}"
	git tag v{{version}}
	# Floating major-version tag (@v6) — lets users pin to a major and
	# always receive the latest stable patch without editing their workflows.
	MAJOR="$(echo "{{version}}" | cut -d. -f1)" && git tag -fa "v${MAJOR}" -m "v${MAJOR} → v{{version}}"
	git push origin HEAD:main "v{{version}}"
	git push origin "v$(echo "{{version}}" | cut -d. -f1)" --force
	"/mnt/c/Program Files/GitHub CLI/gh.exe" release create v{{version}} target/release/janitor \
		--title "v{{version}} - The Industrial Pivot" \
		--notes-file README.md \
		--latest
	uv run --with "mkdocs-material<9.6" --with "mkdocs<2" mkdocs gh-deploy --force
	@echo "💀 Release v{{version}} deployed."

# 5. MULTI-REPO GAUNTLET
# Deterministic Rust orchestrator replacing ultimate_gauntlet.sh.
# Reads gauntlet_targets.txt (one owner/repo per line), bounces PRs in parallel
# within each repo (hardware-aware concurrency: auto-detected from system RAM),
# then generates a global PDF + CSV export.
#
# Concurrency tiers (auto-detected via --concurrency 0):
#   < 8 GiB RAM  → 2 workers (Safety Mode)
#   8–16 GiB     → 4 workers
#   16–32 GiB    → 8 workers
#   > 32 GiB     → logical CPU count (Aggressive Mode)
#
# Usage:
#   just run-gauntlet                             # defaults from gauntlet_targets.txt
#   just run-gauntlet --pr-limit 50               # 50 PRs per repo
#   just run-gauntlet --pr-limit 5000 --timeout 60
#   just run-gauntlet --targets my_repos.txt --out-dir ~/Desktop
#   just run-gauntlet --concurrency 4             # manual override
#
run-gauntlet *ARGS:
	#!/usr/bin/env bash
	set -euo pipefail
	if [[ -z "${IN_NIX_SHELL:-}" ]] && command -v nix &>/dev/null; then
	    echo "↳ Entering Nix hermetic shell..."
	    exec nix develop --command just run-gauntlet {{ARGS}}
	fi
	cargo build --release -p gauntlet-runner
	./target/release/gauntlet-runner {{ARGS}}

# Hyper-Gauntlet — libgit2 O(1) network-bypass global audit across all targets.
#
# Clones each repo once, populates refs/remotes/origin/pr/*, then
# scores every PR directly from the packfile — zero `gh pr diff` subshells.
#
# Usage:
#   just hyper-gauntlet                     # 5000 PRs per repo (default)
#   just hyper-gauntlet --pr-limit 500      # custom limit
#   just hyper-gauntlet --targets my.txt    # custom targets file
#
hyper-gauntlet *ARGS:
	#!/usr/bin/env bash
	set -euo pipefail
	if [[ -z "${IN_NIX_SHELL:-}" ]] && command -v nix &>/dev/null; then
	    echo "↳ Entering Nix hermetic shell..."
	    exec nix develop --command just hyper-gauntlet {{ARGS}}
	fi
	cargo build --release -p gauntlet-runner -p cli
	./target/release/gauntlet-runner --hyper --pr-limit 5000 {{ARGS}}

# 6. SINGLE-REPO FORENSIC STRIKE
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

# 7. DOCUMENTATION
deploy-docs:
	uv run --with "mkdocs-material<9.6" --with "mkdocs<2" mkdocs gh-deploy --force

# 8. WINDOWS SYNC
sync:
	@echo "🪟 Syncing to Windows mount..."
	rsync -av --delete \
		--exclude 'target' \
		--exclude '.git' \
		--exclude '.janitor/shadow_src' \
		. /mnt/c/Projects/the-janitor/
	@echo "✅ Windows sync complete."