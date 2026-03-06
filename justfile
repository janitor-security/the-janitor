set shell := ["bash", "-c"]
export PATH := env_var("HOME") + "/.local/bin:" + env_var("PATH")

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
audit:
	@echo "🔍 Auditing Codebase..."
	cargo fmt --all -- --check
	cargo clippy --workspace -- -D warnings
	cargo check --workspace
	cargo test --workspace
	@echo "✅ System Clean."

build:
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

# 5. DOCUMENTATION
deploy-docs:
	uv run --with "mkdocs-material<9.6" --with "mkdocs<2" mkdocs gh-deploy --force

# 6. WINDOWS SYNC
sync:
	@echo "🪟 Syncing to Windows mount..."
	rsync -av --delete \
		--exclude 'target' \
		--exclude '.git' \
		--exclude '.janitor/shadow_src' \
		. /mnt/c/Projects/the-janitor/
	@echo "✅ Windows sync complete."