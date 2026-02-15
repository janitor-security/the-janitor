set shell := ["bash", "-c"]

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
	cargo new --lib crates/supervisor
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
	@echo "💥 Target directory vaporized."

# 3. AUTHENTICATION
auth-refresh:
	@echo "Auth is stateless — token injected at runtime via --token flag."

# 4. RELEASE PROTOCOL
bump-version version:
	@echo "📈 Bumping version to {{version}}..."
	sed -i 's/^version = ".*"/version = "{{version}}"/' Cargo.toml
	find crates -name "Cargo.toml" -exec sed -i 's/^version = ".*"/version = "{{version}}"/' {} +
	sed -i 's/v[0-9]\+\.[0-9]\+\.[0-9]\+\(-[a-zA-Z0-9]\+\)\?/v{{version}}/g' README.md
	cargo check > /dev/null 2>&1 || true
	@echo "✅ Manifests updated."

release version: audit (bump-version version)
	@echo "🚀 Initiating Release Sequence v{{version}}..."
	git add .
	git commit -m "chore: release v{{version}}"
	git tag v{{version}}
	git push origin main --force --tags
	@echo "💀 Release v{{version}} deployed."