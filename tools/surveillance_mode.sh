#!/usr/bin/env bash
# surveillance_mode.sh — Zero-Trust remote access + parametric Gauntlet orchestrator.
#
# Accepts any number of owner/repo slugs.  Runs each target sequentially so
# there is no OS-level memory pressure or Git index lock contention between repos.
#
# Usage:
#   ./tools/surveillance_mode.sh <owner/repo1> [owner/repo2 ...]
#
# Examples:
#   ./tools/surveillance_mode.sh godotengine/godot NixOS/nixpkgs
#   ./tools/surveillance_mode.sh godotengine/godot NixOS/nixpkgs apache/kafka
#
# Remote access (from any device on your Tailnet):
#   ssh <user>@<tailscale-ip>
set -euo pipefail

if [[ $# -eq 0 ]]; then
    echo "Usage: ./tools/surveillance_mode.sh <owner/repo1> <owner/repo2> ..." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
GAUNTLET_DIR="${GAUNTLET_DIR:-$HOME/dev/gauntlet}"

# ── 1. Tailscale install (idempotent) ─────────────────────────────────────────
if ! command -v tailscale &>/dev/null; then
    echo "==> Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
else
    echo "==> Tailscale already installed: $(tailscale version | head -1)"
fi

# ── 2. Enable Tailscale SSH ───────────────────────────────────────────────────
echo "==> Enabling Tailscale SSH..."
sudo tailscale up --ssh
echo "    Tailnet IP: $(tailscale ip -4 2>/dev/null || echo 'not yet assigned')"

cd "$REPO_ROOT"

# ── 3. Compilation guarantee ──────────────────────────────────────────────────
echo "======================================================"
echo "COMPILING APEX BINARY (v7.0.0)..."
echo "======================================================"
just build

# ── 4. Cache purge — corrupted bounce log / PR metadata ──────────────────────
rm -f ~/dev/gauntlet/godotengine/godot/.janitor/bounce_log.ndjson
rm -f ~/dev/gauntlet/NixOS/nixpkgs/.janitor/bounce_log.ndjson
rm -f ~/.janitor/*_pr_cache.json

# ── 5. Sequential strike loop ─────────────────────────────────────────────────
for REPO in "$@"; do
    # Derive the bare repo name the same way the justfile does:
    #   REPO_NAME="${REPO_SLUG##*/}"
    # so godotengine/godot → godot, NixOS/nixpkgs → nixpkgs.
    REPO_NAME="${REPO##*/}"

    echo ""
    echo "======================================================"
    echo "TARGET ACQUIRED: $REPO"
    echo "======================================================"

    echo "Purging bounce log for $REPO..."
    rm -f "$GAUNTLET_DIR/$REPO_NAME/.janitor/bounce_log.ndjson"
    # PR metadata cache is intentionally preserved across runs to save GitHub
    # API quota on PRs that have not changed since the last harvest.

    # ── Phase 1 fetch: populate refs/remotes/origin/pr/* ─────────────────
    REPO_DIR="$GAUNTLET_DIR/$REPO_NAME"
    if [[ -d "$REPO_DIR/.git" ]]; then
        echo "Populating PR refs for $REPO (Phase 1 fetch)..."
        git -C "$REPO_DIR" config --local --add remote.origin.fetch \
            '+refs/pull/*/head:refs/remotes/origin/pr/*' 2>/dev/null || true
        git -C "$REPO_DIR" fetch origin --no-tags --force --quiet
        echo "    PR refs ready."
    fi

    echo "Initiating Parallel Strike for $REPO..."
    PR_LIMIT=5000 BOUNCE_TIMEOUT=20 just parallel-audit "$REPO" 5000 20 || true

    # SCORCH EARTH: delete the local clone to reclaim SSD space.
    # Runs unconditionally (even on audit failure) via the `|| true` above.
    echo "Audit complete. Scorch earth: deleting $REPO_DIR..."
    rm -rf "$REPO_DIR"
    echo "    Deleted → $REPO_DIR"
done

echo ""
echo "======================================================"
echo "SURVEILLANCE MATRIX COMPLETE."
echo "======================================================"
