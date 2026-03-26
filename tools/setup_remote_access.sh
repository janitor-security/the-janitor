#!/usr/bin/env bash
# setup_remote_access.sh — Zero-Trust remote access setup via Tailscale SSH.
#
# Run this once on the workstation before leaving. Once the Tailnet IP is
# established, connect from any device with:
#
#   ssh <user>@<tailscale-ip>
#
# Then launch the gauntlet from the remote session:
#
#   cd ~/dev/the-janitor
#   just hyper-gauntlet
set -euo pipefail

# ── 1. Tailscale install (idempotent) ─────────────────────────────────────────
if ! command -v tailscale &>/dev/null; then
    echo "==> Installing Tailscale (pinned v1.78.1 via apt)..."
    # Use the signed APT repository — avoids the curl-pipe-sh supply chain risk.
    # To update: bump TAILSCALE_VERSION and re-run.
    TAILSCALE_VERSION="1.78.1"
    curl -fsSL https://pkgs.tailscale.com/stable/debian/bookworm.noarmor.gpg \
        | sudo tee /usr/share/keyrings/tailscale-archive-keyring.gpg >/dev/null
    echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] \
        https://pkgs.tailscale.com/stable/debian bookworm main" \
        | sudo tee /etc/apt/sources.list.d/tailscale.list
    sudo apt-get update -qq
    sudo apt-get install -y "tailscale=${TAILSCALE_VERSION}"
else
    echo "==> Tailscale already installed: $(tailscale version | head -1)"
fi

# ── 2. Enable Tailscale SSH ───────────────────────────────────────────────────
echo "==> Enabling Tailscale SSH..."
sudo tailscale up --ssh
echo ""
echo "══════════════════════════════════════════════════════════════════"
echo "  Remote access established."
echo "  Tailnet IP: $(tailscale ip -4 2>/dev/null || echo 'check Tailscale admin console')"
echo ""
echo "  Connect from any device on your Tailnet:"
echo "    ssh $(whoami)@<tailscale-ip>"
echo ""
echo "  Then run the gauntlet:"
echo "    cd ~/dev/the-janitor && just hyper-gauntlet"
echo "══════════════════════════════════════════════════════════════════"
