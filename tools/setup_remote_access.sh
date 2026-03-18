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
    echo "==> Installing Tailscale..."
    curl -fsSL https://tailscale.com/install.sh | sh
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
