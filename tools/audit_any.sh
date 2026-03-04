#!/bin/bash
# USAGE: ./tools/audit_any.sh <owner/repo>

set -euo pipefail

if [ -z "${1:-}" ]; then
    echo "Usage: ./tools/audit_any.sh <owner/repo>"
    exit 1
fi

export REPO_SLUG="$1"
SAFE_NAME=$(basename "$REPO_SLUG")

# Dynamically override the defaults in audit_real_prs.sh
export GODOT_REPO="$HOME/dev/gauntlet/$SAFE_NAME"
export CACHE_FILE="$HOME/.janitor/${SAFE_NAME}_pr_cache.json"
export PROGRESS_FILE="$HOME/.janitor/${SAFE_NAME}_progress.txt"
REPORT_OUT="${SAFE_NAME}_live_pr_audit.md"

echo "🚀 Target acquired: $REPO_SLUG"

# 1. Clone if missing (Shallow clone, no full history)
if [ ! -d "$GODOT_REPO" ]; then
    echo "Cloning $REPO_SLUG..."
    git clone --depth 1 "https://github.com/$REPO_SLUG" "$GODOT_REPO"
fi

# 2. Execute the Strike
echo "⚡ Running Janitor strike..."
./tools/audit_real_prs.sh "$REPORT_OUT"