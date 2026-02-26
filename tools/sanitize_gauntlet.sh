#!/bin/bash
# MISSION: SANITIZE GAUNTLET
# TARGET: ~/dev/gauntlet/*

GAUNTLET_DIR="$HOME/dev/gauntlet"

if [ ! -d "$GAUNTLET_DIR" ]; then
    echo "❌ Error: Gauntlet directory $GAUNTLET_DIR not found."
    exit 1
fi

echo "🧹 Starting Sanitation Protocol..."

for repo in "$GAUNTLET_DIR"/*; do
    if [ -d "$repo/.git" ]; then
        echo "---------------------------------------------------"
        echo "⚡ Processing: $(basename "$repo")"
        cd "$repo" || continue

        # 1. Fetch latest metadata
        echo "   -> Fetching updates..."
        git fetch --all --prune --quiet

        # 2. Determine default branch (main or master)
        # We look for where 'origin/HEAD' points
        git remote set-head origin -a > /dev/null 2>&1
        DEFAULT_BRANCH=$(git symbolic-ref refs/remotes/origin/HEAD | sed 's@^refs/remotes/origin/@@')

        if [ -z "$DEFAULT_BRANCH" ]; then
            echo "   ⚠️  Could not detect default branch. Skipping reset."
            continue
        fi

        # 3. Hard Reset (Destructive)
        echo "   -> Resetting to origin/$DEFAULT_BRANCH..."
        git checkout "$DEFAULT_BRANCH" --quiet
        git reset --hard "origin/$DEFAULT_BRANCH" --quiet

        # 4. Nuke Untracked Files (Build artifacts, temp files)
        # -f = force, -d = directories, -x = ignored files (targets)
        echo "   -> Nuking untracked files..."
        git clean -fdx

        echo "   ✅ Clean & Synced."
    fi
done

echo "---------------------------------------------------"
echo "🏁 Sanitation Complete. The Gauntlet is ready."