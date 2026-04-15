#!/usr/bin/env bash
set -euo pipefail

# This script must be run from the root of the janitor-security/the-janitor repository.
# It first builds the engine, then uses it to conduct offensive strikes against public targets.

# --- [PREFLIGHT] ---
echo "--- [PREFLIGHT] Building Janitor Engine ---"
# Compile the release binary. This is our weapon.
just build

# Capture the absolute path of the project root. This is our anchor.
PROJECT_ROOT=$(pwd)
# Construct an absolute, undeniable path to the binary. This is immune to 'cd'.
JANITOR_BIN="${PROJECT_ROOT}/target/release/janitor"

# --- [TARGETING] ---
# The mathematical "nothing" in Git's object model.
EMPTY_TREE_HASH="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

targets=(
    "https://github.com/auth0/auth0-java"
    "https://github.com/auth0/auth0-php"
    "https://github.com/zendesk/zendesk_api_client_rb"
    "https://github.com/pinterest/gestalt"
    "https://github.com/Aiven-Open/karapace"
)

# --- [EXECUTION] ---
STRIKE_ROOT="bug_hunt_strikes"
mkdir -p "$STRIKE_ROOT"

for repo_url in "${targets[@]}"; do
    repo_slug=$(basename "$repo_url")
    echo "--- [HUNTING] Targeting ${repo_slug} ---"

    # Clone the target repository into a temporary hunt directory.
    strike_dir="${STRIKE_ROOT}/${repo_slug}"
    rm -rf "$strike_dir" # Ensure a clean state
    git clone --depth 1 "$repo_url" "$strike_dir"

    pushd "$strike_dir" > /dev/null

    # Generate the full-repo patch file.
    git diff "$EMPTY_TREE_HASH" HEAD > full_repo.patch

    # Execute the bounce engine using the absolute path to the binary.
    mkdir -p .janitor
    "$JANITOR_BIN" bounce . \
        --patch full_repo.patch \
        --pr-number 1337 \
        --author "sovereign-operator" \
        | tee hunt_results.log

    # Hunt for the high-signal findings in the JSON output.
    echo "--- [RESULTS] High-Signal Findings for ${repo_slug} ---"
    if [ -f ".janitor/bounce_log.ndjson" ]; then
        # Use jq to extract only the critical security findings and format them for a human.
        jq -r '
            .structured_findings[] | 
            select(.id | startswith("security:")) | 
            "  [!] CRITICAL FINDING: \(.id)\n      File: \(.file)\n      Line: \(.line)\n      Remediation: \(.remediation)"
        ' .janitor/bounce_log.ndjson || echo "  [-] No critical 'security:' findings detected."
    else
        echo "Bounce log not found. Scan may have failed."
    fi

    popd > /dev/null
done

echo "--- [HUNT COMPLETE] ---"