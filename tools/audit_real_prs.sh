#!/usr/bin/env bash
# tools/audit_real_prs.sh — THE CRUCIBLE
#
# Live GitHub PR Social Forensics Audit for godotengine/godot.
#
# Fetches the last N open PRs via `gh pr diff` (no local clone needed),
# and bounces each through the full Janitor pipeline including:
#   - Structural dead-symbol detection (PatchBouncer)
#   - Logic-clone detection (BLAKE3 SimHash)
#   - Comment Social Forensics (AhoCorasick banned phrases)
#   - PR Metadata Forensics (unlinked issue check)
#
# Populates: $GODOT_REPO/.janitor/bounce_log.ndjson
# Report:    $REPORT_OUT (default: godot_live_pr_audit.md)
#
# Usage:
#   ./tools/audit_real_prs.sh [report_output.md]
#
# Environment overrides:
#   JANITOR    — path to janitor binary   (default: ./target/release/janitor)
#   GODOT_REPO — path to godot source dir (default: ~/dev/gauntlet/godot)
#   PR_LIMIT   — number of PRs to fetch   (default: 50)

set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
JANITOR="${JANITOR:-$(pwd)/target/release/janitor}"
GODOT_REPO="${GODOT_REPO:-$HOME/dev/gauntlet/godot}"
REPORT_OUT="${1:-godot_live_pr_audit.md}"
REPO_SLUG="godotengine/godot"
PR_LIMIT="${PR_LIMIT:-50}"
BODY_MAX_BYTES=4096   # clamp PR bodies; avoids arg-list overflow on massive changelogs

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m' YLW='\033[0;33m' GRN='\033[0;32m' DIM='\033[2m' NC='\033[0m'
else
    RED='' YLW='' GRN='' DIM='' NC=''
fi
info()  { echo -e "${GRN}==>${NC} $*"; }
warn()  { echo -e "${YLW}WARN${NC}  $*"; }
fail()  { echo -e "${RED}FAIL${NC}  $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
for dep in gh jq awk; do
    command -v "$dep" >/dev/null 2>&1 || {
        fail "'$dep' not found in PATH — aborting."
        exit 1
    }
done

if [[ ! -x "$JANITOR" ]]; then
    fail "janitor binary not found at $JANITOR"
    echo "      Run: cargo build --release --bin janitor"
    exit 1
fi

if [[ ! -d "$GODOT_REPO" ]]; then
    fail "Godot source dir not found at $GODOT_REPO"
    exit 1
fi

info "Janitor : $JANITOR"
info "Repo    : $GODOT_REPO"
info "Output  : $REPORT_OUT"
echo ""

# ── Registry bootstrap ────────────────────────────────────────────────────────
REGISTRY="$GODOT_REPO/.janitor/symbols.rkyv"
if [[ ! -f "$REGISTRY" ]]; then
    info "No registry found — running janitor scan (~30 s)..."
    "$JANITOR" scan "$GODOT_REPO" --format json >/dev/null 2>&1
    info "Scan complete. Registry written to $REGISTRY"
fi

# Clear stale bounce log so the report reflects only this crucible run.
BOUNCE_LOG="$GODOT_REPO/.janitor/bounce_log.ndjson"
if [[ -f "$BOUNCE_LOG" ]]; then
    warn "Clearing existing bounce_log.ndjson (stale from previous runs)"
    : > "$BOUNCE_LOG"
fi

# ── Fetch PR list ─────────────────────────────────────────────────────────────
info "Fetching $PR_LIMIT open PRs from $REPO_SLUG via gh..."
PR_JSON=$(gh pr list \
    --repo   "$REPO_SLUG" \
    --state  open \
    --limit  "$PR_LIMIT" \
    --json   number,author,body)

TOTAL=$(echo "$PR_JSON" | jq 'length')
info "Got $TOTAL PRs. Entering the Crucible..."
echo ""

# ── Counters ──────────────────────────────────────────────────────────────────
BOUNCED=0; SKIPPED=0; ERRORS=0
UNLINKED_COUNT=0; COMMENT_VIOLATIONS=0; HIGH_SCORE=0; HIGH_PR=0

# ── Per-PR bounce loop ────────────────────────────────────────────────────────
while IFS= read -r PR; do
    NUMBER=$(echo "$PR" | jq -r '.number')
    AUTHOR=$(echo "$PR" | jq -r '.author.login // "unknown"')
    # Truncate body; strip null bytes that would break clap argument parsing.
    BODY=$(echo "$PR" | jq -r '.body // ""' | head -c "$BODY_MAX_BYTES" | tr -d '\000')

    printf "  PR #%-5s %-22s  " "$NUMBER" "($AUTHOR)"

    # ── Fetch diff from GitHub via gh pr diff ──────────────────────────────
    PATCH_FILE=$(mktemp /tmp/janitor_crucible_XXXXXX.patch)
    trap 'rm -f "$PATCH_FILE"' EXIT

    # gh pr diff fetches the unified diff from GitHub API.
    # Filter out thirdparty/ and binary image files with awk.
    if ! gh pr diff "$NUMBER" --repo "$REPO_SLUG" 2>/dev/null \
        | awk '
            /^diff --git/ {
                skip = ($3 ~ /^a\/thirdparty\// ||
                        $3 ~ /\.(png|jpg|jpeg|svg|gif|ico|webp|ttf|otf|woff)$/)
            }
            !skip { print }
        ' > "$PATCH_FILE"; then
        echo "[SKIP: gh pr diff failed]"
        rm -f "$PATCH_FILE"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    if [[ ! -s "$PATCH_FILE" ]]; then
        echo "[SKIP: empty diff — pure thirdparty or binary changes]"
        rm -f "$PATCH_FILE"
        SKIPPED=$((SKIPPED + 1))
        continue
    fi

    PATCH_BYTES=$(wc -c < "$PATCH_FILE")

    # ── Bounce ────────────────────────────────────────────────────────────────
    # --format json so we can parse individual score components inline.
    # bounce_log.ndjson is populated as a side-effect regardless of format.
    RESULT=$("$JANITOR" bounce "$GODOT_REPO" \
        --patch      "$PATCH_FILE" \
        --pr-number  "$NUMBER"     \
        --author     "$AUTHOR"     \
        --pr-body    "$BODY"       \
        --format     json          \
        2>/dev/null) && EXIT_CODE=0 || EXIT_CODE=$?

    rm -f "$PATCH_FILE"
    trap - EXIT

    if [[ $EXIT_CODE -ne 0 ]]; then
        echo "[ERROR: bounce returned $EXIT_CODE]"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    # ── Parse score components ────────────────────────────────────────────────
    SCORE=$(  echo "$RESULT" | jq -r '.slop_score        // 0')
    DEAD=$(   echo "$RESULT" | jq -r '.dead_symbols_added // 0')
    CLONES=$( echo "$RESULT" | jq -r '.logic_clones_found // 0')
    ZOMBIES=$(echo "$RESULT" | jq -r '.zombie_symbols_added // 0')
    ANTI=$(   echo "$RESULT" | jq -r '.antipatterns_found // 0')
    CVIOL=$(  echo "$RESULT" | jq -r '.comment_violations // 0')
    UNLINK=$( echo "$RESULT" | jq -r '.unlinked_pr        // 0')

    # ── Build flag string for display ─────────────────────────────────────────
    FLAGS=""
    [[ "$UNLINK"  == "1"     ]] && FLAGS="${FLAGS}${YLW}[NO-ISSUE-LINK]${NC} "
    [[ "$CVIOL"   -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[COMMENT×${CVIOL}]${NC} "
    [[ "$ANTI"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[ANTIPATTERN×${ANTI}]${NC} "
    [[ "$DEAD"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[DEAD×${DEAD}]${NC} "
    [[ "$CLONES"  -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[CLONE×${CLONES}]${NC} "
    [[ "$ZOMBIES" -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[ZOMBIE×${ZOMBIES}]${NC} "

    printf "score=%-4s  diff=%5d B  %b\n" "$SCORE" "$PATCH_BYTES" "${FLAGS:-${GRN}CLEAN${NC}}"

    # ── Running totals ────────────────────────────────────────────────────────
    BOUNCED=$((BOUNCED + 1))
    [[ "$UNLINK" == "1" ]] && UNLINKED_COUNT=$((UNLINKED_COUNT + 1))
    [[ "$CVIOL" -gt 0 ]] 2>/dev/null && COMMENT_VIOLATIONS=$((COMMENT_VIOLATIONS + CVIOL))
    if [[ "$SCORE" -gt "$HIGH_SCORE" ]] 2>/dev/null; then
        HIGH_SCORE=$SCORE; HIGH_PR=$NUMBER
    fi

done < <(echo "$PR_JSON" | jq -c '.[]')

# ── Crucible summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}══════════════════════════════════════════════${NC}"
echo   "  Crucible complete"
echo   "  PRs bounced        : $BOUNCED"
echo   "  PRs skipped        : $SKIPPED  (empty / binary-only diffs)"
echo   "  Errors             : $ERRORS"
echo   "  Unlinked PRs       : $UNLINKED_COUNT  (no Closes/Fixes #N)"
echo   "  Comment violations : $COMMENT_VIOLATIONS  (AI-isms / profanity in diff)"
[[ "$HIGH_PR" -gt 0 ]] && echo "  Highest slop score : $HIGH_SCORE  (PR #$HIGH_PR)"
echo -e "${GRN}══════════════════════════════════════════════${NC}"
echo ""

# ── Generate intelligence report ─────────────────────────────────────────────
info "Generating report → $REPORT_OUT"
"$JANITOR" report \
    --repo   "$GODOT_REPO" \
    --top    50            \
    --format markdown      \
    --out    "$REPORT_OUT"

info "Done. Intelligence report: $REPORT_OUT"
