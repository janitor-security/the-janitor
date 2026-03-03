#!/usr/bin/env bash
# tools/audit_real_prs.sh — THE CRUCIBLE v3 (gh-diff Edition)
#
# Full-corpus PR audit for godotengine/godot.  Designed to handle 4,600+ PRs.
#
# Diff strategy: gh pr diff (same as ultimate_gauntlet.sh — proven to work).
#   1. One `gh pr list --limit 5000` batch call → ~/.janitor/pr_cache_full.json
#      (API cost: 1 request per run.  Cached until you delete it.)
#   2. Per-PR: `gh pr diff <N> --repo <slug>` — GitHub returns the mergeable
#      PR diff, correctly scoped and sized.  No local git clone required.
#
# Progress tracking: ~/.janitor/crucible_progress.txt (one PR number per line).
# The script skips already-processed PRs on restart — safe to Ctrl-C and resume.
#
# Usage:
#   ./tools/audit_real_prs.sh [report_output.md]
#
# Environment overrides:
#   JANITOR        — janitor binary         (default: ./target/release/janitor)
#   GODOT_REPO     — source snapshot root   (default: ~/dev/gauntlet/godot)
#   CACHE_FILE     — PR list JSON cache     (default: ~/.janitor/pr_cache_full.json)
#   PROGRESS_FILE  — resumable progress log (default: ~/.janitor/crucible_progress.txt)
#   PR_LIMIT       — max PRs to cache       (default: 5000)
#   BOUNCE_TIMEOUT — seconds per bounce     (default: 60)
#   REPO_SLUG      — GitHub owner/repo      (default: godotengine/godot)

set -uo pipefail

# Declare the resume-progress associative array at global scope BEFORE any
# conditional blocks.  With set -u, bash can fire "unbound variable" on
# ${DONE_PRS[$KEY]-} if the array was declared later in a branch that didn't
# run yet.  Global declaration guarantees the array always exists.
declare -A DONE_PRS

# ── Configuration ─────────────────────────────────────────────────────────────
JANITOR="${JANITOR:-$(pwd)/target/release/janitor}"
GODOT_REPO="${GODOT_REPO:-$HOME/dev/gauntlet/godot}"
CACHE_FILE="${CACHE_FILE:-$HOME/.janitor/pr_cache_full.json}"
PROGRESS_FILE="${PROGRESS_FILE:-$HOME/.janitor/crucible_progress.txt}"
REPORT_OUT="${1:-godot_live_pr_audit.md}"
REPO_SLUG="${REPO_SLUG:-godotengine/godot}"
PR_LIMIT="${PR_LIMIT:-5000}"
BOUNCE_TIMEOUT="${BOUNCE_TIMEOUT:-60}"
BODY_MAX_BYTES=4096

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m' YLW='\033[0;33m' GRN='\033[0;32m' DIM='\033[2m' NC='\033[0m'
else
    RED='' YLW='' GRN='' DIM='' NC=''
fi
info() { echo -e "${GRN}==>${NC} $*"; }
warn() { echo -e "${YLW}WARN${NC}  $*"; }
fail() { echo -e "${RED}FAIL${NC}  $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
for dep in gh jq awk; do
    command -v "$dep" >/dev/null 2>&1 || { fail "'$dep' not found in PATH — aborting."; exit 1; }
done

if [[ ! -x "$JANITOR" ]]; then
    fail "janitor binary not found at $JANITOR"
    echo "      Run: cargo build --release --bin janitor"
    exit 1
fi

if [[ ! -d "$GODOT_REPO" ]]; then
    fail "GODOT_REPO '$GODOT_REPO' does not exist."
    exit 1
fi

info "Janitor    : $JANITOR"
info "Repo (src) : $GODOT_REPO"
info "Cache      : $CACHE_FILE"
info "Progress   : $PROGRESS_FILE"
info "Report     : $REPORT_OUT"
echo ""

# ── Registry bootstrap ────────────────────────────────────────────────────────
# This must complete BEFORE the PR loop.  If symbols.rkyv is absent, bounce
# attempts an inline scan on every call — guaranteeing timeouts.
REGISTRY="$GODOT_REPO/.janitor/symbols.rkyv"

# Invalidate stale registry (> 60 min old).  A stale or partial registry can
# cause bounce to hang inside the per-PR timeout budget.
if [[ -f "$REGISTRY" ]] && find "$REGISTRY" -mmin +60 -print -quit 2>/dev/null | grep -q .; then
    warn "Registry is > 60 min old — deleting for fresh scan."
    rm -f "$REGISTRY"
fi

if [[ ! -f "$REGISTRY" ]]; then
    info "No registry found — running janitor scan (Godot: ~2–5 min)..."
    mkdir -p "$GODOT_REPO/.janitor"
    "$JANITOR" scan "$GODOT_REPO" --library
    if [[ ! -f "$REGISTRY" ]]; then
        fail "Scan finished but registry missing at $REGISTRY — aborting."
        exit 1
    fi
    info "Scan complete. Registry: $REGISTRY"
fi

# ── PR cache: one batch API call for all metadata ─────────────────────────────
mkdir -p "$(dirname "$CACHE_FILE")" "$(dirname "$PROGRESS_FILE")"

if [[ ! -f "$CACHE_FILE" ]]; then
    info "Fetching up to $PR_LIMIT open PRs from $REPO_SLUG (1 API call)..."
    gh pr list \
        --repo  "$REPO_SLUG" \
        --state open \
        --limit "$PR_LIMIT" \
        --json  number,author,body \
        > "$CACHE_FILE"
    CACHED=$(jq 'length' "$CACHE_FILE")
    info "Cached $CACHED PRs → $CACHE_FILE"
else
    CACHED=$(jq 'length' "$CACHE_FILE")
    info "Using cached PR list: $CACHED PRs  (rm $CACHE_FILE to refresh)"
fi

TOTAL=$(jq 'length' "$CACHE_FILE")
echo ""

# ── Progress: load already-processed PRs into associative array ───────────────
# ALREADY=0 initialised here so the bounce-log check below uses it without
# ever calling ${#DONE_PRS[@]} on a potentially empty array (bash set -u bug).
ALREADY=0
if [[ -f "$PROGRESS_FILE" ]]; then
    while IFS= read -r pr_num; do
        [[ -n "$pr_num" ]] && DONE_PRS["$pr_num"]=1
    done < "$PROGRESS_FILE"
    ALREADY=${#DONE_PRS[@]}
    if [[ $ALREADY -gt 0 ]]; then
        info "Resuming: $ALREADY / $TOTAL PRs already processed — skipping them."
        echo ""
    fi
fi

# Bounce log accumulates across runs when resuming.
# Start fresh only when there is no prior progress.
BOUNCE_LOG="$GODOT_REPO/.janitor/bounce_log.ndjson"
if [[ $ALREADY -eq 0 && -f "$BOUNCE_LOG" ]]; then
    warn "Fresh run — clearing stale bounce_log.ndjson"
    : > "$BOUNCE_LOG"
fi

# ── Counters ──────────────────────────────────────────────────────────────────
PROCESSED=0; SKIPPED=0; ERRORS=0
UNLINKED_COUNT=0; COMMENT_VIOLATIONS=0; HIGH_SCORE=0; HIGH_PR=0

# ── Per-PR bounce loop ────────────────────────────────────────────────────────
INDEX=0
while IFS= read -r PR; do
    NUMBER=$(echo "$PR" | jq -r '.number')
    AUTHOR=$(echo "$PR" | jq -r '.author.login // "unknown"')
    BODY=$(echo   "$PR" | jq -r '.body // ""' | head -c "$BODY_MAX_BYTES" | tr -d '\000')

    INDEX=$((INDEX + 1))

    # ── Resume: skip PRs already in progress file ──────────────────────────────
    if [[ -n "${DONE_PRS[$NUMBER]-}" ]]; then
        continue
    fi

    printf "  [%4d/%d] #%-5s %-20s  " "$INDEX" "$TOTAL" "$NUMBER" "($AUTHOR)"

    # ── Fetch PR diff via gh (same approach as ultimate_gauntlet.sh) ───────────
    PATCH_FILE=$(mktemp /tmp/crucible_XXXXXX.patch)

    if ! gh pr diff "$NUMBER" --repo "$REPO_SLUG" 2>/dev/null \
        | awk '/^diff --git/ { skip = ($3 ~ /^a\/thirdparty\// || $3 ~ /^a\/third_party\// || $3 ~ /^a\/vendor\// || $3 ~ /^a\/tests\// || $3 ~ /\.(png|jpg|jpeg|svg|gif|ico|webp|ttf|otf|woff|bin|a|so|dll|exe|zip|tar|gz|bz2)$/) } !skip { print }' \
        > "$PATCH_FILE"; then
        echo "[SKIP: diff fetch failed]"
        rm -f "$PATCH_FILE"; SKIPPED=$((SKIPPED + 1)); continue
    fi

    if [[ ! -s "$PATCH_FILE" ]]; then
        echo "[SKIP: empty / binary-only diff]"
        rm -f "$PATCH_FILE"; SKIPPED=$((SKIPPED + 1)); continue
    fi

    # ── Bounce ─────────────────────────────────────────────────────────────────
    RESULT=$(timeout "${BOUNCE_TIMEOUT}s" "$JANITOR" bounce "$GODOT_REPO" \
        --registry  "$REGISTRY"   \
        --patch     "$PATCH_FILE" \
        --pr-number "$NUMBER"     \
        --author    "$AUTHOR"     \
        --pr-body   "$BODY"       \
        --format    json          \
        2>/dev/null) && EXIT_CODE=0 || EXIT_CODE=$?

    rm -f "$PATCH_FILE"

    if [[ $EXIT_CODE -eq 124 ]]; then
        echo -e "${RED}[TIMEOUT >${BOUNCE_TIMEOUT}s]${NC}"
        SKIPPED=$((SKIPPED + 1)); continue
    elif [[ $EXIT_CODE -ne 0 ]]; then
        echo "[ERROR: bounce=$EXIT_CODE]"
        ERRORS=$((ERRORS + 1)); continue
    fi

    # ── Parse score components ─────────────────────────────────────────────────
    SCORE=$(  echo "$RESULT" | jq -r '.slop_score          // 0')
    DEAD=$(   echo "$RESULT" | jq -r '.dead_symbols_added  // 0')
    CLONES=$( echo "$RESULT" | jq -r '.logic_clones_found  // 0')
    ZOMBIES=$(echo "$RESULT" | jq -r '.zombie_symbols_added // 0')
    ANTI=$(   echo "$RESULT" | jq -r '.antipatterns_found  // 0')
    CVIOL=$(  echo "$RESULT" | jq -r '.comment_violations  // 0')
    UNLINK=$( echo "$RESULT" | jq -r '.unlinked_pr         // 0')

    # ── Compact single-line output — flags only when non-zero ─────────────────
    FLAGS=""
    [[ "$UNLINK"  == "1"     ]] && FLAGS="${FLAGS}${YLW}[NO-ISSUE]${NC} "
    [[ "$CVIOL"   -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[COMMENT×${CVIOL}]${NC} "
    [[ "$ANTI"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[ANTI×${ANTI}]${NC} "
    [[ "$DEAD"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[DEAD×${DEAD}]${NC} "
    [[ "$CLONES"  -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[CLONE×${CLONES}]${NC} "
    [[ "$ZOMBIES" -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[ZMB×${ZOMBIES}]${NC} "

    if [[ -n "$FLAGS" ]]; then
        printf "score=%-4s  %b\n" "$SCORE" "$FLAGS"
    else
        printf "score=%-4s\n" "$SCORE"
    fi

    # ── Running totals ─────────────────────────────────────────────────────────
    PROCESSED=$((PROCESSED + 1))
    [[ "$UNLINK" == "1" ]] && UNLINKED_COUNT=$((UNLINKED_COUNT + 1))
    [[ "$CVIOL" -gt 0 ]] 2>/dev/null && COMMENT_VIOLATIONS=$((COMMENT_VIOLATIONS + CVIOL))
    if [[ "$SCORE" -gt "$HIGH_SCORE" ]] 2>/dev/null; then
        HIGH_SCORE=$SCORE; HIGH_PR=$NUMBER
    fi

    # ── Mark as done — enables clean resume on Ctrl-C ─────────────────────────
    echo "$NUMBER" >> "$PROGRESS_FILE"

done < <(jq -c '.[]' "$CACHE_FILE")

# ── Crucible summary ──────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo   "  Crucible complete"
echo   "  PRs processed      : $PROCESSED"
echo   "  PRs skipped        : $SKIPPED"
echo   "  Errors             : $ERRORS"
echo   "  Unlinked PRs       : $UNLINKED_COUNT"
echo   "  Comment violations : $COMMENT_VIOLATIONS"
[[ "$HIGH_PR" -gt 0 ]] && echo "  Highest slop score : $HIGH_SCORE  (PR #$HIGH_PR)"
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo ""
echo "  To reset and re-run from scratch:"
echo "    rm $PROGRESS_FILE $CACHE_FILE"
echo ""

# ── Generate intelligence report ──────────────────────────────────────────────
info "Generating report → $REPORT_OUT"
"$JANITOR" report \
    --repo   "$GODOT_REPO" \
    --top    50            \
    --format markdown      \
    --out    "$REPORT_OUT"
info "Done. Report: $REPORT_OUT"
