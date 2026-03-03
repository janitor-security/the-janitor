#!/usr/bin/env bash
# tools/audit_real_prs.sh — THE CRUCIBLE v2 (Git-Protocol Edition)
#
# Full-corpus PR audit for godotengine/godot.  Designed to handle 4,600+ PRs
# without touching the GitHub REST API rate limit (5,000 req/hr).
#
# Diff strategy: git plumbing only.
#   1. One `gh pr list --limit 5000` batch call → ~/.janitor/pr_cache_full.json
#      (API cost: 1 request.  Cached until you delete it.)
#   2. Per-PR: `git fetch origin refs/pull/<N>/head --depth=1` — git protocol,
#      no API token consumed.  If headRefOid is already in the local pack,
#      the fetch is skipped entirely.
#   3. `git diff <baseRefOid> <headRefOid>` — pure local object store.
#
# Progress tracking: ~/.janitor/crucible_progress.txt (one PR number per line).
# The script skips already-processed PRs on restart — safe to Ctrl-C and resume.
#
# Usage:
#   ./tools/audit_real_prs.sh [report_output.md]
#
# Environment overrides:
#   JANITOR        — janitor binary         (default: ./target/release/janitor)
#   GODOT_REPO     — project root (registry + bounce path)
#                    (default: ~/dev/gauntlet/godot   — snapshot or clone)
#   GODOT_GIT      — git clone root (fetch + diff)
#                    (default: ~/dev/gauntlet/godot-git)
#   CACHE_FILE     — PR list JSON cache     (default: ~/.janitor/pr_cache_full.json)
#   PROGRESS_FILE  — resumable progress log (default: ~/.janitor/crucible_progress.txt)
#   PR_LIMIT       — max PRs to cache       (default: 5000)
#   REPO_SLUG      — GitHub owner/repo      (default: godotengine/godot)

set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
JANITOR="${JANITOR:-$(pwd)/target/release/janitor}"
GODOT_REPO="${GODOT_REPO:-$HOME/dev/gauntlet/godot}"
GODOT_GIT="${GODOT_GIT:-$HOME/dev/gauntlet/godot-git}"
CACHE_FILE="${CACHE_FILE:-$HOME/.janitor/pr_cache_full.json}"
PROGRESS_FILE="${PROGRESS_FILE:-$HOME/.janitor/crucible_progress.txt}"
REPORT_OUT="${1:-godot_live_pr_audit.md}"
REPO_SLUG="${REPO_SLUG:-godotengine/godot}"
PR_LIMIT="${PR_LIMIT:-5000}"
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
for dep in git gh jq awk; do
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

if [[ ! -d "$GODOT_GIT/.git" ]]; then
    fail "GODOT_GIT '$GODOT_GIT' is not a git repository."
    echo ""
    echo "  Clone Godot once with:"
    echo "    git clone https://github.com/godotengine/godot.git $GODOT_GIT"
    echo ""
    echo "  Then re-run this script.  Subsequent PR fetches use git protocol"
    echo "  (bandwidth only, no API tokens consumed)."
    exit 1
fi

info "Janitor    : $JANITOR"
info "Repo (src) : $GODOT_REPO"
info "Repo (git) : $GODOT_GIT"
info "Cache      : $CACHE_FILE"
info "Progress   : $PROGRESS_FILE"
info "Report     : $REPORT_OUT"
echo ""

# ── Registry bootstrap ────────────────────────────────────────────────────────
REGISTRY="$GODOT_REPO/.janitor/symbols.rkyv"
if [[ ! -f "$REGISTRY" ]]; then
    info "No registry found — running janitor scan (~30–60 s)..."
    "$JANITOR" scan "$GODOT_REPO" --library --format json >/dev/null 2>&1
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
        --json  number,headRefOid,baseRefOid,author,body \
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
declare -A DONE_PRS
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
if [[ ${#DONE_PRS[@]} -eq 0 && -f "$BOUNCE_LOG" ]]; then
    warn "Fresh run — clearing stale bounce_log.ndjson"
    : > "$BOUNCE_LOG"
fi

# ── Counters ──────────────────────────────────────────────────────────────────
PROCESSED=0; SKIPPED=0; ERRORS=0; FETCHES=0
UNLINKED_COUNT=0; COMMENT_VIOLATIONS=0; HIGH_SCORE=0; HIGH_PR=0

# ── Per-PR bounce loop ────────────────────────────────────────────────────────
INDEX=0
while IFS= read -r PR; do
    NUMBER=$(echo   "$PR" | jq -r '.number')
    AUTHOR=$(echo   "$PR" | jq -r '.author.login // "unknown"')
    HEAD_OID=$(echo "$PR" | jq -r '.headRefOid')
    BASE_OID=$(echo "$PR" | jq -r '.baseRefOid')
    BODY=$(echo     "$PR" | jq -r '.body // ""' | head -c "$BODY_MAX_BYTES" | tr -d '\000')

    INDEX=$((INDEX + 1))

    # ── Resume: skip PRs already in progress file ──────────────────────────────
    if [[ -n "${DONE_PRS[$NUMBER]+_}" ]]; then
        continue
    fi

    printf "  [%4d/%d] #%-5s %-20s  " "$INDEX" "$TOTAL" "$NUMBER" "($AUTHOR)"

    # ── Smart OID fetch: git protocol, no API tokens ───────────────────────────
    OBJ_TYPE=$(git -C "$GODOT_GIT" cat-file -t "$HEAD_OID" 2>/dev/null || true)
    if [[ "$OBJ_TYPE" != "commit" ]]; then
        if ! git -C "$GODOT_GIT" fetch origin \
                "refs/pull/${NUMBER}/head" \
                --depth=1 --quiet 2>/dev/null; then
            echo "[SKIP: git fetch failed]"
            SKIPPED=$((SKIPPED + 1)); continue
        fi
        FETCHES=$((FETCHES + 1))
        OBJ_TYPE=$(git -C "$GODOT_GIT" cat-file -t "$HEAD_OID" 2>/dev/null || true)
        if [[ "$OBJ_TYPE" != "commit" ]]; then
            echo "[SKIP: OID $HEAD_OID missing after fetch]"
            SKIPPED=$((SKIPPED + 1)); continue
        fi
    fi

    # ── Generate diff via git object store (no API call) ──────────────────────
    PATCH_FILE=$(mktemp /tmp/crucible_XXXXXX.patch)
    AWK_FILTER='/^diff --git/ { skip = ($3 ~ /^a\/thirdparty\// || $3 ~ /^a\/vendor\// || $3 ~ /^a\/tests\// || $3 ~ /\.(png|jpg|jpeg|svg|gif|ico|webp|ttf|otf|woff)$/) } !skip { print }'

    # BASE_OID is often absent from the shallow pack — allow git diff to fail
    # silently so the git-show fallback below can recover.
    git -C "$GODOT_GIT" diff "$BASE_OID" "$HEAD_OID" 2>/dev/null \
        | awk "$AWK_FILTER" > "$PATCH_FILE" || true

    # If BASE_OID isn't in the local pack (shallow clone edge case), fall back
    # to showing only the PR head commit's own diff.
    if [[ ! -s "$PATCH_FILE" ]]; then
        git -C "$GODOT_GIT" show "$HEAD_OID" --format="" --patch 2>/dev/null \
            | awk "$AWK_FILTER" > "$PATCH_FILE" || true
    fi

    if [[ ! -s "$PATCH_FILE" ]]; then
        echo "[SKIP: empty diff — thirdparty / binary only]"
        rm -f "$PATCH_FILE"; SKIPPED=$((SKIPPED + 1)); continue
    fi

    # ── Bounce ─────────────────────────────────────────────────────────────────
    RESULT=$(timeout 10s "$JANITOR" bounce "$GODOT_REPO" \
        --patch     "$PATCH_FILE" \
        --pr-number "$NUMBER"     \
        --author    "$AUTHOR"     \
        --pr-body   "$BODY"       \
        --format    json          \
        2>/dev/null) && EXIT_CODE=0 || EXIT_CODE=$?

    rm -f "$PATCH_FILE"

    if [[ $EXIT_CODE -eq 124 ]]; then
        echo -e "${RED}[TIMEOUT — SKIPPED]${NC}"
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
echo   "  Crucible complete (git-protocol edition)"
echo   "  PRs processed      : $PROCESSED"
echo   "  PRs skipped        : $SKIPPED"
echo   "  Errors             : $ERRORS"
echo   "  Git fetches issued : $FETCHES  (rest were already local)"
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
