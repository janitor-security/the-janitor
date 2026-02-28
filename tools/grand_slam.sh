#!/usr/bin/env bash
# tools/grand_slam.sh — THE GRAND SLAM
#
# Full-corpus PR audit. One batch API call caches ALL open PRs to
# ~/.janitor/pr_cache.json. Survives 4,600+ PR corpora without burning
# the GitHub 5,000 req/hr rate limit.
#
# Two modes — auto-detected:
#   GIT MODE  (LOCAL_REPO has .git): git cat-file -t checks OID presence;
#              only fetches refs/pull/<N>/head when the commit is missing.
#              Uses janitor bounce --repo --base --head (no API call per PR).
#   DIFF MODE (LOCAL_REPO is a source snapshot): gh pr diff <N> per PR.
#              Uses janitor bounce --patch. Same as the Crucible but with
#              metadata (author, body) pulled from the cached batch list.
#
# Usage:
#   ./tools/grand_slam.sh [local_repo_path [report_output.md]]
#
# Environment overrides:
#   JANITOR     — path to janitor binary        (default: ./target/release/janitor)
#   LOCAL_REPO  — repo path (git clone or src)  (default: ~/dev/gauntlet/godot)
#   REPO_SLUG   — GitHub "owner/repo" slug      (default: godotengine/godot)
#   CACHE_FILE  — PR list JSON cache            (default: ~/.janitor/pr_cache.json)
#   PR_LIMIT    — max PRs to fetch into cache   (default: 5000)
#   START_AT    — resume from this PR index (0-based, default: 0)

set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
JANITOR="${JANITOR:-$(pwd)/target/release/janitor}"
LOCAL_REPO="${1:-${LOCAL_REPO:-$HOME/dev/gauntlet/godot}}"
REPO_SLUG="${REPO_SLUG:-godotengine/godot}"
CACHE_FILE="${CACHE_FILE:-$HOME/.janitor/pr_cache.json}"
PR_LIMIT="${PR_LIMIT:-5000}"
START_AT="${START_AT:-0}"
BODY_MAX_BYTES=4096

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
    command -v "$dep" >/dev/null 2>&1 || { fail "'$dep' not found in PATH — aborting."; exit 1; }
done

if [[ ! -x "$JANITOR" ]]; then
    fail "janitor binary not found at $JANITOR"
    echo "      Run: cargo build --release --bin janitor"
    exit 1
fi

if [[ ! -d "$LOCAL_REPO" ]]; then
    fail "LOCAL_REPO '$LOCAL_REPO' does not exist."
    exit 1
fi

# ── Mode detection ────────────────────────────────────────────────────────────
if [[ -d "$LOCAL_REPO/.git" ]]; then
    GIT_MODE=true
    info "Mode       : GIT (smart OID fetch)"
else
    GIT_MODE=false
    info "Mode       : DIFF (gh pr diff per PR)"
fi
info "Janitor    : $JANITOR"
info "Local repo : $LOCAL_REPO"
info "Slug       : $REPO_SLUG"
info "Cache      : $CACHE_FILE"
echo ""

# ── Registry bootstrap ────────────────────────────────────────────────────────
REGISTRY="$LOCAL_REPO/.janitor/symbols.rkyv"
if [[ ! -f "$REGISTRY" ]]; then
    info "No registry found — running janitor scan (~30-60 s)..."
    "$JANITOR" scan "$LOCAL_REPO" --format json >/dev/null 2>&1
    info "Scan complete. Registry written to $REGISTRY"
fi

# ── PR cache: fetch ALL open PRs in one API call ──────────────────────────────
if [[ ! -f "$CACHE_FILE" ]]; then
    mkdir -p "$(dirname "$CACHE_FILE")"
    info "Fetching up to $PR_LIMIT open PRs from $REPO_SLUG (one API call)..."
    gh pr list \
        --repo   "$REPO_SLUG" \
        --state  open \
        --limit  "$PR_LIMIT" \
        --json   number,headRefOid,baseRefOid,author,body \
        > "$CACHE_FILE"
    CACHED=$(jq 'length' "$CACHE_FILE")
    info "Cached $CACHED PRs → $CACHE_FILE"
else
    CACHED=$(jq 'length' "$CACHE_FILE")
    info "Using cached PR list: $CACHED PRs → $CACHE_FILE"
    info "  (delete to refresh: rm $CACHE_FILE)"
fi
echo ""

TOTAL=$(jq 'length' "$CACHE_FILE")

# ── Counters ──────────────────────────────────────────────────────────────────
PROCESSED=0; SKIPPED=0; ERRORS=0; GIT_FETCHES=0
UNLINKED_COUNT=0; COMMENT_VIOLATIONS=0; HIGH_SCORE=0; HIGH_PR=0

# ── Per-PR bounce loop ────────────────────────────────────────────────────────
INDEX=0
while IFS= read -r PR; do
    # Resume support: skip PRs before START_AT.
    if [[ $INDEX -lt $START_AT ]]; then
        INDEX=$((INDEX + 1))
        continue
    fi

    NUMBER=$(echo   "$PR" | jq -r '.number')
    AUTHOR=$(echo   "$PR" | jq -r '.author.login // "unknown"')
    HEAD_OID=$(echo "$PR" | jq -r '.headRefOid')
    BASE_OID=$(echo "$PR" | jq -r '.baseRefOid')
    BODY=$(echo     "$PR" | jq -r '.body // ""' | head -c "$BODY_MAX_BYTES" | tr -d '\000')

    DISPLAY_IDX=$((INDEX + 1))
    printf "  [%4d/%d] PR #%-5s %-20s  " "$DISPLAY_IDX" "$TOTAL" "$NUMBER" "($AUTHOR)"

    # ── Per-mode bounce dispatch ───────────────────────────────────────────────
    if [[ "$GIT_MODE" == true ]]; then
        # Smart fetch: check if headRefOid is already in the local clone.
        OBJ_TYPE=$(git -C "$LOCAL_REPO" cat-file -t "$HEAD_OID" 2>/dev/null || true)
        if [[ "$OBJ_TYPE" != "commit" ]]; then
            if ! git -C "$LOCAL_REPO" fetch origin "refs/pull/${NUMBER}/head" --quiet 2>/dev/null; then
                echo "[SKIP: git fetch refs/pull/${NUMBER}/head failed]"
                SKIPPED=$((SKIPPED + 1)); INDEX=$((INDEX + 1)); continue
            fi
            GIT_FETCHES=$((GIT_FETCHES + 1))
            OBJ_TYPE=$(git -C "$LOCAL_REPO" cat-file -t "$HEAD_OID" 2>/dev/null || true)
            if [[ "$OBJ_TYPE" != "commit" ]]; then
                echo "[SKIP: OID $HEAD_OID missing after fetch]"
                SKIPPED=$((SKIPPED + 1)); INDEX=$((INDEX + 1)); continue
            fi
        fi

        RESULT=$(timeout 30s "$JANITOR" bounce "$LOCAL_REPO" \
            --repo      "$LOCAL_REPO" \
            --base      "$BASE_OID"   \
            --head      "$HEAD_OID"   \
            --pr-number "$NUMBER"     \
            --author    "$AUTHOR"     \
            --pr-body   "$BODY"       \
            --format    json          \
            2>/dev/null) && EXIT_CODE=0 || EXIT_CODE=$?

    else
        # Diff mode: fetch patch via gh pr diff (one API call per PR).
        PATCH_FILE=$(mktemp /tmp/grand_slam_XXXXXX.patch)
        trap 'rm -f "$PATCH_FILE"' EXIT

        if ! gh pr diff "$NUMBER" --repo "$REPO_SLUG" 2>/dev/null \
            | awk '
                /^diff --git/ {
                    skip = ($3 ~ /^a\/thirdparty\// ||
                            $3 ~ /\.(png|jpg|jpeg|svg|gif|ico|webp|ttf|otf|woff)$/)
                }
                !skip { print }
            ' > "$PATCH_FILE"; then
            echo "[SKIP: gh pr diff failed]"
            rm -f "$PATCH_FILE"; trap - EXIT
            SKIPPED=$((SKIPPED + 1)); INDEX=$((INDEX + 1)); continue
        fi

        if [[ ! -s "$PATCH_FILE" ]]; then
            echo "[SKIP: empty diff — thirdparty/binary only]"
            rm -f "$PATCH_FILE"; trap - EXIT
            SKIPPED=$((SKIPPED + 1)); INDEX=$((INDEX + 1)); continue
        fi

        RESULT=$(timeout 30s "$JANITOR" bounce "$LOCAL_REPO" \
            --patch     "$PATCH_FILE" \
            --pr-number "$NUMBER"     \
            --author    "$AUTHOR"     \
            --pr-body   "$BODY"       \
            --format    json          \
            2>/dev/null) && EXIT_CODE=0 || EXIT_CODE=$?

        rm -f "$PATCH_FILE"; trap - EXIT
    fi

    if [[ $EXIT_CODE -eq 124 ]]; then
        echo -e "${RED}[TIMEOUT — SKIPPED]${NC}  PR #$NUMBER took >30 s — likely oversized diff"
        SKIPPED=$((SKIPPED + 1)); INDEX=$((INDEX + 1)); continue
    elif [[ $EXIT_CODE -ne 0 ]]; then
        echo "[ERROR: bounce returned $EXIT_CODE]"
        ERRORS=$((ERRORS + 1)); INDEX=$((INDEX + 1)); continue
    fi

    # ── Parse score components ─────────────────────────────────────────────────
    SCORE=$(  echo "$RESULT" | jq -r '.slop_score          // 0')
    DEAD=$(   echo "$RESULT" | jq -r '.dead_symbols_added  // 0')
    CLONES=$( echo "$RESULT" | jq -r '.logic_clones_found  // 0')
    ZOMBIES=$(echo "$RESULT" | jq -r '.zombie_symbols_added // 0')
    ANTI=$(   echo "$RESULT" | jq -r '.antipatterns_found  // 0')
    CVIOL=$(  echo "$RESULT" | jq -r '.comment_violations  // 0')
    UNLINK=$( echo "$RESULT" | jq -r '.unlinked_pr         // 0')

    FLAGS=""
    [[ "$UNLINK"  == "1"  ]] && FLAGS="${FLAGS}${YLW}[NO-ISSUE]${NC} "
    [[ "$CVIOL"   -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[COMMENT×${CVIOL}]${NC} "
    [[ "$ANTI"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[ANTI×${ANTI}]${NC} "
    [[ "$DEAD"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[DEAD×${DEAD}]${NC} "
    [[ "$CLONES"  -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[CLONE×${CLONES}]${NC} "
    [[ "$ZOMBIES" -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[ZMB×${ZOMBIES}]${NC} "

    printf "score=%-4s  %b\n" "$SCORE" "${FLAGS:-${GRN}CLEAN${NC}}"

    # ── Running totals ─────────────────────────────────────────────────────────
    PROCESSED=$((PROCESSED + 1))
    [[ "$UNLINK" == "1" ]] && UNLINKED_COUNT=$((UNLINKED_COUNT + 1))
    [[ "$CVIOL" -gt 0 ]] 2>/dev/null && COMMENT_VIOLATIONS=$((COMMENT_VIOLATIONS + CVIOL))
    if [[ "$SCORE" -gt "$HIGH_SCORE" ]] 2>/dev/null; then
        HIGH_SCORE=$SCORE; HIGH_PR=$NUMBER
    fi

    INDEX=$((INDEX + 1))
done < <(jq -c '.[]' "$CACHE_FILE")

# ── Grand Slam summary ────────────────────────────────────────────────────────
echo ""
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo   "  Grand Slam complete"
echo   "  Mode               : $([ "$GIT_MODE" = true ] && echo 'GIT' || echo 'DIFF')"
echo   "  PRs processed      : $PROCESSED"
echo   "  PRs skipped        : $SKIPPED"
echo   "  Errors             : $ERRORS"
if [[ "$GIT_MODE" == true ]]; then
    echo "  OIDs freshly fetched: $GIT_FETCHES  (rest already local)"
fi
echo   "  Unlinked PRs       : $UNLINKED_COUNT"
echo   "  Comment violations : $COMMENT_VIOLATIONS"
[[ "$HIGH_PR" -gt 0 ]] && echo "  Highest slop score : $HIGH_SCORE  (PR #$HIGH_PR)"
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo ""

# ── Generate intelligence report ──────────────────────────────────────────────
REPORT_OUT="${2:-grand_slam_report.md}"
info "Generating report → $REPORT_OUT"
"$JANITOR" report \
    --repo   "$LOCAL_REPO" \
    --top    50            \
    --format markdown      \
    --out    "$REPORT_OUT"
info "Done. Report: $REPORT_OUT"
info "Hint: janitor report --global --gauntlet ~/dev/gauntlet/ for cross-repo aggregation."
