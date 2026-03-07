#!/usr/bin/env bash
# tools/generate_client_package.sh — UNIVERSAL CLIENT PACKAGE GENERATOR
#
# Generates a professional "Sales Package" (CSV + PDF) for any GitHub repository:
#   1. Auto-detect local clone; shallow-clone if absent.
#   2. Build symbol registry via `janitor scan` (cached until stale).
#   3. Fetch PR metadata via `gh pr list` (single API call, cached).
#   4. Bounce each PR via `gh pr diff` + `janitor bounce` (resumable).
#   5. Export CSV:  <REPO_NAME>_full_audit.csv
#   6. Export PDF:  <REPO_NAME>_intelligence_report.pdf
#
# Resource guards (from ultimate_gauntlet.sh):
#   - Bounce timeout: $BOUNCE_TIMEOUT per PR (default: 30 s)
#   - Vendor/binary diff lines stripped by awk before bounce
#   - Registry invalidated after $REGISTRY_TTL_MIN minutes (default: 120)
#
# Usage:
#   ./tools/generate_client_package.sh <owner/repo>
#   ./tools/generate_client_package.sh godotengine/godot
#   ./tools/generate_client_package.sh kubernetes/kubernetes
#
# Environment overrides:
#   JANITOR          — janitor binary          (default: ./target/release/janitor)
#   GAUNTLET_DIR     — clone parent directory  (default: ~/dev/gauntlet)
#   PR_LIMIT         — max PRs to bounce       (default: 5000)
#   BOUNCE_TIMEOUT   — seconds per bounce      (default: 30)
#   REGISTRY_TTL_MIN — registry max age (min)  (default: 120)
#   OUTPUT_DIR       — where to write CSV+PDF  (default: current directory)

set -uo pipefail

# ── Argument validation ────────────────────────────────────────────────────────
if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <owner/repo>"
    echo "Example: $0 godotengine/godot"
    exit 1
fi

REPO_SLUG="$1"

# Derive REPO_NAME from slug (last component after '/').
REPO_NAME="${REPO_SLUG##*/}"

if [[ -z "$REPO_NAME" ]]; then
    echo "ERROR: Cannot derive repo name from '${REPO_SLUG}'. Expected format: owner/repo"
    exit 1
fi

# ── Configuration ─────────────────────────────────────────────────────────────
JANITOR="${JANITOR:-$(pwd)/target/release/janitor}"
GAUNTLET_DIR="${GAUNTLET_DIR:-$HOME/dev/gauntlet}"
PR_LIMIT="${PR_LIMIT:-5000}"
BOUNCE_TIMEOUT="${BOUNCE_TIMEOUT:-30}"
REGISTRY_TTL_MIN="${REGISTRY_TTL_MIN:-120}"
OUTPUT_DIR="${OUTPUT_DIR:-$(pwd)}"
BODY_MAX_BYTES=4096

REPO_DIR="$GAUNTLET_DIR/$REPO_NAME"
CACHE_FILE="$HOME/.janitor/pkg_cache_${REPO_NAME}.json"
PROGRESS_FILE="$HOME/.janitor/pkg_progress_${REPO_NAME}.txt"
REGISTRY="$REPO_DIR/.janitor/symbols.rkyv"

CSV_OUT="$OUTPUT_DIR/${REPO_NAME}_full_audit.csv"
PDF_OUT="$OUTPUT_DIR/${REPO_NAME}_intelligence_report.pdf"

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m' YLW='\033[0;33m' GRN='\033[0;32m' BLU='\033[0;34m' DIM='\033[2m' NC='\033[0m'
else
    RED='' YLW='' GRN='' BLU='' DIM='' NC=''
fi
info() { echo -e "${GRN}==>${NC} $*"; }
warn() { echo -e "${YLW}WARN${NC}  $*"; }
fail() { echo -e "${RED}FAIL${NC}  $*"; exit 1; }
step() { echo -e "${BLU}---${NC} $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
for dep in gh jq awk; do
    command -v "$dep" >/dev/null 2>&1 || fail "'$dep' not found in PATH — aborting."
done

if [[ ! -x "$JANITOR" ]]; then
    fail "janitor binary not found at $JANITOR\n      Run: cargo build --release --bin janitor"
fi

mkdir -p "$GAUNTLET_DIR" "$HOME/.janitor" "$OUTPUT_DIR"

info "Client Package Generator"
info "Repo slug  : $REPO_SLUG"
info "Repo dir   : $REPO_DIR"
info "PR limit   : $PR_LIMIT"
info "CSV output : $CSV_OUT"
info "PDF output : $PDF_OUT"
echo ""

# ── 1. Clone if absent ────────────────────────────────────────────────────────
if [[ ! -d "$REPO_DIR" ]]; then
    step "Cloning https://github.com/${REPO_SLUG} --depth 1 → $REPO_DIR ..."
    if ! git clone --depth 1 \
            "https://github.com/${REPO_SLUG}" "$REPO_DIR" \
            --quiet 2>/dev/null; then
        fail "Clone failed for ${REPO_SLUG}. Check the slug and your network access."
    fi
    CLONE_SIZE=$(du -sh "$REPO_DIR" 2>/dev/null | cut -f1 || echo "?")
    info "Clone complete (${CLONE_SIZE} on disk)."
else
    info "Local clone found: $REPO_DIR (skipping clone)"
fi

# ── 2. Symbol registry ────────────────────────────────────────────────────────
# Invalidate stale registry.
if [[ -f "$REGISTRY" ]] && find "$REGISTRY" -mmin +"$REGISTRY_TTL_MIN" -print -quit 2>/dev/null | grep -q .; then
    warn "Registry is > ${REGISTRY_TTL_MIN} min old — deleting for fresh scan."
    rm -f "$REGISTRY"
fi

if [[ ! -f "$REGISTRY" ]]; then
    step "Building symbol registry for $REPO_SLUG (~2–5 min)..."
    mkdir -p "$REPO_DIR/.janitor"
    "$JANITOR" scan "$REPO_DIR" --library \
        --exclude thirdparty/ \
        --exclude vendor/ \
        --exclude node_modules/ \
        --exclude target/ \
        --exclude tests \
        --exclude test \
        --exclude external \
        --exclude docs \
        --exclude doc \
        2>/dev/null || true

    if [[ ! -f "$REGISTRY" ]]; then
        fail "Scan completed but registry missing at $REGISTRY — aborting."
    fi
    info "Registry built: $REGISTRY"
else
    info "Using cached registry: $REGISTRY"
fi

# ── 3. PR metadata cache (one API call) ───────────────────────────────────────
if [[ ! -f "$CACHE_FILE" ]]; then
    step "Fetching up to $PR_LIMIT PRs from $REPO_SLUG (1 API call)..."
    gh pr list \
        --repo  "$REPO_SLUG" \
        --state all \
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

# ── 4. Progress: load already-processed PRs ───────────────────────────────────
declare -A DONE_PRS
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

# Start fresh bounce log only on a clean run.
BOUNCE_LOG="$REPO_DIR/.janitor/bounce_log.ndjson"
if [[ $ALREADY -eq 0 && -f "$BOUNCE_LOG" ]]; then
    warn "Fresh run — clearing stale bounce_log.ndjson"
    : > "$BOUNCE_LOG"
fi

# ── 5. Per-PR bounce loop ─────────────────────────────────────────────────────
PROCESSED=0; SKIPPED=0; ERRORS=0
UNLINKED_COUNT=0; ANTI_COUNT=0; ZOMBIE_COUNT=0; ACTIONABLE_COUNT=0
HIGH_SCORE=0; HIGH_PR=0

INDEX=0
while IFS= read -r PR; do
    NUMBER=$(echo "$PR" | jq -r '.number')
    AUTHOR=$(echo "$PR" | jq -r '.author.login // "unknown"')
    BODY=$(echo   "$PR" | jq -r '.body // ""' | head -c "$BODY_MAX_BYTES" | tr -d '\000')

    INDEX=$((INDEX + 1))

    # Skip PRs already in progress file.
    if [[ -n "${DONE_PRS[$NUMBER]-}" ]]; then
        continue
    fi

    printf "  [%4d/%d] #%-5s %-20s  " "$INDEX" "$TOTAL" "$NUMBER" "($AUTHOR)"

    # Fetch PR diff via gh pr diff — no git history needed (proven approach).
    PATCH_FILE=$(mktemp /tmp/pkg_patch_XXXXXX.patch)

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

    RESULT=$(timeout "${BOUNCE_TIMEOUT}s" "$JANITOR" bounce "$REPO_DIR" \
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

    SCORE=$(   echo "$RESULT" | jq -r '.slop_score           // 0')
    SCORE_INT=${SCORE%.*}
    ANTI=$(    echo "$RESULT" | jq -r '.antipatterns_found   // 0')
    UNLINK=$(  echo "$RESULT" | jq -r '.unlinked_pr          // 0')
    ZOMBIES=$( echo "$RESULT" | jq -r '.zombie_symbols_added // 0')
    HALL=$(    echo "$RESULT" | jq -r '.hallucinated_security_fix // 0')

    [[ "$UNLINK"  == "1" ]] && UNLINKED_COUNT=$((UNLINKED_COUNT + 1))
    [[ "$ANTI"    -gt 0 ]] 2>/dev/null && ANTI_COUNT=$((ANTI_COUNT + ANTI))
    [[ "$ZOMBIES" -gt 0 ]] 2>/dev/null && ZOMBIE_COUNT=$((ZOMBIE_COUNT + ZOMBIES))

    if [[ "$SCORE_INT" -ge 100 ]] || [[ "$ZOMBIES" -gt 0 ]] || [[ "$HALL" -gt 0 ]]; then
        ACTIONABLE_COUNT=$((ACTIONABLE_COUNT + 1))
    fi

    if [[ "$SCORE_INT" -gt "$HIGH_SCORE" ]] 2>/dev/null; then
        HIGH_SCORE=$SCORE_INT; HIGH_PR=$NUMBER
    fi

    # Compact output — flags only when non-zero.
    FLAGS=""
    [[ "$UNLINK"  == "1"  ]] && FLAGS="${FLAGS}${YLW}[NO-ISSUE]${NC} "
    [[ "$ANTI"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[ANTI×${ANTI}]${NC} "
    [[ "$HALL"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[HALL×${HALL}]${NC} "
    [[ "$ZOMBIES" -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[ZMB×${ZOMBIES}]${NC} "

    if [[ -n "$FLAGS" ]]; then
        printf "score=%-4s  %b\n" "$SCORE" "$FLAGS"
    else
        printf "score=%-4s\n" "$SCORE"
    fi

    PROCESSED=$((PROCESSED + 1))
    echo "$NUMBER" >> "$PROGRESS_FILE"

done < <(jq -c '.[]' "$CACHE_FILE")

# ── Summary ───────────────────────────────────────────────────────────────────
HOURS_SAVED=$(awk "BEGIN { printf \"%.1f\", $ACTIONABLE_COUNT * 12 / 60 }")
MONEY_SAVED=$(awk "BEGIN { printf \"%.0f\", $ACTIONABLE_COUNT * 12 / 60 * 100 }")

echo ""
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo   "  Bounce complete — $REPO_SLUG"
echo   "  PRs processed      : $PROCESSED / $TOTAL"
echo   "  PRs skipped        : $SKIPPED"
echo   "  Errors             : $ERRORS"
echo   "  Actionable         : $ACTIONABLE_COUNT"
echo   "  Unlinked PRs       : $UNLINKED_COUNT"
echo   "  Antipatterns       : $ANTI_COUNT"
echo   "  Zombie symbols     : $ZOMBIE_COUNT"
[[ "$HIGH_PR" -gt 0 ]] && echo "  Highest slop score : $HIGH_SCORE  (PR #$HIGH_PR)"
echo   "  Hours reclaimed    : ${HOURS_SAVED}h  (\$${MONEY_SAVED})"
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo ""

# ── Helper: human-readable file size ──────────────────────────────────────────
file_size_human() {
    local file="$1"
    local bytes
    bytes=$(stat --format="%s" "$file" 2>/dev/null || stat -f "%z" "$file" 2>/dev/null || echo "0")
    if [[ "$bytes" -ge 1048576 ]]; then
        awk "BEGIN { printf \"%.1f MB\", $bytes/1048576 }"
    elif [[ "$bytes" -ge 1024 ]]; then
        awk "BEGIN { printf \"%.1f KB\", $bytes/1024 }"
    else
        echo "${bytes} B"
    fi
}

# ── 6. Export CSV ─────────────────────────────────────────────────────────────
step "Exporting CSV → $CSV_OUT"
CSV_OK=false
if "$JANITOR" export \
    --repo "$REPO_DIR" \
    --out  "$CSV_OUT"; then
    CSV_SIZE=$(file_size_human "$CSV_OUT")
    info "CSV written: $CSV_OUT  (${CSV_SIZE})"
    CSV_OK=true
else
    warn "CSV export failed — check bounce log at $REPO_DIR/.janitor/bounce_log.ndjson"
fi

echo ""

# ── 7. Export PDF intelligence report ─────────────────────────────────────────
step "Generating PDF intelligence report → $PDF_OUT"
PDF_OK=false
if "$JANITOR" report \
    --repo   "$REPO_DIR" \
    --top    50          \
    --format pdf         \
    --out    "$PDF_OUT" 2>&1; then
    PDF_SIZE=$(file_size_human "$PDF_OUT")
    info "PDF written: $PDF_OUT  (${PDF_SIZE})"
    PDF_OK=true
else
    warn "PDF generation failed."
    warn "Requirements: pandoc + texlive-latex-extra + texlive-fonts-recommended"
    warn "Install: sudo apt-get install pandoc texlive-latex-extra texlive-fonts-recommended"
    warn "macOS:   brew install pandoc basictex && sudo tlmgr install titlesec tocloft xfp newunicodechar framed"
fi

echo ""
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo   "  CLIENT PACKAGE COMPLETE — $REPO_SLUG"
if $CSV_OK; then
    CSV_SIZE=$(file_size_human "$CSV_OUT")
    echo   "  CSV  : $CSV_OUT  (${CSV_SIZE})"
else
    echo -e "  CSV  : ${RED}FAILED${NC}"
fi
if $PDF_OK; then
    PDF_SIZE=$(file_size_human "$PDF_OUT")
    echo   "  PDF  : $PDF_OUT  (${PDF_SIZE})"
else
    echo -e "  PDF  : ${RED}FAILED — run with pandoc+texlive installed${NC}"
fi
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo ""
echo "  To reset and re-run from scratch:"
echo "    rm $PROGRESS_FILE $CACHE_FILE"
echo ""
