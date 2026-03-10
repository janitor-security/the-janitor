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
DID_CLONE=false
if [[ ! -d "$REPO_DIR" ]]; then
    step "Cloning https://github.com/${REPO_SLUG} --depth 1 → $REPO_DIR ..."
    if ! git clone --depth 1 \
            "https://github.com/${REPO_SLUG}" "$REPO_DIR" \
            --quiet 2>/dev/null; then
        fail "Clone failed for ${REPO_SLUG}. Check the slug and your network access."
    fi
    CLONE_SIZE=$(du -sh "$REPO_DIR" 2>/dev/null | cut -f1 || echo "?")
    info "Clone complete (${CLONE_SIZE} on disk)."
    DID_CLONE=true
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
# Invalidate cache if it was written by an older version that did not include
# the `state` field (schema guard — prevents all PRs defaulting to "open").
if [[ -f "$CACHE_FILE" ]]; then
    if jq -e '(length > 0) and (.[0] | has("state") | not)' "$CACHE_FILE" > /dev/null 2>&1; then
        warn "Cache schema outdated (missing 'state' field) — invalidating."
        rm -f "$CACHE_FILE"
    fi
fi

if [[ ! -f "$CACHE_FILE" ]]; then
    step "Fetching up to $PR_LIMIT PRs from $REPO_SLUG (1 API call)..."
    gh pr list \
        --repo  "$REPO_SLUG" \
        --state all \
        --limit "$PR_LIMIT" \
        --json  number,author,body,state,mergeable \
        > "$CACHE_FILE"
    CACHED=$(jq 'length' "$CACHE_FILE")
    info "Cached $CACHED PRs → $CACHE_FILE"
else
    CACHED=$(jq 'length' "$CACHE_FILE")
    info "Using cached PR list: $CACHED PRs"
    info "  Refresh cache : rm $CACHE_FILE"
fi

TOTAL=$(jq 'length' "$CACHE_FILE")
echo ""

# ── 4. Progress: load already-processed PRs ───────────────────────────────────
# Reconcile progress file against bounce_log on every resume: a prior SIGKILL
# may have written PR numbers to the progress file but lost the bounce_log
# entries (kernel page-cache not flushed).  Only PRs with a confirmed log entry
# are treated as "done" — orphaned entries are silently dropped and will be
# re-processed.
declare -A DONE_PRS
ALREADY=0
BOUNCE_LOG="$REPO_DIR/.janitor/bounce_log.ndjson"

if [[ -f "$PROGRESS_FILE" ]]; then
    if [[ -f "$BOUNCE_LOG" ]]; then
        # Build set of PR numbers that actually have a bounce_log entry.
        LOGGED_PRS=$(python3 - "$BOUNCE_LOG" <<'PYEOF'
import json, sys
logged = set()
with open(sys.argv[1]) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
            n = e.get("pr_number")
            if n is not None:
                logged.add(str(int(n)))
        except Exception:
            pass
print('\n'.join(logged))
PYEOF
)
        # Rewrite progress file keeping only confirmed entries.
        ORPHAN_COUNT=0
        CONFIRMED_LINES=()
        while IFS= read -r pr_num; do
            if [[ -z "$pr_num" ]]; then continue; fi
            if echo "$LOGGED_PRS" | grep -qxF "$pr_num"; then
                CONFIRMED_LINES+=("$pr_num")
                DONE_PRS["$pr_num"]=1
            else
                ORPHAN_COUNT=$((ORPHAN_COUNT + 1))
            fi
        done < "$PROGRESS_FILE"
        if [[ $ORPHAN_COUNT -gt 0 ]]; then
            printf '%s\n' "${CONFIRMED_LINES[@]}" > "$PROGRESS_FILE"
            python3 -c "import os; os.fdatasync(open('${PROGRESS_FILE}','ab').fileno())" \
                2>/dev/null || true
            warn "Reconciled $ORPHAN_COUNT orphaned progress entries (log-less) — will re-process."
        fi
    else
        while IFS= read -r pr_num; do
            [[ -n "$pr_num" ]] && DONE_PRS["$pr_num"]=1
        done < "$PROGRESS_FILE"
    fi
    ALREADY=${#DONE_PRS[@]}
    if [[ $ALREADY -gt 0 ]]; then
        info "Resuming: $ALREADY / $TOTAL PRs already processed — skipping them."
        info "  Reset progress: rm $PROGRESS_FILE"
        info "  Full reset    : rm $PROGRESS_FILE $CACHE_FILE"
        echo ""
    fi
fi

# Start fresh bounce log only on a clean run.
if [[ $ALREADY -eq 0 && -f "$BOUNCE_LOG" ]]; then
    warn "Fresh run — clearing stale bounce_log.ndjson"
    : > "$BOUNCE_LOG"
fi

# ── 5. Per-PR bounce loop ─────────────────────────────────────────────────────
PROCESSED=0; SKIPPED=0; ERRORS=0

INDEX=0
while IFS= read -r PR; do
    NUMBER=$(echo "$PR" | jq -r '.number')
    AUTHOR=$(echo "$PR" | jq -r '.author.login // "unknown"')
    BODY=$(echo      "$PR" | jq -r '.body // ""' | head -c "$BODY_MAX_BYTES" | tr -d '\000')
    # GitHub state values: OPEN, MERGED, CLOSED — normalise to lowercase for CLI.
    STATE=$(echo     "$PR" | jq -r '.state // "OPEN"' | tr '[:upper:]' '[:lower:]')
    MERGEABLE=$(echo "$PR" | jq -r '.mergeable // ""')

    INDEX=$((INDEX + 1))

    # Skip PRs already in progress file.
    if [[ -n "${DONE_PRS[$NUMBER]-}" ]]; then
        continue
    fi

    # Skip CONFLICTING PRs — their diffs are rebasing artifacts, not signal.
    if [[ "$MERGEABLE" == "CONFLICTING" ]]; then
        SKIPPED=$((SKIPPED + 1)); continue
    fi

    printf "  [%4d/%d] #%-5s %-20s  " "$INDEX" "$TOTAL" "$NUMBER" "($AUTHOR)"

    # Fetch PR diff via gh pr diff — no git history needed (proven approach).
    PATCH_FILE=$(mktemp /tmp/pkg_patch_XXXXXX.patch)
    BOUNCE_STDERR=$(mktemp /tmp/pkg_stderr_XXXXXX.txt)

    if ! gh pr diff "$NUMBER" --repo "$REPO_SLUG" 2>/dev/null \
        | awk '/^diff --git/ { skip = ($3 ~ /^a\/thirdparty\// || $3 ~ /^a\/third_party\// || $3 ~ /^a\/vendor\// || $3 ~ /^a\/tests\// || $3 ~ /\.(png|jpg|jpeg|svg|gif|ico|webp|ttf|otf|woff|woff2|bin|a|so|dll|exe|zip|tar|gz|bz2|xz)$/) } !skip { print }' \
        > "$PATCH_FILE"; then
        echo "[SKIP: diff fetch failed]"
        rm -f "$PATCH_FILE" "$BOUNCE_STDERR"; SKIPPED=$((SKIPPED + 1)); continue
    fi

    if [[ ! -s "$PATCH_FILE" ]]; then
        echo "[SKIP: empty / binary-only diff]"
        rm -f "$PATCH_FILE" "$BOUNCE_STDERR"; SKIPPED=$((SKIPPED + 1)); continue
    fi

    # Trace the exact command so failures are immediately diagnosable.
    set -x
    RESULT=$(timeout "${BOUNCE_TIMEOUT}s" "$JANITOR" bounce "$REPO_DIR" \
        --registry  "$REGISTRY"   \
        --patch     "$PATCH_FILE" \
        --pr-number "$NUMBER"     \
        --author    "$AUTHOR"     \
        --pr-body   "$BODY"       \
        --repo-slug "$REPO_SLUG"  \
        --pr-state  "$STATE"      \
        --format    json          \
        2>"$BOUNCE_STDERR") && EXIT_CODE=0 || EXIT_CODE=$?
    set +x

    rm -f "$PATCH_FILE"

    if [[ $EXIT_CODE -eq 124 ]]; then
        echo -e "${RED}[TIMEOUT >${BOUNCE_TIMEOUT}s]${NC}"
        rm -f "$BOUNCE_STDERR"; SKIPPED=$((SKIPPED + 1)); continue
    elif [[ $EXIT_CODE -ne 0 ]]; then
        echo -e "${RED}[ERROR: bounce exited $EXIT_CODE — ABORTING]${NC}"
        echo ""
        echo "  ── janitor stderr ──────────────────────────────"
        cat "$BOUNCE_STDERR"
        echo "  ────────────────────────────────────────────────"
        echo ""
        echo "  Last 10 lines of bounce log (if any):"
        tail -10 "$BOUNCE_LOG" 2>/dev/null || echo "  (no log yet)"
        rm -f "$BOUNCE_STDERR"
        exit 1
    fi

    rm -f "$BOUNCE_STDERR"

    SCORE=$(   echo "$RESULT" | jq -r '.slop_score           // 0')
    ANTI=$(    echo "$RESULT" | jq -r '.antipatterns_found   // 0')
    UNLINK=$(  echo "$RESULT" | jq -r '.unlinked_pr          // 0')
    ZOMBIES=$( echo "$RESULT" | jq -r '.zombie_symbols_added // 0')
    HALL=$(    echo "$RESULT" | jq -r '.hallucinated_security_fix // 0')

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
# Counts only — ROI/actionable metrics come from `janitor report` which is the
# authoritative source.  No business logic in this script.
echo ""
echo -e "${GRN}══════════════════════════════════════════════════${NC}"
echo   "  Bounce complete — $REPO_SLUG"
echo   "  PRs processed : $PROCESSED / $TOTAL"
echo   "  PRs skipped   : $SKIPPED (conflict/empty/timeout)"
echo   "  Errors        : $ERRORS"
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

# ── 8. Cleanup cloned repo ────────────────────────────────────────────────────
# If this script performed the clone, delete the working tree now that all
# output files have been written.  Pre-existing clones are left untouched.
if $DID_CLONE; then
    step "Removing cloned repo: $REPO_DIR"
    rm -rf "$REPO_DIR"
    rm -f  "$PROGRESS_FILE" "$CACHE_FILE"
    info "Cleanup complete. Output files retained at $OUTPUT_DIR"
fi
