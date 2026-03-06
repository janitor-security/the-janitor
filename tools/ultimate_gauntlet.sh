#!/usr/bin/env bash
# tools/ultimate_gauntlet.sh — THE ULTIMATE GAUNTLET
#
# 20-repo stress test across all supported languages. Per repo:
#   1. Clone --depth 1 to $CLONE_DIR (/tmp/gauntlet_repo)
#   2. janitor scan  — dead-symbol analysis
#   3. janitor dedup — structural clone detection
#   4. Bounce last $PR_LIMIT (100) PRs via gh pr diff (DIFF mode)
#   5. rm -rf $CLONE_DIR  — CRITICAL: SSD budget management
#   6. Append summary row + deep-dive section to $LEDGER
#
# Resource guards:
#   - RAM < 512 MB free → sleep 30 s before clone
#   - Disk < 2 GB free at /tmp → skip repo
#   - Bounce timeout: $BOUNCE_TIMEOUT per PR (default: 10 s)
#   - 1 MiB file cutoff is enforced inside janitor itself
#
# Usage:
#   ./tools/ultimate_gauntlet.sh [--resume]
#
# Environment overrides:
#   JANITOR         — path to janitor binary     (default: ./target/release/janitor)
#   CLONE_DIR       — temp clone path            (default: /tmp/gauntlet_repo)
#   PR_LIMIT        — PRs to bounce per repo     (default: 100)
#   BOUNCE_TIMEOUT  — seconds per bounce call    (default: 10)
#   LEDGER          — results markdown path      (default: docs/ultimate_gauntlet_results.md)

set -uo pipefail

# ── Repo manifest ─────────────────────────────────────────────────────────────
REPOS=(
    godotengine/godot           # C++      — game engine
    electron/electron           # C++/JS   — desktop framework
    microsoft/vscode            # TS       — editor
    DefinitelyTyped/DefinitelyTyped  # TS  — type definitions
    vercel/next.js              # JS/TS    — React framework
    ansible/ansible             # Python   — automation
    home-assistant/core         # Python   — home automation
    kubernetes/kubernetes       # Go       — container orchestration
    moby/moby                   # Go       — container engine
    rust-lang/rust              # Rust     — compiler
    tauri-apps/tauri            # Rust/JS  — desktop apps
    spring-projects/spring-boot # Java     — JVM framework
    elastic/elasticsearch       # Java     — search engine
    redis/redis                 # C        — key-value store
    NixOS/nixpkgs               # Nix      — package collection
    dotnet/aspnetcore           # C#       — web framework (C# stress test)
    apache/kafka                # Java     — distributed messaging (Java stress test)
    ohmyzsh/ohmyzsh             # Bash     — shell framework (Bash stress test)
    pytorch/pytorch             # C++/Py   — AI infrastructure (C++ stress test)
    langchain-ai/langchain      # Python   — AI framework (high-velocity)
    # ── Enterprise scale benchmarks (Go/HCL/TS/Rust grammar stress) ──────────
    hashicorp/terraform         # Go/HCL   — IaC engine (large Go + HCL corpus)
    docker/cli                  # Go       — Docker CLI (large single-language Go)
    cloudflare/workers-sdk      # TS/Rust  — Wrangler v2+ (active repo; cloudflare/wrangler is archived v1)
)

# ── Configuration ─────────────────────────────────────────────────────────────
JANITOR="${JANITOR:-$(pwd)/target/release/janitor}"
CLONE_DIR="${CLONE_DIR:-/tmp/gauntlet_repo}"
PR_LIMIT="${PR_LIMIT:-100}"
BOUNCE_TIMEOUT="${BOUNCE_TIMEOUT:-10}"
LEDGER="${LEDGER:-$(pwd)/docs/ultimate_gauntlet_results.md}"
BODY_MAX_BYTES=4096
RESUME="${1:-}"

# ── Colours ───────────────────────────────────────────────────────────────────
if [[ -t 1 ]]; then
    RED='\033[0;31m' YLW='\033[0;33m' GRN='\033[0;32m' BLU='\033[0;34m' DIM='\033[2m' NC='\033[0m'
else
    RED='' YLW='' GRN='' BLU='' DIM='' NC=''
fi
info() { echo -e "${GRN}==>${NC} $*"; }
warn() { echo -e "${YLW}WARN${NC}  $*"; }
fail() { echo -e "${RED}FAIL${NC}  $*"; }
step() { echo -e "${BLU}---${NC} $*"; }

# ── Preflight ─────────────────────────────────────────────────────────────────
for dep in gh jq awk git; do
    command -v "$dep" >/dev/null 2>&1 || { fail "'$dep' not found in PATH — aborting."; exit 1; }
done

if [[ ! -x "$JANITOR" ]]; then
    fail "janitor binary not found at $JANITOR"
    echo "      Run: cargo build --release --bin janitor"
    exit 1
fi

# GNU time for peak RSS sampling.
# Use absolute path /usr/bin/time to bypass the shell builtin.
# Preferred: -f "%M" -o FILE writes only the peak RSS in KB (a plain integer)
# to a dedicated file — simple to parse, no regex, immune to ANSI noise.
# Fallback: -v writes verbose stats to stderr (shared with janitor's progress bars);
# awk grep for "Maximum resident set size (kbytes):" with LC_ALL=C.
GNU_TIME=""
GNU_TIME_HAS_F=false
if /usr/bin/time -o /dev/null -f "%M" true >/dev/null 2>&1; then
    GNU_TIME="/usr/bin/time"
    GNU_TIME_HAS_F=true
elif /usr/bin/time -v true 2>&1 | grep -q "Maximum resident set size" 2>/dev/null; then
    GNU_TIME="/usr/bin/time"
fi

# ── Vendor / test exclusions ──────────────────────────────────────────────────
# NOTE: clap replaces default_values when any --exclude is supplied, so we must
# re-specify the built-in defaults (thirdparty/, vendor/, node_modules/, target/)
# alongside the additional gauntlet-specific patterns.
SCAN_EXCLUDES=(
    --exclude thirdparty/
    --exclude vendor/
    --exclude node_modules/
    --exclude target/
    --exclude tests
    --exclude test
    --exclude external
    --exclude docs
    --exclude doc
    --exclude demos
    --exclude demo
    --exclude benchmarks
    --exclude generated
    --exclude __pycache__
    --exclude .git
)

# ── Resource helpers ──────────────────────────────────────────────────────────
free_ram_mb()  { awk '/^MemAvailable:/ { printf "%d", $2/1024 }' /proc/meminfo 2>/dev/null || echo "9999"; }
free_disk_mb() { df /tmp --output=avail -m 2>/dev/null | tail -1 | tr -d ' ' || echo "9999"; }

# ── Resume: build set of already-completed slugs ──────────────────────────────
declare -A COMPLETED
if [[ "$RESUME" == "--resume" && -f "$LEDGER" ]]; then
    while IFS= read -r line; do
        # Match table rows: | `owner/repo` | ...
        if [[ "$line" =~ ^\|[[:space:]]*\`([^|]+)\`[[:space:]]*\| ]]; then
            COMPLETED["${BASH_REMATCH[1]}"]=1
        fi
    done < "$LEDGER"
    info "Resume mode: ${#COMPLETED[@]} repos already in ledger — will skip them."
fi

# ── Ledger initialisation ─────────────────────────────────────────────────────
mkdir -p "$(dirname "$LEDGER")"
if [[ ! -f "$LEDGER" || "$RESUME" != "--resume" ]]; then
    cat > "$LEDGER" <<'HEADER'
# Ultimate Gauntlet Results

> Generated by `tools/ultimate_gauntlet.sh`
> Engine: [The Janitor](https://thejanitor.app)

## Summary

| Repo | Duration | Peak RSS | Dead Symbols | Clone Groups | PRs Bounced | Unlinked PRs | Zombies | Antipatterns | Errors |
|------|----------|----------|-------------|--------------|-------------|--------------|---------|--------------|--------|
HEADER
    info "Ledger initialised: $LEDGER"
else
    info "Appending to existing ledger: $LEDGER"
fi

# ── Global accumulators (summed across all repos) ─────────────────────────────
GLOBAL_DEAD=0
GLOBAL_GROUPS=0
GLOBAL_PROCESSED=0
GLOBAL_TOTAL_PRS=0
GLOBAL_UNLINKED=0
GLOBAL_ZOMBIES=0
GLOBAL_ANTI=0
GLOBAL_ERRORS=0
GLOBAL_ACTIONABLE=0

# ── Main loop ─────────────────────────────────────────────────────────────────
TOTAL_REPOS=${#REPOS[@]}
REPO_IDX=0

for REPO_SLUG in "${REPOS[@]}"; do
    REPO_IDX=$((REPO_IDX + 1))
    echo ""
    echo -e "${GRN}════════════════════════════════════════════════════${NC}"
    echo -e "  [${REPO_IDX}/${TOTAL_REPOS}]  ${BLU}${REPO_SLUG}${NC}"
    echo -e "${GRN}════════════════════════════════════════════════════${NC}"

    # Resume: skip if already in ledger.
    if [[ -n "${COMPLETED[$REPO_SLUG]+_}" ]]; then
        info "Already completed — skipping."
        continue
    fi

    REPO_START=$(date +%s)
    DEAD_SYMBOLS=0
    DEDUP_GROUPS=0
    PR_PROCESSED=0
    PR_SKIPPED=0
    PR_ERRORS=0
    PR_TOTAL=0
    UNLINKED_COUNT=0
    ZOMBIE_COUNT=0
    ANTI_COUNT=0
    PEAK_RSS="N/A"
    ACTIONABLE_COUNT=0
    SCORE_BLOCKED=0  # ≥100
    SCORE_WARNED=0   # 70–99
    SCORE_MINOR=0    # 1–69
    SCORE_CLEAN=0    # 0
    # Deep-dive data (populated during scan + bounce).
    TOP_DEAD=""
    TOP_TOXIC_TEXT=""
    TOP_CLEAN_TEXT=""

    # ── Resource guards ────────────────────────────────────────────────────────
    RAM_MB=$(free_ram_mb)
    if [[ "$RAM_MB" -lt 512 ]]; then
        warn "Only ${RAM_MB} MB RAM free — sleeping 30 s for system to settle..."
        sleep 30
        RAM_MB=$(free_ram_mb)
    fi

    DISK_MB=$(free_disk_mb)
    if [[ "$DISK_MB" -lt 2048 ]]; then
        warn "Only ${DISK_MB} MB disk free at /tmp — insufficient for clone."
        printf "| \`%s\` | SKIPPED | — | — | — | — | — | — | — | disk full |\n" \
            "$REPO_SLUG" >> "$LEDGER"
        continue
    fi

    # ── 1. CLONE ──────────────────────────────────────────────────────────────
    rm -rf "$CLONE_DIR"
    step "Cloning https://github.com/${REPO_SLUG} --depth 1..."
    if ! git clone --depth 1 \
            "https://github.com/${REPO_SLUG}" "$CLONE_DIR" \
            --quiet 2>/dev/null; then
        fail "Clone failed — skipping ${REPO_SLUG}."
        printf "| \`%s\` | — | — | — | — | — | — | — | — | clone failed |\n" \
            "$REPO_SLUG" >> "$LEDGER"
        continue
    fi
    CLONE_SIZE=$(du -sh "$CLONE_DIR" 2>/dev/null | cut -f1 || echo "?")
    step "Clone complete (${CLONE_SIZE} on disk, $(($(free_disk_mb))) MB /tmp remaining)."

    # ── 2. SCAN ───────────────────────────────────────────────────────────────
    step "Running janitor scan..."
    SCAN_JSON=$(mktemp /tmp/gauntlet_scan_XXXXXX.json)
    SCAN_TIME=$(mktemp /tmp/gauntlet_time_XXXXXX.txt)

    if [[ -n "$GNU_TIME" ]]; then
        if [[ "$GNU_TIME_HAS_F" == true ]]; then
            # -f "%M" writes only the peak RSS in kilobytes to the output file.
            # Janitor's stderr (indicatif ANSI progress bars) goes to /dev/null.
            /usr/bin/time -f "%M" -o "$SCAN_TIME" "$JANITOR" scan "$CLONE_DIR" \
                "${SCAN_EXCLUDES[@]}" --library --format json \
                > "$SCAN_JSON" 2>/dev/null
            SCAN_EXIT=$?
            RSS_KB=$(tr -d '[:space:]' < "$SCAN_TIME" 2>/dev/null)
            if [[ "$RSS_KB" =~ ^[0-9]+$ ]]; then
                PEAK_RSS=$(awk "BEGIN { printf \"%.0f MB\", $RSS_KB/1024 }")
            else
                PEAK_RSS="N/A"
            fi
        else
            # Fallback: -v verbose — both janitor stderr and time stats share SCAN_TIME.
            # LC_ALL=C prevents awk choking on ANSI codes from janitor's progress bar.
            /usr/bin/time -v "$JANITOR" scan "$CLONE_DIR" \
                "${SCAN_EXCLUDES[@]}" --library --format json \
                > "$SCAN_JSON" 2>"$SCAN_TIME"
            SCAN_EXIT=$?
            PEAK_RSS=$(LC_ALL=C awk '/Maximum resident set size \(kbytes\):/ { printf "%.0f MB", $NF/1024 }' \
                "$SCAN_TIME" 2>/dev/null)
            [[ -z "$PEAK_RSS" ]] && PEAK_RSS="N/A"
        fi
    else
        "$JANITOR" scan "$CLONE_DIR" \
            "${SCAN_EXCLUDES[@]}" --library --format json \
            > "$SCAN_JSON" 2>/dev/null
        SCAN_EXIT=$?
    fi
    rm -f "$SCAN_TIME"

    if [[ $SCAN_EXIT -eq 0 ]]; then
        DEAD_SYMBOLS=$(jq '.dead_symbols | length' "$SCAN_JSON" 2>/dev/null || echo "0")
        step "Scan: ${DEAD_SYMBOLS} dead symbols."
        # Top 5 dead symbols for certainty audit — with relative file path.
        # ltrimstr strips the absolute clone-dir prefix; what remains is the
        # repo-relative path (e.g. modules/gdscript/gdscript_parser.cpp).
        TOP_DEAD=$(jq -r --arg root "$CLONE_DIR/" \
            '.dead_symbols[:5] | .[] | "  - `\(.id)` (\(.file_path | ltrimstr($root)))"' \
            "$SCAN_JSON" 2>/dev/null || echo "")
    else
        warn "Scan returned exit code ${SCAN_EXIT} — continuing."
    fi
    # SCAN_JSON intentionally kept open until after ledger write below.

    # ── 3. DEDUP ──────────────────────────────────────────────────────────────
    step "Running janitor dedup..."
    DEDUP_OUT=$("$JANITOR" dedup "$CLONE_DIR" "${SCAN_EXCLUDES[@]}" 2>/dev/null || true)
    if echo "$DEDUP_OUT" | grep -qi "no duplicate"; then
        DEDUP_GROUPS=0
    else
        DEDUP_GROUPS=$(echo "$DEDUP_OUT" | grep -c "Clone\|Duplicate\|clone\|duplicate" 2>/dev/null || echo "0")
    fi
    step "Dedup: ${DEDUP_GROUPS} clone groups."

    # ── 4. BOUNCE (last $PR_LIMIT PRs) ────────────────────────────────────────
    step "Fetching $PR_LIMIT PRs for ${REPO_SLUG}..."
    PR_CACHE=$(mktemp /tmp/gauntlet_prs_XXXXXX.json)
    # Per-PR data file: TAB-separated SCORE \t NUMBER \t AUTHOR \t ANTI_DETAIL
    # Kept in memory as a sorted temp file; cleaned up after this repo's ledger write.
    PR_DATA_FILE=$(mktemp /tmp/gauntlet_prdata_XXXXXX.tsv)

    if ! gh pr list \
            --repo  "$REPO_SLUG" \
            --state all \
            --limit "$PR_LIMIT" \
            --json  number,author,body \
            > "$PR_CACHE" 2>/dev/null; then
        warn "gh pr list failed — skipping bounce for ${REPO_SLUG}."
        PR_ERRORS=$((PR_ERRORS + 1))
    else
        PR_TOTAL=$(jq 'length' "$PR_CACHE" 2>/dev/null || echo "0")
        step "Bouncing ${PR_TOTAL} PRs (timeout=${BOUNCE_TIMEOUT}s each)..."

        PR_IDX=0
        while IFS= read -r PR; do
            PR_IDX=$((PR_IDX + 1))
            NUMBER=$(echo "$PR" | jq -r '.number')
            AUTHOR=$(echo "$PR" | jq -r '.author.login // "unknown"')
            BODY=$(echo   "$PR" | jq -r '.body // ""' \
                | head -c "$BODY_MAX_BYTES" | tr -d '\000')

            printf "    [%3d/%d] PR #%-6s %-18s  " \
                "$PR_IDX" "$PR_TOTAL" "$NUMBER" "(${AUTHOR})"

            PATCH=$(mktemp /tmp/gauntlet_patch_XXXXXX.patch)

            # Fetch patch via gh pr diff — no git history needed.
            if ! gh pr diff "$NUMBER" --repo "$REPO_SLUG" 2>/dev/null \
                | awk '/^diff --git/ { skip = ($3 ~ /^a\/thirdparty\// || $3 ~ /^a\/third_party\// || $3 ~ /^a\/vendor\// || $3 ~ /\.(png|jpg|jpeg|svg|gif|ico|webp|ttf|otf|woff|bin|a|so|dll|exe|zip|tar|gz|bz2)$/) } !skip { print }' \
                > "$PATCH"; then
                echo "[SKIP: diff fetch failed]"
                rm -f "$PATCH"
                PR_SKIPPED=$((PR_SKIPPED + 1))
                continue
            fi

            if [[ ! -s "$PATCH" ]]; then
                echo "[SKIP: empty/binary-only diff]"
                rm -f "$PATCH"
                PR_SKIPPED=$((PR_SKIPPED + 1))
                continue
            fi

            RESULT=$(timeout "${BOUNCE_TIMEOUT}s" "$JANITOR" bounce "$CLONE_DIR" \
                --patch     "$PATCH"  \
                --pr-number "$NUMBER" \
                --author    "$AUTHOR" \
                --pr-body   "$BODY"   \
                --format    json      \
                2>/dev/null) && BOUNCE_EXIT=0 || BOUNCE_EXIT=$?

            rm -f "$PATCH"

            if [[ $BOUNCE_EXIT -eq 124 ]]; then
                echo "[TIMEOUT >${BOUNCE_TIMEOUT}s]"
                PR_SKIPPED=$((PR_SKIPPED + 1))
                continue
            elif [[ $BOUNCE_EXIT -ne 0 ]]; then
                echo "[ERROR: exit=${BOUNCE_EXIT}]"
                PR_ERRORS=$((PR_ERRORS + 1))
                continue
            fi

            SCORE=$(      echo "$RESULT" | jq -r '.slop_score                // 0')
            SCORE_INT=${SCORE%.*}   # integer part for bash -ge/-gt comparisons
            ANTI=$(      echo "$RESULT" | jq -r '.antipatterns_found        // 0')
            UNLINK=$(    echo "$RESULT" | jq -r '.unlinked_pr               // 0')
            ZOMBIES=$(   echo "$RESULT" | jq -r '.zombie_symbols_added      // 0')
            DEAD_ADDED=$(echo "$RESULT" | jq -r '.dead_symbols_added        // 0')
            CLONES=$(    echo "$RESULT" | jq -r '.logic_clones_found        // 0')
            HALL=$(      echo "$RESULT" | jq -r '.hallucinated_security_fix // 0')
            # antipattern_details: array of human-readable finding descriptions.
            # Falls back to empty array on older binaries that don't emit this field.
            # Identical strings are grouped with (xN) suffix to avoid A | A | A noise.
            ANTI_DETAIL=$(echo "$RESULT" | \
                jq -r '(.antipattern_details // []) | .[]' 2>/dev/null | \
                awk '
                    { if (!seen[$0]++) order[++n]=$0; count[$0]++ }
                    END {
                        sep=""
                        for (i=1; i<=n; i++) {
                            k=order[i]
                            printf "%s", sep
                            if (count[k]>1) printf "%s (x%d)", k, count[k]
                            else printf "%s", k
                            sep=" | "
                        }
                    }
                ' 2>/dev/null || echo "")

            [[ "$UNLINK"  == "1"  ]] && UNLINKED_COUNT=$((UNLINKED_COUNT + 1))
            [[ "$ANTI"    -gt 0 ]] 2>/dev/null && ANTI_COUNT=$((ANTI_COUNT + ANTI))
            [[ "$ZOMBIES" -gt 0 ]] 2>/dev/null && ZOMBIE_COUNT=$((ZOMBIE_COUNT + ZOMBIES))

            # Score band tracking (uses SCORE_INT — bash -ge/-gt require integers).
            if [[ "$SCORE_INT" -ge 100 ]]; then
                SCORE_BLOCKED=$((SCORE_BLOCKED + 1))
            elif [[ "$SCORE_INT" -ge 70 ]]; then
                SCORE_WARNED=$((SCORE_WARNED + 1))
            elif [[ "$SCORE_INT" -gt 0 ]]; then
                SCORE_MINOR=$((SCORE_MINOR + 1))
            else
                SCORE_CLEAN=$((SCORE_CLEAN + 1))
            fi

            # Actionable intercept: blocked (≥100), zombie re-injection, or hallucination.
            if [[ "$SCORE_INT" -ge 100 ]] \
                || [[ "$ZOMBIES" -gt 0 ]] \
                || [[ "$HALL"    -gt 0 ]]; then
                ACTIONABLE_COUNT=$((ACTIONABLE_COUNT + 1))
            fi

            # Record per-PR data for deep-dive ranking (TAB-separated).
            # Columns: SCORE NUMBER AUTHOR ANTI_DETAIL ZOMBIES UNLINK DEAD_ADDED CLONES HALL
            # Use dash sentinel for empty ANTI_DETAIL: IFS=$'\t' read collapses
            # consecutive tabs (tab is whitespace in IFS), shifting later columns.
            printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
                "$SCORE" "$NUMBER" "$AUTHOR" "${ANTI_DETAIL:--}" \
                "$ZOMBIES" "$UNLINK" "$DEAD_ADDED" "$CLONES" "$HALL" \
                >> "$PR_DATA_FILE"

            FLAGS=""
            [[ "$UNLINK"     == "1" ]] && FLAGS="${FLAGS}${YLW}[NO-ISSUE]${NC} "
            [[ "$ANTI"       -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[ANTI×${ANTI}]${NC} "
            [[ "$HALL"       -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${RED}[HALL×${HALL}]${NC} "
            [[ "$ZOMBIES"    -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[ZMB×${ZOMBIES}]${NC} "
            [[ "$DEAD_ADDED" -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${BLU}[DEAD×${DEAD_ADDED}]${NC} "
            [[ "$CLONES"     -gt 0 ]] 2>/dev/null && FLAGS="${FLAGS}${DIM}[CLN×${CLONES}]${NC} "

            printf "score=%-4s  %b\n" "$SCORE" "${FLAGS:-${GRN}CLEAN${NC}}"

            PR_PROCESSED=$((PR_PROCESSED + 1))

        done < <(jq -c '.[]' "$PR_CACHE")
    fi
    rm -f "$PR_CACHE"

    # ── Compute top-3 toxic + top-3 clean from per-PR data ────────────────────
    if [[ -s "$PR_DATA_FILE" ]]; then
        # Top 3 by score (descending numeric sort on column 1).
        while IFS=$'\t' read -r TSCORE TNUMBER TAUTHOR TDETAIL TZOMBIES TUNLINK TDEAD TCLONES THALL; do
            TOP_TOXIC_TEXT+="  - **PR #${TNUMBER}** by \`${TAUTHOR}\` — score **${TSCORE}**"
            [[ "$TDETAIL"  != "-" ]] && TOP_TOXIC_TEXT+="\n    *Antipatterns: ${TDETAIL}*"
            [[ "$THALL"    -gt 0 ]] 2>/dev/null && TOP_TOXIC_TEXT+="\n    *Hallucinated security fixes: ${THALL}*"
            [[ "$TZOMBIES" -gt 0 ]] 2>/dev/null && TOP_TOXIC_TEXT+="\n    *Zombie deps: ${TZOMBIES}*"
            [[ "$TDEAD"    -gt 0 ]] 2>/dev/null && TOP_TOXIC_TEXT+="\n    *Dead symbols added: ${TDEAD}*"
            [[ "$TCLONES"  -gt 0 ]] 2>/dev/null && TOP_TOXIC_TEXT+="\n    *Logic clone groups: ${TCLONES}*"
            [[ "$TUNLINK" == "1" ]] && TOP_TOXIC_TEXT+="\n    *No linked issue*"
            TOP_TOXIC_TEXT+="\n"
        done < <(sort -t$'\t' -k1 -rn "$PR_DATA_FILE" | head -3)

        # Top 3 clean: score == 0.
        while IFS=$'\t' read -r TSCORE TNUMBER TAUTHOR REST; do
            TOP_CLEAN_TEXT+="  - PR #${TNUMBER} by \`${TAUTHOR}\`\n"
        done < <(awk -F$'\t' '$1+0 == 0' "$PR_DATA_FILE" | head -3)
    fi
    rm -f "$PR_DATA_FILE"

    # ── 5. TEARDOWN ───────────────────────────────────────────────────────────
    step "Tearing down clone..."
    rm -rf "$CLONE_DIR"
    step "/tmp freed ($(free_disk_mb) MB available)."

    # ── 6. LEDGER — summary row + deep-dive section ───────────────────────────
    REPO_END=$(date +%s)
    DURATION=$((REPO_END - REPO_START))
    if [[ $DURATION -ge 3600 ]]; then
        DURATION_FMT="$((DURATION / 3600))h$((DURATION % 3600 / 60))m"
    elif [[ $DURATION -ge 60 ]]; then
        DURATION_FMT="$((DURATION / 60))m$((DURATION % 60))s"
    else
        DURATION_FMT="${DURATION}s"
    fi

    # Summary table row.
    printf "| \`%s\` | %s | %s | %d | %d | %d/%d | %d | %d | %d | %d |\n" \
        "$REPO_SLUG"        \
        "$DURATION_FMT"     \
        "$PEAK_RSS"         \
        "$DEAD_SYMBOLS"     \
        "$DEDUP_GROUPS"     \
        "$PR_PROCESSED"     \
        "$PR_TOTAL"         \
        "$UNLINKED_COUNT"   \
        "$ZOMBIE_COUNT"     \
        "$ANTI_COUNT"       \
        "$PR_ERRORS"        \
        >> "$LEDGER"

    # Deep-dive section — appended after the summary table.
    {
        printf "\n### %s\n\n" "$REPO_SLUG"
        printf "**Duration**: %s | **Peak RSS**: %s | **PRs Bounced**: %d/%d | **Dead Symbols**: %d | **Clone Groups**: %d\n\n" \
            "$DURATION_FMT" "$PEAK_RSS" "$PR_PROCESSED" "$PR_TOTAL" "$DEAD_SYMBOLS" "$DEDUP_GROUPS"

        HOURS_SAVED=$(awk "BEGIN { printf \"%.1f\", $ACTIONABLE_COUNT * 12 / 60 }")
        MONEY_SAVED=$(awk "BEGIN { printf \"%.0f\", $ACTIONABLE_COUNT * 12 / 60 * 100 }")
        printf "**Workslop Impact**: %d actionable intercepts | **%s hrs reclaimed** | **\$%s saved**\n\n" \
            "$ACTIONABLE_COUNT" "$HOURS_SAVED" "$MONEY_SAVED"

        printf "**Score Distribution**: %d blocked (≥100) | %d warned (70–99) | %d minor (1–69) | %d clean (0)\n\n" \
            "$SCORE_BLOCKED" "$SCORE_WARNED" "$SCORE_MINOR" "$SCORE_CLEAN"

        printf "#### Top 3 Toxic PRs\n\n"
        if [[ -n "$TOP_TOXIC_TEXT" ]]; then
            printf "%b" "$TOP_TOXIC_TEXT"
        else
            printf "_No PRs with slop score > 0 in sample._\n"
        fi

        printf "\n#### Top 3 Clean PRs\n\n"
        if [[ -n "$TOP_CLEAN_TEXT" ]]; then
            printf "%b" "$TOP_CLEAN_TEXT"
        else
            printf "_No zero-score PRs in sample._\n"
        fi

        printf "\n#### Dead Symbol Certainty Audit (Top 5)\n\n"
        if [[ -n "$TOP_DEAD" ]]; then
            printf "%s\n" "$TOP_DEAD"
            if [[ "$DEAD_SYMBOLS" -gt 5 ]] 2>/dev/null; then
                printf "  _(…and %d more — verify with \`janitor scan %s --library\`)_\n" \
                    "$((DEAD_SYMBOLS - 5))" "$REPO_SLUG"
            fi
        else
            printf "_No dead symbols found._\n"
        fi

        printf "\n---\n"
    } >> "$LEDGER"

    rm -f "$SCAN_JSON"

    # Accumulate global totals.
    GLOBAL_DEAD=$((GLOBAL_DEAD + DEAD_SYMBOLS))
    GLOBAL_GROUPS=$((GLOBAL_GROUPS + DEDUP_GROUPS))
    GLOBAL_PROCESSED=$((GLOBAL_PROCESSED + PR_PROCESSED))
    GLOBAL_TOTAL_PRS=$((GLOBAL_TOTAL_PRS + PR_TOTAL))
    GLOBAL_UNLINKED=$((GLOBAL_UNLINKED + UNLINKED_COUNT))
    GLOBAL_ZOMBIES=$((GLOBAL_ZOMBIES + ZOMBIE_COUNT))
    GLOBAL_ANTI=$((GLOBAL_ANTI + ANTI_COUNT))
    GLOBAL_ERRORS=$((GLOBAL_ERRORS + PR_ERRORS))
    GLOBAL_ACTIONABLE=$((GLOBAL_ACTIONABLE + ACTIONABLE_COUNT))

    echo ""
    info "${REPO_SLUG} → ${DURATION_FMT} | rss=${PEAK_RSS} | dead=${DEAD_SYMBOLS} | prs=${PR_PROCESSED}/${PR_TOTAL} | unlinked=${UNLINKED_COUNT} | zombies=${ZOMBIE_COUNT} | anti=${ANTI_COUNT} | actionable=${ACTIONABLE_COUNT}"

done

# ── Final summary: TOTAL row + Global Workslop section ────────────────────────
TOTAL_HOURS=$(awk "BEGIN { printf \"%.1f\", $GLOBAL_ACTIONABLE * 12 / 60 }")
TOTAL_SAVINGS=$(awk "BEGIN { printf \"%.0f\", $GLOBAL_ACTIONABLE * 12 / 60 * 100 }")

{
    printf "| **TOTAL** | — | — | **%d** | **%d** | **%d/%d** | **%d** | **%d** | **%d** | **%d** |\n" \
        "$GLOBAL_DEAD" "$GLOBAL_GROUPS" \
        "$GLOBAL_PROCESSED" "$GLOBAL_TOTAL_PRS" \
        "$GLOBAL_UNLINKED" "$GLOBAL_ZOMBIES" "$GLOBAL_ANTI" "$GLOBAL_ERRORS"

    printf "\n---\n\n"
    printf "## Global Workslop Impact\n\n"
    printf "| Metric | Value |\n"
    printf "|:-------|------:|\n"
    printf "| Actionable intercepts (Blocked ≥ 100 / Zombie / Hallucination) | **%d** |\n" "$GLOBAL_ACTIONABLE"
    printf "| **Total engineering time reclaimed** | **%s hours** |\n" "$TOTAL_HOURS"
    printf "| **Estimated operational savings** | **\$%s** |\n" "$TOTAL_SAVINGS"
    printf "\n"
    printf "> Methodology: 12 min/triage × \$100/hr loaded engineering cost.\n"
    printf "> Actionable = PRs scoring ≥ 100 (gate blocked) or confirmed adversarial signal (Zombie re-injection / Hallucinated Security Fix).\n"
} >> "$LEDGER"

echo ""
echo -e "${GRN}════════════════════════════════════════════════════${NC}"
echo   "  ULTIMATE GAUNTLET COMPLETE"
echo   "  Repos: ${TOTAL_REPOS} | PRs: ${GLOBAL_PROCESSED}/${GLOBAL_TOTAL_PRS} | Dead: ${GLOBAL_DEAD}"
echo   "  Actionable: ${GLOBAL_ACTIONABLE} | Saved: ${TOTAL_HOURS}h / \$${TOTAL_SAVINGS}"
echo   "  Full results: $LEDGER"
echo -e "${GRN}════════════════════════════════════════════════════${NC}"
echo ""
echo "  To resume a partial run:  ./tools/ultimate_gauntlet.sh --resume"
echo "  To reset and re-run:      rm $LEDGER && ./tools/ultimate_gauntlet.sh"
