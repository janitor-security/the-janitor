#!/usr/bin/env bash
# run_gauntlet.sh — The Janitor Omni-Gauntlet Benchmark
#
# Iterates every directory under GAUNTLET_DIR, runs `janitor scan` under
# /usr/bin/time -v, and captures:
#   - Total symbol count
#   - Dead symbol count (and percentage)
#   - Peak RSS (kbytes)
#   - Wall-clock elapsed time
#
# Outputs a Markdown table to stdout and a TSV file to GAUNTLET_DIR/../gauntlet_results.tsv
#
# Usage:
#   ./tools/run_gauntlet.sh
#   GAUNTLET_DIR=~/dev/gauntlet ./tools/run_gauntlet.sh
#   JANITOR=./target/release/janitor ./tools/run_gauntlet.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"

JANITOR="${JANITOR:-$REPO_ROOT/target/release/janitor}"
GAUNTLET_DIR="${GAUNTLET_DIR:-$HOME/dev/gauntlet}"
TSV_OUT="${TSV_OUT:-$REPO_ROOT/gauntlet_results.tsv}"

# ---------------------------------------------------------------------------
# Validate environment
# ---------------------------------------------------------------------------

if [[ ! -x "$JANITOR" ]]; then
  echo "ERROR: janitor binary not found at $JANITOR" >&2
  echo "       Run 'cargo build --release' first." >&2
  exit 1
fi

if [[ ! -d "$GAUNTLET_DIR" ]]; then
  echo "ERROR: gauntlet directory not found: $GAUNTLET_DIR" >&2
  exit 1
fi

if ! command -v /usr/bin/time &>/dev/null; then
  echo "ERROR: /usr/bin/time not found (GNU time required for -v flag)" >&2
  exit 1
fi

# ---------------------------------------------------------------------------
# Benchmark loop
# ---------------------------------------------------------------------------

printf '%-14s\t%-8s\t%-6s\t%-8s\t%-12s\t%-10s\n' \
  "repo" "total" "dead" "dead_pct" "peak_rss_kb" "elapsed_s" \
  > "$TSV_OUT"

declare -a REPOS TOTALS DEADS PCTS RSSS ELAPSEDS

i=0
for REPO_PATH in "$GAUNTLET_DIR"/*/; do
  [[ -d "$REPO_PATH" ]] || continue
  NAME=$(basename "$REPO_PATH")
  TMPOUT=$(mktemp)
  TMPERR=$(mktemp)

  echo -n "  Scanning $NAME ... " >&2

  # Run janitor scan; capture both stdout and stderr (time goes to stderr).
  # Exit code may be non-zero for repos with no supported files — tolerate it.
  /usr/bin/time -v "$JANITOR" scan "$REPO_PATH" \
    > "$TMPOUT" 2> "$TMPERR" || true

  # Extract from janitor text output.
  TOTAL=$(grep -oP 'Total entities\s*:\s*\K\d+' "$TMPOUT" || echo "0")
  DEAD=$(grep -oP 'Dead\s*:\s*\K\d+' "$TMPOUT" || echo "0")
  TOTAL=${TOTAL:-0}
  DEAD=${DEAD:-0}

  PCT=$(awk "BEGIN {
    if ($TOTAL > 0) printf \"%.1f%%\", $DEAD * 100 / $TOTAL
    else print \"0.0%\"
  }")

  # Extract from GNU time -v stderr.
  RSS=$(grep -oP 'Maximum resident set size \(kbytes\):\s*\K\d+' "$TMPERR" || echo "0")
  RSS=${RSS:-0}

  # Elapsed time — format is either m:ss.cs or h:mm:ss
  ELAPSED_RAW=$(grep -oP 'Elapsed \(wall clock\) time.*?:\s*\K[\d:.]+' "$TMPERR" || echo "?")

  rm -f "$TMPOUT" "$TMPERR"

  echo "done (total=$TOTAL dead=$DEAD rss=${RSS}kb elapsed=$ELAPSED_RAW)" >&2

  REPOS+=("$NAME")
  TOTALS+=("$TOTAL")
  DEADS+=("$DEAD")
  PCTS+=("$PCT")
  RSSS+=("$RSS")
  ELAPSEDS+=("$ELAPSED_RAW")

  printf '%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$NAME" "$TOTAL" "$DEAD" "$PCT" "$RSS" "$ELAPSED_RAW" \
    >> "$TSV_OUT"

  (( i++ )) || true
done

# ---------------------------------------------------------------------------
# Markdown table output
# ---------------------------------------------------------------------------

echo ""
echo "| Repo | Language | Total Symbols | Dead | Dead% | Peak RAM | Scan Time |"
echo "|:-----|:---------|:-------------|:-----|:------|:---------|:----------|"

# Language hints (extend as needed).
declare -A LANG
LANG=(
  [godot]="C++"
  [doom]="C"
  [veloren]="Rust"
  [hugo]="Go"
  [flask]="Python"
  [fastapi]="Python"
  [requests]="Python"
  [scrapy]="Python"
  [black]="Python"
  [rich]="Python"
  [starlette]="Python"
  [axios]="JS/TS"
  [lodash]="JS"
  [Mindustry]="Java"
  [FreeCol]="Java"
)

for j in "${!REPOS[@]}"; do
  NAME="${REPOS[$j]}"
  LANG_STR="${LANG[$NAME]:-Unknown}"
  TOTAL="${TOTALS[$j]}"
  DEAD="${DEADS[$j]}"
  PCT="${PCTS[$j]}"
  RSS="${RSSS[$j]}"
  RSS_MB=$(awk "BEGIN { printf \"%.0f MB\", $RSS / 1024 }")
  ELAPSED="${ELAPSEDS[$j]}"

  # Highlight godot as the anchor data point.
  if [[ "$NAME" == "godot" ]]; then
    echo "| **$NAME** | **$LANG_STR** | **$TOTAL** | **$DEAD** | **$PCT** | **$RSS_MB** | **$ELAPSED** |"
  else
    echo "| $NAME | $LANG_STR | $TOTAL | $DEAD | $PCT | $RSS_MB | $ELAPSED |"
  fi
done

echo ""
echo "TSV results written to: $TSV_OUT"
