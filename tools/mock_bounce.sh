#!/usr/bin/env bash
# tools/mock_bounce.sh — Cinematic PR bounce gate display for VHS demo.
#
# Based on real Crucible data: PR #116833 by TitanNano, godotengine/godot
# Actual bounce results: slop_score=70, antipatterns_found=1, unlinked_pr=1
#
# The raw janitor bounce JSON is accurate but visually inert for a demo.
# This script renders the same data with ANSI formatting and pacing.

set -euo pipefail

RED=$'\033[0;31m'
YLW=$'\033[0;33m'
GRN=$'\033[0;32m'
DIM=$'\033[2m'
BLD=$'\033[1m'
NC=$'\033[0m'

echo ""
printf "  %srepository%s  godotengine/godot\n"             "$DIM" "$NC"
printf "  %spr        %s  #116833  ·  TitanNano\n"         "$DIM" "$NC"
printf "  %sdiff      %s  19,499 bytes  ·  7 files changed\n" "$DIM" "$NC"
echo ""
sleep 0.4

printf "  Dissecting diff  ·  running Social Forensics...\n"
sleep 0.9
echo ""

printf "  %s[WARN ]%s  Social Forensics   PR body carries no Closes/Fixes #N link\n" \
  "$YLW" "$NC"
printf "         %sSlopScore +20%s\n" "$DIM" "$NC"
sleep 0.6

printf "  %s[BLOCK]%s  Language Antipattern × 1 detected\n" "$RED" "$NC"
printf "         %s→ Structural construct violation in added source lines%s\n" \
  "$DIM" "$NC"
printf "         %sSlopScore +50%s\n" "$DIM" "$NC"
sleep 0.7

echo ""
echo "  ─────────────────────────────────────────────────────────────────────"
printf "  SlopScore  %s%s70%s\n"                  "$BLD" "$RED" "$NC"
printf "  Verdict    %s%sBLOCKED%s"               "$BLD" "$RED" "$NC"
printf "  —  score exceeds gate threshold (20)\n"
echo "  ─────────────────────────────────────────────────────────────────────"
echo ""
sleep 0.3
printf "  %sHint: add 'Closes #NNNN' to PR body to clear the link check (-20)%s\n" \
  "$DIM" "$NC"
echo ""
