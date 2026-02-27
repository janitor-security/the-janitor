#!/usr/bin/env bash
# tools/mock_bond.sh — Theatrical Ed25519 attestation display for VHS demo.
#
# Simulates the visual output of:
#   janitor clean ~/dev/gauntlet/godot --force-purge --token $JANITOR_TOKEN
#
# Running `janitor clean` against a 16K-symbol live repo is not demo-safe.
# This script produces identical terminal output using real ANSI codes and
# a /dev/urandom-derived signature so every recording is unique.

set -euo pipefail

DIM=$'\033[2m'
GRN=$'\033[32m'
YLW=$'\033[33m'
BLD=$'\033[1m'
NC=$'\033[0m'

echo ""
echo "  janitor clean ~/dev/gauntlet/godot --force-purge --token \$JANITOR_TOKEN"
echo ""
sleep 0.5

printf '%s[shadow tree]%s  Symlinking 7,812 dead-symbol files into .janitor/shadow_src/\n' "$DIM" "$NC"
sleep 0.7

printf '%s[shadow tree]%s  Running test suite in isolation...\n' "$DIM" "$NC"
sleep 1.8

printf '%s[PASS          ]%s  Shadow test suite clean. Proceeding to physical excision.\n' "$GRN" "$NC"
sleep 0.6

printf '%s[reaper        ]%s  Excising 7,812 symbols -- bottom-to-top byte-splice\n' "$YLW" "$NC"
sleep 2.2

printf '%s[INTEGRITY BOND]%s  Ed25519 audit log sealed\n' "$GRN" "$NC"
sleep 0.4

printf '%s[INTEGRITY BOND]%s  .janitor/audit_log.json -- 7812 entries, SHA-256 chained\n' "$GRN" "$NC"
sleep 0.4

SIG=$(head -c 48 /dev/urandom | base64 | tr -d '\n=' | cut -c1-88)
printf '%s[INTEGRITY BOND]%s  Signature: %s%s%s\n' "$GRN" "$NC" "$BLD" "$SIG" "$NC"
sleep 0.3

echo ""
printf '%s%s RECLAMATION COMPLETE.%s  7,812 dead symbols excised.\n' "$BLD" "$GRN" "$NC"
printf '                         Bond: .janitor/audit_log.json\n'
echo ""
