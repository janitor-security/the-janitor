#!/usr/bin/env bash
# issue-token.sh — Janitor Lead Specialist Token Issuance
#
# Generates a purge token and emits a JSON Attestation Package suitable for
# delivery to a customer via email or secure channel.
#
# USAGE:
#   JANITOR_SIGNING_KEY=<64-hex-chars> ./tools/issue-token.sh [OPTIONS]
#
# OPTIONS:
#   --customer <id>   Customer identifier (email, order ID, or handle). Required.
#   --tier    <tier>  License tier (default: lead-specialist).
#   --expires <date>  Expiry annotation in ISO 8601 format (default: +1 year).
#   --key     <hex>   Override JANITOR_SIGNING_KEY env var.
#
# OUTPUT:
#   JSON Attestation Package to stdout. Redirect to a file or pipe to jq.
#
# SECURITY:
#   The signing key is consumed from the environment variable JANITOR_SIGNING_KEY.
#   Never pass the key as a positional argument or embed it in shell history.
#   The key should be stored in a secrets manager (e.g. 1Password, Vault) and
#   injected into the environment only at issuance time.
#
# EXAMPLE:
#   JANITOR_SIGNING_KEY="$(op read 'op://vault/janitor-signing-key/credential')" \
#     ./tools/issue-token.sh --customer "acme@example.com" --tier lead-specialist \
#     > attestations/acme-2026-02-19.json

set -euo pipefail

# ── Defaults ────────────────────────────────────────────────────────────────
CUSTOMER=""
TIER="lead-specialist"
EXPIRES=""
KEY_OVERRIDE=""

# ── Argument parsing ─────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --customer) CUSTOMER="$2"; shift 2 ;;
        --tier)     TIER="$2";     shift 2 ;;
        --expires)  EXPIRES="$2";  shift 2 ;;
        --key)      KEY_OVERRIDE="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Validation ───────────────────────────────────────────────────────────────
if [[ -z "$CUSTOMER" ]]; then
    echo "ERROR: --customer is required." >&2
    echo "USAGE: JANITOR_SIGNING_KEY=<hex> $0 --customer <id>" >&2
    exit 1
fi

SIGNING_KEY="${KEY_OVERRIDE:-${JANITOR_SIGNING_KEY:-}}"
if [[ -z "$SIGNING_KEY" ]]; then
    echo "ERROR: JANITOR_SIGNING_KEY environment variable is not set." >&2
    echo "       Set it or pass --key <hex>." >&2
    exit 1
fi

# ── Locate mint-token binary ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MINT_BIN="$REPO_ROOT/target/release/mint-token"

if [[ ! -x "$MINT_BIN" ]]; then
    echo "INFO: mint-token binary not found at $MINT_BIN, building..." >&2
    cargo build -p mint-token --release --quiet 2>&1 | tail -n 5 >&2
fi

if [[ ! -x "$MINT_BIN" ]]; then
    echo "ERROR: Failed to build mint-token. Run: cargo build -p mint-token --release" >&2
    exit 1
fi

# ── Mint token ───────────────────────────────────────────────────────────────
# mint-token outputs a decorated box; the token is the last non-empty line.
RAW_OUTPUT="$("$MINT_BIN" mint --key "$SIGNING_KEY" 2>&1)"
TOKEN="$(echo "$RAW_OUTPUT" | grep -v '^[╔╚║]' | grep -v '^$' | tail -n 1)"

if [[ -z "$TOKEN" ]]; then
    echo "ERROR: mint-token produced no token. Check the signing key." >&2
    exit 1
fi

# ── Timestamp & expiry ───────────────────────────────────────────────────────
ISSUED_AT="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
if [[ -z "$EXPIRES" ]]; then
    # Default: +1 year. Portable across GNU date and BSD date (macOS).
    if date -v+1y > /dev/null 2>&1; then
        # BSD date (macOS)
        EXPIRES="$(date -v+1y -u +"%Y-%m-%dT%H:%M:%SZ")"
    else
        # GNU date (Linux)
        EXPIRES="$(date -u -d "+1 year" +"%Y-%m-%dT%H:%M:%SZ")"
    fi
fi

# ── Attestation Package ──────────────────────────────────────────────────────
# Emit a JSON object suitable for storage, audit, or secure email delivery.
cat <<EOF
{
  "schema": "janitor-attestation-v1",
  "issued_at": "$ISSUED_AT",
  "expires_at": "$EXPIRES",
  "customer": "$CUSTOMER",
  "tier": "$TIER",
  "token": "$TOKEN",
  "algorithm": "Ed25519",
  "message": "JANITOR_PURGE_AUTHORIZED",
  "usage": {
    "clean": "janitor clean <path> --force-purge --token '<token>'",
    "dedup": "janitor dedup <path> --apply --force-purge --token '<token>'"
  },
  "support": "support@thejanitor.app",
  "license_url": "https://thejanitor.app/pricing"
}
EOF
