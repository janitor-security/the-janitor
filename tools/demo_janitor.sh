#!/usr/bin/env bash
# tools/demo_janitor.sh — Demo-mode janitor router for VHS recording.
#
# Routes 'bounce' to mock_bounce.sh for cinematic output.
# All other subcommands delegate to the real release binary.
#
# In demo.tape hidden preamble:
#   mkdir -p /tmp/_jdemo
#   ln -sf ~/dev/the-janitor/tools/demo_janitor.sh /tmp/_jdemo/janitor
#   export PATH=/tmp/_jdemo:$PATH

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REAL_BINARY="$SCRIPT_DIR/../target/release/janitor"

case "${1:-}" in
  bounce)
    exec "$SCRIPT_DIR/mock_bounce.sh" "$@"
    ;;
  *)
    exec "$REAL_BINARY" "$@"
    ;;
esac
