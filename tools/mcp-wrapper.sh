#!/usr/bin/env bash
# MCP stdio bridge with automatic UDS daemon resurrection.
#
# On each invocation (Claude Code relaunches this on every session):
#   1. Check whether the janitor UDS daemon is actively listening on SOCK.
#      Uses `ss -lx` — available on all Linux hosts without extra tooling.
#   2. If dead or missing: spawn the daemon silently in the background,
#      then wait 1 s for it to bind and start accepting connections.
#   3. Bridge Claude Code's stdio to `janitor mcp` (JSON-RPC 2.0 stdio transport).
#
# Zero-Upload mandate: execution stays 100 % local. No cloud relay.

BINARY=/home/ghrammr/dev/the-janitor/target/release/janitor
SOCK=/tmp/janitor.sock

# ss -lx lists Unix-domain sockets in LISTEN state.
# grep -qF does a fixed-string match against the socket path.
if ! ss -lx 2>/dev/null | grep -qF "$SOCK"; then
    # Daemon is absent or stale — resurrect it silently.
    "$BINARY" serve --socket "$SOCK" >/dev/null 2>&1 &
    # Allow 1 s for the daemon to bind and enter the accept loop.
    sleep 1
fi

exec "$BINARY" mcp
