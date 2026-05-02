# Hunt Report: openai/codex

**Sprint**: Batch 94
**Date**: 2026-05-02
**Commit depth**: --depth 1

## Findings

### 1. Intent Divergence — codex-rs/model-provider/src/auth.rs:58
- **ID**: security:intent_divergence
- **Severity**: Critical
- **Finding**: `UnauthenticatedAuthProvider` sends NO Authorization headers. Intentional design for local OSS providers with `requires_openai_auth = false`.
- **Logged to BOUNTY_LEDGER**: Yes (Approval ~40%). Elevation path: confirm whether user-configured provider with `requires_openai_auth = false` can route codebase content to attacker-controlled endpoint.

### 2. Intent Divergence — codex-rs/responses-api-proxy/src/read_api_key.rs:204
- **Triage**: Near `mlock()` call securing API key in memory — security-enhancing code, not a vulnerability. Not logged.

### 3. Raw Pointer Dereference (×22 findings)
- **Files**: linux-sandbox, shell-escalation, PTY utilities, Windows sandbox
- **Triage**: All in intentional `unsafe {}` blocks in system-level sandbox/PTY/socket implementation code. Required for seccomp, ptrace, and platform IPC. No evidence of attacker-controllable inputs reaching these dereferences through the external interface. Approval% < 20%. Not logged.
