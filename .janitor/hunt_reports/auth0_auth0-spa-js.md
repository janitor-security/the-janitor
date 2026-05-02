# Hunt Report: auth0/auth0-spa-js

**Sprint**: Batch 94 (Ledger Reconstruction)
**Date**: 2026-05-02
**Commit depth**: --depth 1

## Findings

### 1. Prototype Pollution — static/auth0-spa-js.development_old.js
- **ID**: security:prototype_pollution
- **File**: static/auth0-spa-js.development_old.js (lines 19, 2018)
- **Triage**: File is `*_old.js` — archived/deprecated artifact in static/. Not active SDK code. Approval% < 10%. Not logged.

### 2. Unpinned Assets (static demo files)
- Multiple unpinned `<script src>` tags across static/*.html demo files
- **Triage**: Demo/example files only. Not production SDK code. Approval% < 15%. Not logged.

### 3. Non-Constant-Time Comparison — src/Auth0Client.ts
- **ID**: security:non_constant_time_comparison
- **Severity**: Critical
- **File**: src/Auth0Client.ts (lines 637, 913, 920, 925, 931)
- **Triage**: Root cause was `window.location.assign(` matching the bare `sign(` taint source pattern. FP eradicated by removing bare `sign(` from `secret_source_ac` in `sidechannel.rs`. No genuine secret-producing call is present — `getTokenSilently` comparisons are on public identity fields (audience, scope, clientId), not secret material. Not logged.

## Structural Guard Applied
- `crates/forge/src/sidechannel.rs`: removed `b"sign("` pattern (matches `assign(`); replaced with `b"crypto.sign("`, `b"Ed25519.sign("`, `b"ed25519.sign("`. Removed `b"getToken"` and `b"generateToken"` (too broad — match public-token-retrieval methods, not secret producers).
