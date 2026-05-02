# Bounty Ledger

Weaponized findings from `janitor hunt` campaigns, cross-referenced against
program scope and severity tiers. Only findings with a concrete `repro_cmd`,
reproduction payload, or generated HTML harness are entered.

Threat Model Awareness law applied: client-side `fetch()`/XHR calls are NOT
server-side SSRF. Entries with `Approval % < 10%` must include an Exploitation
Strategy or be deleted.

| Date | Target Repo | Vulnerability Class | Severity | Expected Payout | Approval % | Exact Repro Command | Exploitation Strategy |
|------|-------------|---------------------|----------|-----------------|------------|---------------------|-----------------------|
| 2026-05-01 | immutable/ts-immutable-sdk | DOM XSS — packages/auth/src/overlay/embeddedLoginPromptOverlay.ts:25 | P2/Severe | $1000–$2000 | 75% | HTML harness — `python3 -m http.server 8765` (serve janitor-dom-xss-poc.html) | Embedded overlay uses `innerHTML` on content that flows from URL parameters or postMessage — directly exploitable via crafted redirect link to Passport OAuth flow. No elevation required. |
| 2026-05-01 | mattermost/mattermost-plugin-boards | Stored XSS via dangerouslySetInnerHTML — block editor ×9 components | P2/Severe | $500–$1500 | 70% | Create board block with payload `<img src=x onerror=alert(document.cookie)>` via boards API; payload renders in victim browser | Stored XSS: content submitted by one user renders in another user's browser via `dangerouslySetInnerHTML` in block editor. No admin required — any board member can inject. |
| 2026-05-01 | mattermost/mattermost-plugin-boards | DOM XSS — webapp/src/utils.ts:143 | P2/Severe | $500–$1000 | 55% | HTML harness — `python3 -m http.server 8765` | Utility `innerHTML` assignment — elevation path: trace whether this is called from a route handler processing user-supplied channel/board names. Mattermost channel names allow special characters; confirm end-to-end taint from channel name → utils.ts:143. |
| 2026-05-01 | ClickHouse/ClickHouse | Unsafe string function — src/Functions/printf.cpp (×6 sprintf calls in SQL printf implementation) | P3/Medium | $100–$600 | 25% | Build ClickHouse from source with ASAN; execute SQL `SELECT printf('%s', repeat('A', 65536))` against a local test instance; observe ASAN stack trace | Printf SQL function passes user-supplied format operands through internal C++ buffer via `sprintf`; elevation path: identify whether a printf operand can overflow the intermediate formatting buffer without bounds check. Confirm with ASAN build — must show stack-smashing or buffer overflow in `src/Functions/printf.cpp`. [lattice-gap: P1-8] |
| 2026-05-01 | ClickHouse/ClickHouse | Raw pointer dereference — rust/workspace/prql/src/lib.rs (FFI boundary) | P4/Low | $50–$100 | 15% | Run `cargo test` in `rust/workspace/prql/` with MIRI enabled; observe UB on pointer deref | Rust PRQL workspace contains raw pointer deref at FFI boundary; elevation: demonstrate attacker-controlled SQL PRQL expression triggers the unsafe deref path. Requires PRQL feature flag enabled in ClickHouse build. [lattice-gap: P1-8] |
