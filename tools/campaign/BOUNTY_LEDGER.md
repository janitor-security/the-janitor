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
