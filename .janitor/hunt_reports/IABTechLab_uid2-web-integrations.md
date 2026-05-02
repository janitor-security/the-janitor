# Hunt Report: IABTechLab/uid2-web-integrations

**Sprint**: Batch 95
**Date**: 2026-05-02
**Commit depth**: --depth 1

## Result: no_findings

UID2 Web Integrations SDK (@uid2/uid2-sdk v4.0.95) — advertiser-side browser
identity integration.  No DOM manipulation sinks receiving attacker-controlled
data, no raw account-merge sinks, no secret-handling code outside SDK-delegated
identity token flows.  All token operations use the Trade Desk UID2 API under
HTTPS with standard CORS constraints.
