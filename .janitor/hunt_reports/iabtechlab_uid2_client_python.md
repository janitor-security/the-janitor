# Hunt Report — IABTechLab/uid2-client-python

**Sprint**: Batch 99
**Date**: 2026-05-03
**Engagement**: trade_desk_targets
**Repo**: https://github.com/IABTechLab/uid2-client-python (--depth 1)
**Hunter**: janitor hunt /tmp/iab-uid2 --format bugcrowd

## Result: no_findings

Initial scan flagged `security:oauth_excessive_scope` in
`uid2_client/encryption.py` line 304. Review determined this is a
structural false positive: the `identity_scope=identity_scope` keyword
argument in `Params(...)` caused the `scope=` OAUTH_MARKER to fire.
`identity_scope` is the UID2 SDK's internal `IdentityScope` enum (UID2 vs
EUID) — not an OAuth authorization scope.  No OAuth authorization flow,
token exchange, or authorization server URL is present in the file.

Path guard `path.contains("encrypt")` added to `is_hunt_false_positive_path`
in `crates/forge/src/slop_hunter.rs`.  Re-run confirmed finding absent.
