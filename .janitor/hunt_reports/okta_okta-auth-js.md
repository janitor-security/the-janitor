# Hunt Report: okta/okta-auth-js

**Date**: 2026-05-02
**Sprint**: Batch 97
**Target**: https://github.com/okta/okta-auth-js
**Language Profile**: TypeScript, JavaScript
**Engine Version**: v10.2.0-beta.5

## Result: no_findings

`janitor hunt /tmp/okta-auth-js --format bugcrowd` returned `no_findings`.

The okta-auth-js SDK is a browser/Node.js OAuth 2.0 / OIDC client library. No
weaponized findings emitted:

- TypeScript `innerHTML` candidates are suppressed by the existing
  `rhs_is_static_i18n_template` guard — all DOM write sites use static strings
  or template literals composed exclusively of constant values.
- `fetch()` / `XMLHttpRequest` sink candidates are client-side HTTP calls to
  Okta's authorization server; blocked by SOP/CORS and therefore NOT SSRF
  (Threat Model Awareness Law: client-side HTTP ≠ server-side SSRF).
- No credential material committed to repository.
- No OpenAPI or GraphQL schema files present in repository (Schema Taint
  Verification Law: no schema → `schema_taint:unresolved`, approval ceiling
  remains <40%, no escalation path for hypothetical innerHTML sinks).

## Ledger: no billable findings
