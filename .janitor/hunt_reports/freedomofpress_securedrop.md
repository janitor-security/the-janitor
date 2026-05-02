# Hunt Report: freedomofpress/securedrop

**Sprint**: Batch 95
**Date**: 2026-05-02
**Commit depth**: --depth 1

## Structural Guard Applied

`security:dom_xss_innerHTML` fired at `securedrop/static/js/journalist.js` lines
41, 62, and 227.  Root cause: `innerHTML` assignments built from `get_string()`
i18n helper calls and `.length` numeric expressions — no attacker-controlled data.

**Fix (Structural Eradication Law)**: Added `rhs_is_static_i18n_template()` guard
to `crates/forge/src/slop_hunter.rs::find_inner_html_assignments`.  Guard suppresses
`dom_xss_innerHTML` when the entire RHS is composed of string literals, known i18n
helper calls (`get_string`, `_`, `gettext`, `ngettext`, `i18n`), `.length`
expressions, and `+` concatenations thereof.  Re-run: findings absent from output.

## Findings

### 1. subprocess_shell_injection — devops/scripts/verify-mo.py:112
- **Severity**: Informational
- **Triage**: `verify-mo.py` is a CI devops script, not the web application.  The
  `shell=True` carries an explicit `# nosemgrep` + `# noqa: S602` annotation with
  developer comment explaining the intentional rationale (inherit Python venv).
  Not remotely exploitable.
- **Approval %**: <10% — devops-only, intentional, requires local CI access.
- **Logged to BOUNTY_LEDGER**: No.

### 2. missing_ownership_check — admin.py lines 357, 416, 450
- **Severity**: Informational
- **Triage**: All three routes carry `@admin_required` decorator.  Admin users have
  intentional full access to the journalist roster — querying any `user_id` is
  correct design for administrative management.  No IDOR.
- **Approval %**: <10% — admin-required endpoints, intended access model.
- **Logged to BOUNTY_LEDGER**: No.

### 3. missing_ownership_check — col.py:150, main.py:232
- **Severity**: Informational
- **Triage**: SecureDrop's access model is shared-queue — all journalists have
  equal read access to all sources.  `filesystem_id` is not a journalist-scoped
  resource.  `mark_seen()` uses the authenticated journalist session identity.
  IDOR does not apply to a shared-queue design.
- **Approval %**: <15% — by-design access model.
- **Logged to BOUNTY_LEDGER**: No.
