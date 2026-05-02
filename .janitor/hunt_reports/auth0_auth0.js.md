# Hunt Report: auth0/auth0.js

**Sprint**: Batch 94 (Ledger Reconstruction)
**Date**: 2026-05-02
**Commit depth**: --depth 1

## Findings

### 1. DOM XSS — src/web-auth/captcha.js:402
- **ID**: security:dom_xss_innerHTML
- **Severity**: Critical
- **File**: src/web-auth/captcha.js:402
- **Sink**: `element.innerHTML = options.templates.error(err)` — developer-configurable error template rendered without sanitization
- **Logged to BOUNTY_LEDGER**: Yes (Approval ~35%)

### 2. DOM XSS — src/web-auth/username-password.js:52
- **ID**: security:dom_xss_innerHTML
- **Severity**: Critical
- **File**: src/web-auth/username-password.js:52
- **Sink**: `div.innerHTML = formHtml` — server-returned HTML form rendered directly into DOM
- **Logged to BOUNTY_LEDGER**: Yes (Approval ~25%)

### 3. Unpinned Assets (example files)
- Multiple unpinned `<script src>` tags in `example/index.html`, `example/login.html`
- **Triage**: Example/demo files only, not production SDK code. Approval% < 15%. Not logged.

### 4. Missing Ownership Check — integration/selenium.js:93
- **ID**: security:missing_ownership_check
- **Severity**: KevCritical
- **File**: integration/selenium.js:93
- **Triage**: Selenium test integration file. Routes localhost:3000 path parameter. Test infrastructure only — not production code. Approval% < 10%. Not logged.
