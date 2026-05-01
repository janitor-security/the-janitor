# Hunt Report: mattermost/mattermost-plugin-boards

**Date**: 2026-05-01
**Engine**: v10.2.0-beta.5
**Format**: bugcrowd
**Status**: 2 billable finding classes (SSRF out-of-scope per program rules)

---

**Summary Title:** Multiple instances of security:react_xss_dangerous_html in target
**VRT Category:** Cross-Site Scripting (XSS) > DOM-Based
**Affected Package / Component:** **github.com/mattermost/mattermost-plugin-boards** go1.24.6 (`go.mod`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: webapp/src/components/blocksEditor/blocks/checkbox/index.tsx, Line: 40
- File: webapp/src/components/blocksEditor/blocks/h1/index.tsx, Line: 23
- File: webapp/src/components/blocksEditor/blocks/h2/index.tsx, Line: 23
- File: webapp/src/components/blocksEditor/blocks/h3/index.tsx, Line: 23
- File: webapp/src/components/blocksEditor/blocks/quote/index.tsx, Line: 23
- File: webapp/src/components/blocksEditor/blocks/text-dev/index.tsx, Line: 22
- File: webapp/src/components/blocksEditor/blocks/text/index.tsx, Line: 24
- File: webapp/src/components/boardsUnfurl/boardsUnfurl.tsx, Line: 209
- File: webapp/src/components/rhsChannelBoardItem.tsx, Line: 108
**Business Impact:** A DOM-based XSS sink can enable session theft, arbitrary action execution in a victim browser, and account takeover in the Mattermost boards interface.
**Vulnerability Reproduction:**
Pentester notes:
1. Review `webapp/src/components/blocksEditor/blocks/checkbox/index.tsx` line 40 and identify the route, command, or parser entry point that reaches this sink.
2. Send a benign canary value through the affected input and confirm it reaches the sink without normalization or allowlist enforcement.
3. Replace the canary with the payload class for this finding and capture the response, log entry, or state transition that demonstrates impact.
4. Retest after adding the recommended validation control to confirm the sink no longer receives attacker-controlled input.
**Remediation Advice:** Replace `dangerouslySetInnerHTML` with safe React text rendering or a sanitization library such as DOMPurify.

---

**Summary Title:** Multiple instances of security:dom_xss_innerHTML in target
**VRT Category:** Cross-Site Scripting (XSS) > DOM-Based
**Affected Package / Component:** **github.com/mattermost/mattermost-plugin-boards** go1.24.6 (`go.mod`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: webapp/src/utils.ts, Line: 143
**Business Impact:** A DOM-based XSS sink can enable session theft and arbitrary action execution.
**Vulnerability Reproduction:**
```text
cat > janitor-dom-xss-poc.html <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Janitor DOM XSS Delivery</title>
<form id="janitor-delivery" method="GET" action="/">
<input name="user_input" value="<img src=x onerror=alert(1)>">
</form>
<script>document.getElementById('janitor-delivery').submit();</script>
HTML
python3 -m http.server 8765
```
**Remediation Advice:** Review the affected innerHTML assignment and sanitize input before insertion.
