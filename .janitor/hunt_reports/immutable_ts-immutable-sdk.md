# Hunt Report: immutable/ts-immutable-sdk

**Date**: 2026-05-01
**Engine**: v10.2.0-beta.5
**Format**: bugcrowd
**Status**: 2 billable finding classes

---

**Summary Title:** Multiple instances of security:ssrf_dynamic_url in target
**VRT Category:** Server-Side Request Forgery (SSRF)
**Affected Package / Component:** **ts-immutable-sdk@Unknown** (`package.json`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: packages/auth-next-server/src/config.ts, Line: 38
- File: packages/auth/src/Auth.ts, Line: 677
- File: packages/checkout/sdk/src/availability/availability.ts, Line: 25
- File: packages/checkout/widgets-lib/src/components/Transak/useTransakIframe.ts, Line: 106
- File: packages/internal/bridge/sdk/src/lib/gmpRecovery.ts, Line: 35
- File: packages/internal/metrics/src/utils/request.ts, Line: 19
- File: packages/wallet/src/zkEvm/relayerClient.ts, Line: 136
**Business Impact:** The identified sinks can enable high-impact compromise of confidentiality, integrity, and availability if they are reachable in production workflows.
**Vulnerability Reproduction:**
```text
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```
**Remediation Advice:** Review the affected sink usage, remove unsafe data flow into the target API, and apply the framework-native safe alternative.

---

**Summary Title:** Multiple instances of security:dom_xss_innerHTML in target
**VRT Category:** Cross-Site Scripting (XSS) > DOM-Based
**Affected Package / Component:** **ts-immutable-sdk@Unknown** (`package.json`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: packages/auth/src/overlay/embeddedLoginPromptOverlay.ts, Line: 25
**Business Impact:** A DOM-based XSS sink can enable session theft, arbitrary action execution in a victim browser, and lateral compromise of privileged user workflows. Critical for Web3 Passport wallet — XSS can enable unauthorized transactions on behalf of the wallet user.
**Vulnerability Reproduction:**
```text
cat > janitor-dom-xss-poc.html <<'HTML'
<!doctype html>
<meta charset="utf-8">
<title>Janitor DOM XSS Delivery</title>
<form id="janitor-delivery" method="GET" action="<vulnerable-client-route>">
<input name="user_input" value="<img src=x onerror=alert(1)>">
</form>
<script>document.getElementById('janitor-delivery').submit();</script>
HTML
python3 -m http.server 8765
```
**Remediation Advice:** Review the affected sink usage, remove unsafe data flow into the target API, and apply the framework-native safe alternative.
