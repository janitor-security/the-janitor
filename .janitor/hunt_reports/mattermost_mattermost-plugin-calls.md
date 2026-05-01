# Hunt Report: mattermost/mattermost-plugin-calls

**Date**: 2026-05-01
**Engine**: v10.2.0-beta.5
**Format**: bugcrowd
**Status**: 2 billable finding classes

---

**Summary Title:** security:ssrf_dynamic_url in recording component
**VRT Category:** Server-Side Request Forgery (SSRF)
**Affected Package / Component:** **github.com/mattermost/mattermost-plugin-calls** go1.24.13 (`go.mod`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: standalone/src/recording/index.tsx, Line: 40
**Business Impact:** SSRF in the recording component could allow an attacker to direct the recording agent to make unauthorized HTTP requests to internal services.
**Vulnerability Reproduction:**
```text
curl -X POST http://target.local/vulnerable -H 'Content-Type: application/json' -d '{"url": "http://169.254.169.254/latest/meta-data/"}'
```
**Remediation Advice:** Validate and allowlist the URL used by the recording component against known-safe endpoints.

---

**Summary Title:** security:unpinned_asset in speech binary download
**VRT Category:** Informational
**Affected Package / Component:** **github.com/mattermost/mattermost-plugin-calls** go1.24.13 (`go.mod`)
**Vulnerability Details:**
I found the following vulnerable code paths while reviewing the target artifacts:
- File: lt/cmd/speech/main.go, Line: 36
**Business Impact:** An unpinned asset download in the build pipeline can be substituted by a supply-chain attacker without detection.
**Vulnerability Reproduction:**
```text
# Step 1: record the current digest:
curl -fsSL "<remote-url>" -o /tmp/janitor_asset_probe && sha256sum /tmp/janitor_asset_probe
# Step 2: apply an inline checksum guard
```
**Remediation Advice:** Pin the downloaded asset to a specific SHA-256 digest.
