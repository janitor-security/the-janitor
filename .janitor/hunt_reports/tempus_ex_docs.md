# Hunt Report: tempus-ex/docs

**Sprint**: Sprint Batch 100
**Date**: 2026-05-03
**Target**: https://github.com/tempus-ex/docs
**Engagement**: infinite_athlete_targets
**Format**: bugcrowd
**Result**: no_findings

## Engine Output

```
Summary Title: Multiple instances of no_findings in target
VRT Category: Informational
Affected Package / Component: docs@0.1.0 (package.json)
Vulnerability Details: No exploitable issue was identified in the reviewed target artifacts.
Business Impact: No direct business impact was identified because the scan did not emit any findings.
Data Flow Analysis: No vulnerable source-to-sink path was identified.
Vulnerability Reproduction: No reproduction steps are required.
Remediation Advice: No mitigation required.
```

## Manual Analysis

Target is a Next.js developer documentation site. Notable files:
- `lib/auth.ts` — cookie-based auth guard (`fftoken`) delegating to `validateFusionFeedToken`
- `lib/fusionfeed.ts` — token validated by calling `POST {fusionFeedUrl}/v2/graphql`; all
  `fetch()` calls are client-side TypeScript, blocked by SOP/CORS. Per Threat Model
  Awareness Law: client-side HTTP calls are not server-side SSRF. Approval % < 10%.
- `aws/lib/github-actions-stack.ts` — AWS CDK stack with `apigateway:GET: '*'`; this is
  infrastructure-as-code in the docs deployment CDK, not accessible via the public web
  application. Requires AWS console access to exploit. Per Threat Model Awareness Law:
  requires Administrative privileges. Approval % < 10%. No elevation path to remote
  exploitation without AWS credential compromise — entry deleted.
- No injectable templates, no server-side dynamic rendering of untrusted input found.
