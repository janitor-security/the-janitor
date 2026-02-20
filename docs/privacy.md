# Privacy Policy

**Effective Date:** 2026-02-19
**Entity:** The Janitor (operated by GhrammR)
**Contact:** privacy@thejanitor.app

---

## 1. Overview

The Janitor is a **locally-executed software binary**. It does not have a backend, a cloud service, or a telemetry system. This Privacy Policy describes what data is and is not collected when you use the Software.

**Short version: We do not receive your source code. We do not collect telemetry. We do not know you are using the Software unless you contact us.**

---

## 2. Data We Do NOT Collect

The Software does not transmit any of the following:

| Category | Transmitted? |
|:---------|:------------:|
| Your source code | No |
| File paths or directory names | No |
| Dead symbol names or analysis results | No |
| Audit log contents | No |
| Machine identifiers (hostname, IP, CPU) | No |
| Usage telemetry (commands run, frequency, flags used) | No |
| Crash reports | No |
| Email address or identity | No |

The Software operates entirely offline. All analysis — reference graph construction, heuristic classification, AhoCorasick scanning, shadow-tree simulation, and structural clone detection — is performed on your local machine using only your local files.

---

## 3. Data Processed Locally (Not Transmitted)

When you run The Janitor, the following data is processed **in memory on your machine** and is never transmitted:

- **Source code contents**: Read via memory-mapped I/O (`memmap2`) for analysis. Never written to network sockets.
- **Symbol names**: Extracted, stored in `.janitor/symbols.rkyv` on your local disk.
- **Audit log entries**: Written to `.janitor/audit_log.json` on your local disk. You control this file.
- **Ghost backups**: Deleted symbols backed up to `.janitor/ghost/` on your local disk.

All `.janitor/` artefacts remain on your machine under your sole control.

---

## 4. Token Verification (Lead Specialist / Industrial Core)

Token verification is a **pure offline cryptographic operation**:

1. Your token is a base64-encoded Ed25519 signature.
2. The binary verifies the signature against a public verifying key embedded in the binary at compile time.
3. No network request is made. No token value or verification result is transmitted anywhere.

The Janitor does not know when or how often you use your token.

---

## 5. Purchase Data (Lemon Squeezy)

Token purchase is handled by **Lemon Squeezy** ([lemonsqueezy.com](https://lemonsqueezy.com)), an independent payment processor. When you purchase a license:

- Payment and billing data is processed by Lemon Squeezy under their own [Privacy Policy](https://www.lemonsqueezy.com/privacy).
- The Janitor receives only the information necessary to issue your token (customer name/email for the attestation package).
- This data is used solely to generate and deliver your token. It is not sold or shared with third parties.

---

## 6. Website Analytics (thejanitor.app)

The documentation site at `thejanitor.app` is hosted via GitHub Pages. GitHub may collect standard server access logs (IP address, browser user agent, referrer URL) as part of hosting. See [GitHub's Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement) for details.

The Janitor does not use cookies, tracking pixels, or third-party analytics on thejanitor.app.

---

## 7. Contact and Data Requests

If you have questions about this Privacy Policy or wish to exercise any applicable data rights, contact:

**privacy@thejanitor.app**

---

## 8. Changes to This Policy

This policy may be updated. The Effective Date at the top of this document reflects the most recent revision. Material changes will be noted in the project's release notes.
