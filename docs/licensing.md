# Licensing

**The Janitor** is licensed under the [Business Source License 1.1 (BUSL-1.1)](https://spdx.org/licenses/BUSL-1.1.html).

---

## What Is BUSL-1.1?

BUSL-1.1 is a **source-available license** that distinguishes between:

- **Non-production use** — free, unrestricted. Read the code, modify it, run it locally, test it, evaluate it, contribute to it.
- **Production / commercial use** — requires a commercial license when the use constitutes a "Production Use" as defined below.

**Change Date**: `2030-02-15`. On that date, the license automatically converts to **MIT** and remains MIT in perpetuity. Every release binary ever shipped will also be MIT from that date forward.

---

## What Is Free

The following are always free, for individuals and organizations of any size:

| Use Case | Free? |
|----------|-------|
| Scanning your codebase locally | ✅ |
| `janitor scan` / `janitor dedup` / `janitor dashboard` | ✅ |
| Running `janitor clean` without a purge token | ✅ |
| Evaluation, research, academic use | ✅ |
| Contributing to this repository | ✅ |
| Using the binary in personal or open-source projects | ✅ |
| Building internal tooling that calls the binary | ✅ |

> **Rule of thumb**: If you are using The Janitor as a developer productivity tool for yourself or your open-source project, you pay nothing.

---

## What Requires a License (Team / Industrial Core)

A commercial license is required when **any of the following apply**:

| Use Case | License Required |
|----------|-----------------|
| Issuing **signed audit attestations** (`--token`) to customers or auditors | ✅ Lead Specialist |
| Embedding The Janitor in a **SaaS product** or hosted service | ✅ Lead Specialist |
| Running `janitor clean --token` or `janitor dedup --apply --token` in **CI/CD on behalf of paying customers** | ✅ Lead Specialist |
| Deploying in an organization with **>10 million LOC** under management | ✅ Industrial Core |
| On-premises token server or SLA-backed support | ✅ Industrial Core |

> **Rule of thumb**: If you are selling a product or service that includes The Janitor's output (especially signed audit logs or integrity attestations) as part of your value proposition, a commercial license is required.

---

## Tier Summary

| Tier | Price | Who It's For |
|------|-------|--------------|
| **Free** | **$0** | Individual developers. Unlimited Scan, Cleanup, Dedup, Bounce, Dashboard. No signed logs. |
| **Team** | **$499/yr** | Teams up to 25. All free features + Ed25519 Integrity Bonds + CI/CD Compliance Attestation + The Governor GitHub App. |
| **Industrial** | **Custom** | Monoliths >1M LOC. On-prem token server, keypair rotation protocol, SOC 2 audit support, enterprise SLA, unlimited seats. |

[**Get Certified → thejanitor.lemonsqueezy.com**](INSERT_REAL_LEMONSQUEEZY_LINK_HERE)

---

## The Token Gate: Technical Implementation

The commercial boundary is enforced cryptographically — not by a license key file or a network check.

1. **Free path**: `janitor scan`, `janitor clean --force-purge` (without `--token`) — no token required.
2. **Paid path**: operations requiring a purge token call `vault::SigningOracle::verify_token(token)`, which verifies an Ed25519 signature of the string `JANITOR_PURGE_AUTHORIZED` against a verifying key embedded in the binary.
3. **Token issuance**: tokens are minted by thejanitor.app's signing key after license verification. The private key never leaves thejanitor.app servers.
4. **Offline verification**: the binary performs a pure local cryptographic check — no network call, no telemetry.

See [Token Gate documentation](sovereignty/tokens.md) for the full protocol.

---

## 90-Day Immaturity Gate

As an additional safety guarantee, `clean` and `dedup --apply` refuse to remove symbols from source files modified fewer than 90 days ago, even with a valid token. This protects recently active code from accidental excision.

Pass `--override-tax` to bypass this gate when you explicitly intend to clean recently modified files.

---

## Contributor License Agreement

By opening a pull request, you agree that your contribution is licensed to the project under the same BUSL-1.1 terms, with the automatic MIT conversion on the Change Date. No separate CLA signature is required.

---

## Contact

License questions: **legal@thejanitor.app**
Commercial inquiries: **sales@thejanitor.app**
