# Pricing

## Automated Cleanup is Free. Integrity Proof is the Standard.

The Janitor separates the **action** (dead code removal) from the **verified proof** (signed attestation that the action occurred correctly). The action is a utility. The proof is the product.

---

## Tiers

### Free Tier

**For individual developers and open-source projects.**

No account required. No time limit. No LOC cap.

| Capability | Included |
|:-----------|:--------:|
| `janitor scan` — dead symbol detection | ✓ |
| `janitor clean` — shadow simulation + physical removal | ✓ |
| `janitor dedup` — structural clone detection + Safe Proxy Pattern | ✓ |
| `janitor bounce` — PR slop gate (JSON output for CI) | ✓ |
| `janitor badge` — Code Health Badge (SVG) | ✓ |
| `janitor dashboard` — Ratatui TUI | ✓ |
| **PQC-Signed Audit Logs** | — |
| **CI/CD Compliance Attestation** | — |
| **Janitor Sentinel** (GitHub App automation) | — |

> The cleanup happens. The proof does not exist in a legally attestable form.

---

### Team Specialist — $499 / year

**A team digital license for engineering organizations that need automated CI/CD enforcement and verifiable audit trails.**

Includes all Junior Janitor capabilities, plus:

| Capability | Included |
|:-----------|:--------:|
| **PQC-Signed Audit Logs** — every cleanup event automatically signed with ML-DSA-65 (NIST FIPS 204), stored in `.janitor/audit_log.json` | ✓ |
| **CI/CD Compliance Attestation** — `--token` flag activates signed reports in GitHub Actions, GitLab CI, Jenkins | ✓ |
| **Janitor Sentinel** — GitHub App that automatically runs `janitor bounce` on every pull request and posts a slop-score comment | ✓ |
| **Shared Credit Pool** — team-level token shared across all CI runners; no per-seat key management | ✓ |
| **License Issue SLA** — 48-hour response for license key delivery and renewal | ✓ |
| Up to 25 named seats on a single license | ✓ |

When a pull request clears the gate, Janitor Sentinel issues a CycloneDX v1.5 CBOM automatically — no token flag, no manual step.

[**Activate — Yearly ($499/yr) →**](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348) · [**Monthly billing →**](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1362706)

---

### Industrial Core — Custom

**An enterprise digital license for organizations where code integrity is a compliance obligation, not a preference.**

Includes all Team Specialist capabilities, plus:

- **On-Premises Token Server** — dedicated verifying key issued for air-gapped deployments; zero external calls required
- **Keypair Rotation Protocol** — signed rotation schedule; invalidating a compromised token requires only a keypair rotation, satisfying SOC 2 Type II change-management requirements
- **Enterprise License SLA** — contractual response times for key issuance, renewal, and emergency rotation (4-hour SLA for confirmed compromises)
- **Indemnification** — commercial indemnification clause available for regulated industries
- **Extended CI/CD Compatibility** — operates with Bazel, Pants, Meson, and internal CI pipelines without modification
- **Unlimited named seats** on a single organization license

[**Book an Audit → sales@thejanitor.app**](mailto:sales@thejanitor.app)

---

## How Attestation Works

### Team — Janitor Sentinel

When a Team-licensed pull request clears the slop gate, **Janitor Sentinel** automatically issues a **CycloneDX v1.5 CBOM** (Cryptography Bill of Materials). The CBOM records every cryptographic operation: the ML-DSA-65 (NIST FIPS 204) attestation signatures, BLAKE3 structural hashes, and per-symbol audit entries covering `{timestamp}{file_path}{sha256_pre_cleanup}`.

No CLI flag required. No manual step. Janitor Sentinel handles issuance automatically on a clean merge.

### Industrial Core — On-Premises

Industrial Core licensees receive a dedicated verifying-key token for air-gapped deployments. The token is a base64-encoded ML-DSA-65 (NIST FIPS 204) signature of the string `JANITOR_PURGE_AUTHORIZED`, verified offline against the public key embedded in the binary. No network call is made at verification time.

The cleanup is identical at every tier. The attestation is what you are paying for.

---

## FAQ

**Is the Team license a subscription that can be revoked?**
Team licenses are managed via Janitor Sentinel. Industrial Core on-premises tokens are ML-DSA-65 (NIST FIPS 204) signatures — deterministic for a given keypair. Revocation is achieved by rotating the keypair; existing tokens for the old key become cryptographically invalid.

**Does the tool phone home?**
No. Token verification, audit log signing, and all analysis are fully offline computations. No telemetry is collected.

**Can I use the Free tier commercially?**
Yes. Running `janitor scan`, `janitor clean`, and `janitor dedup` on a commercial codebase is free. The BUSL-1.1 commercial restriction applies when you embed The Janitor as part of a paid SaaS product or issue attestations to your own paying customers. See [Licensing](licensing.md) for details.

**When does the license convert to MIT?**
`2030-02-15`. All versions ever released will be MIT from that date forward.
