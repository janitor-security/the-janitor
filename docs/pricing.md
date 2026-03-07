# Pricing & Licensing

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

Includes all Free tier capabilities, plus:

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

## License (BUSL-1.1)

**The Janitor** is licensed under the [Business Source License 1.1 (BUSL-1.1)](https://spdx.org/licenses/BUSL-1.1.html).

BUSL-1.1 distinguishes between:

- **Non-production use** — free, unrestricted. Read the code, modify it, run it locally, test it, evaluate it, contribute to it.
- **Production / commercial use** — requires a commercial license when the use constitutes a "Production Use" as defined below.

**Change Date**: `2030-02-15`. On that date, the license automatically converts to **MIT** and remains MIT in perpetuity. Every release binary ever shipped will also be MIT from that date forward.

### What Is Always Free

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

### What Requires a License

A commercial license is required when **any of the following apply**:

| Use Case | License Required |
|----------|-----------------|
| Issuing **signed audit attestations** (`--token`) to customers or auditors | ✅ Team Specialist |
| Embedding The Janitor in a **SaaS product** or hosted service | ✅ Team Specialist |
| Running `janitor clean --token` in **CI/CD on behalf of paying customers** | ✅ Team Specialist |
| Deploying in an organization with **>10 million LOC** under management | ✅ Industrial Core |
| On-premises token server or SLA-backed support | ✅ Industrial Core |

### 90-Day Immaturity Gate

`clean` and `dedup --apply` refuse to remove symbols from source files modified fewer than 90 days ago, even with a valid token. This protects recently active code from accidental excision. Pass `--override-tax` to bypass this gate when you explicitly intend to clean recently modified files.

### Contributor License Agreement

By opening a pull request, you agree that your contribution is licensed to the project under the same BUSL-1.1 terms, with the automatic MIT conversion on the Change Date. No separate CLA signature is required.

---

## Token Gate

Destructive operations (`janitor clean`, `janitor dedup --apply`) require a valid **purge token** — a base64-encoded ML-DSA-65 (NIST FIPS 204) signature of the string `JANITOR_PURGE_AUTHORIZED`.

```
Token = Base64( ML_DSA65_Sign(SIGNING_KEY, "JANITOR_PURGE_AUTHORIZED") )
```

The binary embeds only the **verifying key** (`const VERIFYING_KEY_BYTES`). The signing key never leaves thejanitor.app.

### Verification Flow

```
┌─────────────┐        ┌──────────────────┐        ┌─────────────────┐
│  CLI flag   │        │  SigningOracle    │        │ VERIFYING_KEY   │
│ --token T   │──────▶ │  verify_token(T) │──────▶ │ BYTES (binary)  │
└─────────────┘        └────────┬─────────┘        └────────┬────────┘
                                │                           │
                          base64_decode(T)          VerifyingKey::
                                │                  from_bytes(...)
                          sig_bytes [64]                    │
                                │                           │
                                └──────── verify(msg, sig) ─┘
                                                │
                                        Ok → proceed
                                        Err → ACCESS DENIED
```

1. Base64-decode the token → ML-DSA-65 signature bytes.
2. Construct `Signature::from_bytes(&sig_bytes)`.
3. Call `verifying_key.verify(b"JANITOR_PURGE_AUTHORIZED", &sig)`.
4. `Ok(())` → operation proceeds. Any error → process exits 1.

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Unforgeability** | ML-DSA-65 (NIST FIPS 204) — 128-bit post-quantum security level. |
| **Message binding** | Token is a signature of the exact string `JANITOR_PURGE_AUTHORIZED`. |
| **Key isolation** | Binary embeds only the 32-byte verifying key. Private key never on end-user machine. |
| **No network call** | Verification is fully offline — `VerifyingKey::verify()` is a pure local computation. |

On an invalid or missing token, the CLI prints:

```
ACCESS DENIED. Purchase ML-DSA-65 Token at thejanitor.app
```

and exits with code `1`. No partial work is performed.

---

## FAQ

**Is the Team license a subscription that can be revoked?**
Team licenses are managed via Janitor Sentinel. Industrial Core on-premises tokens are ML-DSA-65 (NIST FIPS 204) signatures — deterministic for a given keypair. Revocation is achieved by rotating the keypair; existing tokens for the old key become cryptographically invalid.

**Does the tool phone home?**
No. Token verification, audit log signing, and all analysis are fully offline computations. No telemetry is collected.

**Can I use the Free tier commercially?**
Yes. Running `janitor scan`, `janitor clean`, and `janitor dedup` on a commercial codebase is free. The BUSL-1.1 commercial restriction applies when you embed The Janitor as part of a paid SaaS product or issue attestations to your own paying customers.

**When does the license convert to MIT?**
`2030-02-15`. All versions ever released will be MIT from that date forward.

**License questions:** legal@thejanitor.app
**Commercial inquiries:** sales@thejanitor.app
