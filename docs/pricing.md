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
| **The Governor** (GitHub App automation) | — |

> The cleanup happens. The proof does not exist in a legally attestable form.

---

### Team Specialist — $499 / year

**A team digital license for engineering organizations that need automated CI/CD enforcement and verifiable audit trails.**

Includes all Junior Janitor capabilities, plus:

| Capability | Included |
|:-----------|:--------:|
| **PQC-Signed Audit Logs** — every cleanup event automatically signed with Ed25519, stored in `.janitor/audit_log.json` | ✓ |
| **CI/CD Compliance Attestation** — `--token` flag activates signed reports in GitHub Actions, GitLab CI, Jenkins | ✓ |
| **The Governor** — GitHub App that automatically runs `janitor bounce` on every pull request and posts a slop-score comment | ✓ |
| **Shared Credit Pool** — team-level token shared across all CI runners; no per-seat key management | ✓ |
| **License Issue SLA** — 48-hour response for license key delivery and renewal | ✓ |
| Up to 25 named seats on a single license | ✓ |

The token gate is a single Ed25519 signature verified offline — no network call, no telemetry.

[**Get Certified → thejanitor.lemonsqueezy.com**](https://thejanitor.lemonsqueezy.com/checkout/buy/lazarus_key)

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

## What the Token Does

A Team or Industrial Core token is a **base64-encoded Ed25519 signature** of the string
`JANITOR_PURGE_AUTHORIZED`. The binary embeds only the verifying key (32 bytes) — no network call
is made at verification time.

When you run:

```bash
janitor clean ./src --force-purge --token <your-token>
```

The Janitor:
1. Verifies the token offline (pure cryptographic check)
2. Performs the cleanup
3. Signs each audit entry with a per-event Ed25519 signature covering `{timestamp}{file_path}{sha256_pre_cleanup}`
4. Writes the signed log to `.janitor/audit_log.json`
5. Prints: `🛡️ INTEGRITY VERIFIED. PQC-Signed Audit Log generated at .janitor/audit_log.json.`

Without a token:
1. Performs the cleanup
2. Writes an unsigned audit log
3. Prints: `✅ RECLAMATION COMPLETE. (Note: No signed attestation generated. Run with --token to certify this excision.)`

The cleanup is identical either way. The attestation is what you are paying for.

---

## FAQ

**Is the token a subscription that can be revoked?**
Tokens are deterministic for a given keypair — the same key always produces the same token. Revocation works by rotating the keypair (updating `VERIFYING_KEY_BYTES` in the binary and redistributing). Existing tokens for the old key become invalid.

**Does the tool phone home?**
No. Token verification, audit log signing, and all analysis are fully offline computations. No telemetry is collected.

**Can I use the Free tier commercially?**
Yes. Running `janitor scan`, `janitor clean`, and `janitor dedup` on a commercial codebase is free. The BUSL-1.1 commercial restriction applies when you embed The Janitor as part of a paid SaaS product or issue attestations to your own paying customers. See [Licensing](licensing.md) for details.

**When does the license convert to MIT?**
`2030-02-15`. All versions ever released will be MIT from that date forward.
