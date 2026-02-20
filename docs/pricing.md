# Pricing

## Automated Cleanup is Free. Integrity Proof is the Standard.

The Janitor separates the **action** (dead code removal) from the **verified proof** (signed attestation that the action occurred correctly). The action is a utility. The proof is the product.

---

## Tiers

### Junior Janitor — Free

**For individual developers and open-source projects.**

No account required. No time limit. No LOC cap.

| Capability | Included |
|:-----------|:--------:|
| `janitor scan` — dead symbol detection | ✓ |
| `janitor clean` — shadow simulation + physical removal | ✓ |
| `janitor dedup` — structural clone detection + Safe Proxy Pattern | ✓ |
| `janitor bounce` — PR slop gate (JSON output for CI) | ✓ |
| `janitor badge` — code health SVG badge | ✓ |
| `janitor dashboard` — Ratatui TUI | ✓ |
| **PQC-Signed Audit Logs** | — |
| **Sovereign Status Badges** (compliance-grade) | — |
| **CI/CD Compliance Attestation** | — |

> The cleanup happens. The proof does not exist in a legally attestable form.

---

### Lead Specialist — $499 / year

**For teams and organizations that need to prove, not just perform.**

Everything in Junior Janitor, plus:

| Capability | Included |
|:-----------|:--------:|
| **PQC-Signed Audit Logs** — every excision event signed with Ed25519, stored in `.janitor/audit_log.json` | ✓ |
| **Sovereign Status Badges** — tamper-evident SVG with embedded signature | ✓ |
| **CI/CD Compliance Attestation** — `--token` flag enables signed reports in GitHub Actions, GitLab CI, Jenkins | ✓ |
| Priority support (48-hour SLA) | ✓ |
| Up to 5 seats | ✓ |

The token gate is a single Ed25519 signature verified offline — no network call, no telemetry.

[**Get Certified → thejanitor.lemonsqueezy.com**](https://thejanitor.lemonsqueezy.com/checkout/buy/lazarus_key)

---

### Industrial Core — Custom

**For monoliths exceeding 1 million LOC.**

Everything in Lead Specialist, plus:

- **On-Premises Token Server** — air-gapped deployments, no external calls
- **SLA** — guaranteed response times and uptime
- **Custom integration support** — Bazel, Pants, Meson, internal CI pipelines
- **Unlimited seats**
- **Volume pricing for multi-repo organizations**

Contact: [sales@thejanitor.app](mailto:sales@thejanitor.app)

---

## What the Token Does

A Lead Specialist or Industrial Core token is a **base64-encoded Ed25519 signature** of the string
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

**Can I use the Junior Janitor tier commercially?**
Yes. Running `janitor scan`, `janitor clean`, and `janitor dedup` on a commercial codebase is free. The BUSL-1.1 commercial restriction applies when you embed The Janitor as part of a paid SaaS product or issue attestations to your own paying customers. See [Licensing](licensing.md) for details.

**When does the license convert to MIT?**
`2030-02-15`. All versions ever released will be MIT from that date forward.
