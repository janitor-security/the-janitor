# Launch Checklist — Janitor Sentinel v7.9.4

> Internal operations document. Not for public nav.
> Every section is self-contained with exact commands, URLs, and button labels.

---

## Section 0 — Pre-Launch State Audit

Run these checks in order before any launch action.

```bash
# 1. Audit must pass — definition of done
just audit

# 2. Supply chain advisory scan — must return exit 0
cargo audit

# 3. Governor tests must pass
cd ~/dev/the-governor && cargo test

# 4. Confirm binary version
/tmp/janitor --version    # must print v7.9.4

# 5. Confirm ARCHITECTURE_INVERSION.md is committed
git -C ~/dev/the-janitor log --oneline | grep -i "ARCHITECTURE_INVERSION"
```

Checklist:
- [ ] `just audit` passes (all tests, fmt, clippy, check)
- [ ] `cargo audit` returns exit 0 — no new advisories
- [ ] `cargo test` in the-governor passes
- [ ] `janitor --version` outputs `v7.9.4`
- [ ] `ARCHITECTURE_INVERSION.md` is committed

---

## Section 1 — Deploy the Governor

### Deploy Command

Run from `~/dev/` (parent of both repos — Docker build context must include both):

```bash
cd ~/dev
fly deploy -a the-governor --config the-governor/fly.toml --dockerfile the-governor/Dockerfile .
```

### Verify Deployment

```bash
curl -s https://the-governor.fly.dev/health
# Expect: 200 OK
# If 503: Janitor daemon socket not detected — check entrypoint.sh logs
```

### Required Environment Variables

Set via `fly secrets set VAR=value -a the-governor`:

| Variable | Description | Where to get it |
|---|---|---|
| `GITHUB_APP_ID` | Numeric GitHub App ID | GitHub App settings page |
| `GITHUB_PRIVATE_KEY_BASE64` | RSA PEM, base64-encoded | `base64 -w0 <path/to/private-key.pem>` |
| `WEBHOOK_SECRET` | Secret set in the App's Webhook settings | Generate: `openssl rand -hex 32` |
| `JANITOR_PRIVATE_KEY_HEX` | Ed25519 seed (32 bytes, 64 hex chars) | `cargo run -p mint-token -- generate` |
| `LEMONSQUEEZY_WEBHOOK_SECRET` | LemonSqueezy webhook signing secret | LemonSqueezy dashboard → Webhooks |
| `RESEND_API_KEY` | Resend.com API key for welcome emails | resend.com/api-keys |
| `LS_INDIE_VARIANT_ID` | LemonSqueezy Team variant ID | LemonSqueezy dashboard → Products |
| `LS_INDIE_MONTHLY_VARIANT_ID` | LemonSqueezy monthly variant ID | LemonSqueezy dashboard → Products |

Optional (for /v1/induce AI endpoint):

| Variable | Description |
|---|---|
| `GOOGLE_APPLICATION_CREDENTIALS_JSON` | GCP Service Account JSON (inline) |
| `GOVERNOR_INVERT_MODE` | Set to `1` to enable Architecture Inversion mode |

Set secrets:

```bash
fly secrets set GITHUB_APP_ID=<id> -a the-governor
fly secrets set GITHUB_PRIVATE_KEY_BASE64="$(base64 -w0 ~/path/to/app.pem)" -a the-governor
fly secrets set WEBHOOK_SECRET="$(openssl rand -hex 32)" -a the-governor
fly secrets set JANITOR_PRIVATE_KEY_HEX=<64-hex-chars> -a the-governor
fly secrets set LEMONSQUEEZY_WEBHOOK_SECRET=<secret> -a the-governor
fly secrets set RESEND_API_KEY=<key> -a the-governor
fly secrets set LS_INDIE_VARIANT_ID=<id> -a the-governor
fly secrets set LS_INDIE_MONTHLY_VARIANT_ID=<id> -a the-governor
```

### Log Check

```bash
fly logs -a the-governor
```

Expected startup sequence:
```
PEM key audit (first/last 10 chars) ...
Janitor Daemon socket detected — pre-flight OK
Janitor Sentinel initialized
Listening on 0.0.0.0:3000
```

Note: v7.9.4 changes (architecture inversion routes `/v1/analysis-token`, `/v1/report`,
`dashmap` DashMap fields, `GOVERNOR_INVERT_MODE`) require a redeploy before the
Marketplace listing goes live.

---

## Section 2 — GitHub App Configuration

### App Settings URL

`https://github.com/settings/apps`

### Add `security_events: write` Permission

1. Open `https://github.com/settings/apps`
2. Click the app name (e.g. "janitor-sentinel")
3. Click "Permissions & events" in the left sidebar
4. Scroll to "Repository permissions"
5. Find "Code scanning alerts" — set to "Read and write"
6. Click "Save changes" at the bottom
7. Users who have already installed the app must re-approve the permission upgrade
   (GitHub will prompt them the next time they visit the app installation page)

### Verify SARIF Integration

Open a test PR in a repo where Sentinel is installed. When the PR contains a finding
(e.g. add `gets(buf)` to a C file), confirm:

- Check Run appears with "Janitor: Code Quality Gate Failed"
- The "Files changed" tab shows inline annotations for the finding

---

## Section 3 — GitHub Marketplace Submission

### Prerequisites

- [ ] GitHub App is published (not draft) at `https://github.com/apps/janitor-sentinel`
- [ ] App has a logo (PNG, 200×200 minimum)
- [ ] Domain `thejanitor.app` is verified on the GitHub organization
- [ ] `docs/marketplace-listing.md` short description is under 120 characters
- [ ] All 5 screenshots captured (see `docs/marketplace-listing.md` for list)
- [ ] Privacy Policy URL is live: `https://thejanitor.app/privacy`
- [ ] Terms of Service URL is live: `https://thejanitor.app/terms`
- [ ] Pricing plans configured in Marketplace listing form

### Submission URL

```
https://github.com/settings/apps/janitor-sentinel/marketplace-listing
```

(Replace `janitor-sentinel` with the actual app slug if different.)

### Content to Paste

Short description and full description are in `docs/marketplace-listing.md`.

Short description (120 chars):
> Structural firewall for AI-generated PRs. Detects security antipatterns, Swarm clones, and zombie deps before merge.

### Screenshot Requirements

Screenshots must be exactly 1280×640 pixels (GitHub Marketplace requirement).

1. Check Run — failure case (showing "Code Quality Gate Failed" + score summary)
2. Check Run — success case (showing "PQC Bond Issued")
3. Code Scanning annotations in PR diff
4. Swarm clone warning in Check Run summary
5. `janitor.toml` policy-as-code in GitHub UI

### Pricing Configuration

In the Marketplace listing form, add:

| Plan | Price | Details |
|---|---|---|
| Free | $0 | GitHub Action (CLI mode, no Sentinel) |
| Team | $499/yr | Janitor Sentinel — unlimited repos, single org |

### Domain Verification Steps

1. Go to `https://github.com/settings/apps/janitor-sentinel/marketplace-listing`
2. Under "Publisher and support information", enter `https://thejanitor.app`
3. GitHub will provide a DNS TXT record to add to the domain
4. Add the TXT record at your DNS provider
5. Click "Verify domain" — GitHub confirms within minutes

---

## Section 4 — Webhook Configuration (Customer-Facing)

### What the Webhook Is

The Janitor can emit a signed NDJSON POST to any URL when a bounce completes.
Useful for Slack, Teams, Datadog, Splunk, PagerDuty, and SIEM integrations.
Payloads are HMAC-SHA256 signed with the configured secret.

### janitor.toml Configuration Block

```toml
[webhook]
url    = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
events = ["critical_threat", "necrotic_flag"]  # or ["all"] for every bounce
secret = "env:JANITOR_WEBHOOK_SECRET"           # resolves env var at call time
# secret = "mysecretstring"                     # or inline (not recommended)
```

### URL Sources by Platform

| Platform | How to get URL |
|---|---|
| Slack | Slack App settings → Incoming Webhooks → Add new webhook to workspace |
| Teams | Teams channel → Connectors → Incoming Webhook → Configure |
| Datadog | Datadog integrations → Webhooks → New webhook |
| Splunk HEC | Splunk → Settings → Data inputs → HTTP Event Collector → New Token |
| PagerDuty | PagerDuty service → Integrations → Add integration → Custom Event Transformer |
| Webhook.site | `https://webhook.site` — generates a test URL immediately |

### Set the Webhook Secret

```bash
export JANITOR_WEBHOOK_SECRET="$(openssl rand -hex 32)"
# or set it in your CI/CD secrets and reference as env:JANITOR_WEBHOOK_SECRET in toml
```

### Verify with curl

```bash
# Trigger a test bounce and capture the payload
janitor bounce . --patch /dev/null --format json 2>/dev/null > /tmp/test_payload.json

# Manually POST to verify your webhook receiver accepts the signature
SECRET="your-secret-here"
PAYLOAD=$(cat /tmp/test_payload.json)
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | awk '{print "sha256="$2}')
curl -X POST https://your-webhook-url \
  -H "Content-Type: application/json" \
  -H "X-Janitor-Signature-256: $SIG" \
  -H "X-Janitor-Event: critical_threat" \
  -d "$PAYLOAD"
```

### Header Reference

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `X-Janitor-Event` | `critical_threat` or `necrotic_flag` |
| `X-Janitor-Signature-256` | `sha256=<hex-digest>` — HMAC-SHA256 of the request body |

---

## Section 5 — Lemon Squeezy Trial Tier

### URL

`https://app.lemonsqueezy.com`

### Enable 14-Day Trial on $499/yr Variant

1. Log in at `https://app.lemonsqueezy.com`
2. Navigate to Products → The Janitor → Team Tier ($499/yr)
3. Click "Edit" on the variant
4. Under "Subscription", enable "Free trial"
5. Set trial period to 14 days
6. Click "Save"

### Post-Trial Funnel Note

After the trial ends, LemonSqueezy sends a payment reminder email automatically.
Customers who do not convert are downgraded to the Free tier (CLI only — no Sentinel).
Configure the post-trial email template in LemonSqueezy Email → Subscription templates.

---

## Section 6 — Forensic Audit Drop (First Public Report)

### Target: kubernetes/kubernetes

```bash
# Hyper-gauntlet: fetch all PR refs via libgit2, zero gh pr diff subshells
just hyper-gauntlet --pr-limit 1000 --timeout 30 \
  --targets /dev/stdin <<< "kubernetes/kubernetes" \
  --gauntlet-dir ~/dev/gauntlet --out-dir ~/dev/gauntlet-out
```

Or using the generate-client-package tool for a full PDF + CSV output:

```bash
PR_LIMIT=1000 ./tools/generate_client_package.sh kubernetes/kubernetes
```

### Post-Processing Steps

```bash
# Generate markdown report
janitor report --repo ~/dev/gauntlet/kubernetes --format markdown \
  --out ~/dev/gauntlet-out/kubernetes-report.md

# Generate CSV audit trail
janitor export --repo ~/dev/gauntlet/kubernetes \
  --out ~/dev/gauntlet-out/kubernetes-audit.csv

# Generate CBOM bond
janitor report --repo ~/dev/gauntlet/kubernetes --format cbom \
  --out ~/dev/gauntlet-out/kubernetes-cbom.json

# Validate CBOM at cyclonedx.org
# Upload ~/dev/gauntlet-out/kubernetes-cbom.json to https://cyclonedx.org/tool-center/
```

### Distribution Targets

| Platform | URL / Handle |
|---|---|
| Hacker News | `https://news.ycombinator.com/submit` — title: "We audited 1,000 kubernetes/kubernetes PRs for AI slop — here's what we found" |
| Kubernetes Security List | `kubernetes-security@googlegroups.com` |
| CNCF Slack | `#security` channel at `cloud-native.slack.com` |
| r/netsec | `https://www.reddit.com/r/netsec/submit` |
| r/rust (for methodology) | `https://www.reddit.com/r/rust/submit` |

### Case Study Format Template

```markdown
# [Repo Name] PR Audit Report — Janitor v7.9.4

**Date**: [YYYY-MM-DD]
**PRs Audited**: [N]
**Engine**: The Janitor v7.9.4 (tree-sitter AST, MinHash LSH, ML-DSA-65 attestation)

## Executive Summary

- [N]% of PRs scored above the 100-point slop threshold
- [N] Swarm clone pairs detected (>85% structural similarity)
- [N] security antipatterns found (category breakdown)
- [N] zombie dependencies re-introduced

## Top 10 PRs by Slop Score

[Table from `janitor report --format markdown`]

## Methodology

See https://thejanitor.app/architecture for the full technical specification.
```

---

## Section 7 — Architecture Inversion Deployment (Future)

Architecture Inversion replaces the git-clone path in the Governor with a
token-exchange protocol where source code never leaves the customer's runner.

### Validation Steps Before Production

```bash
# 1. Verify both routes respond correctly in legacy mode
curl -X POST https://the-governor.fly.dev/v1/analysis-token \
  -H "Content-Type: application/json" \
  -d '{"repo":"test/repo","pr":1,"head_sha":"abc","installation_id":0}'
# Expect: 404 (invert_mode is false)

curl -X POST https://the-governor.fly.dev/v1/report \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer test" \
  -d '{}'
# Expect: 404 (invert_mode is false)

# 2. Test token issuance in staging with GOVERNOR_INVERT_MODE=1
# Deploy a staging instance or set the flag temporarily
fly secrets set GOVERNOR_INVERT_MODE=1 -a the-governor-staging

# 3. End-to-end test: run janitor bounce with --report-url against staging
janitor bounce . --patch /dev/null \
  --report-url https://the-governor-staging.fly.dev/v1/report \
  --analysis-token $(curl -sf ... | jq -r .token)
```

### Enable GOVERNOR_INVERT_MODE

```bash
fly secrets set GOVERNOR_INVERT_MODE=1 -a the-governor
fly deploy -a the-governor --config the-governor/fly.toml --dockerfile the-governor/Dockerfile ~/dev/
```

### Rollback Procedure

```bash
# Remove the flag to revert to legacy clone mode
fly secrets unset GOVERNOR_INVERT_MODE -a the-governor
fly deploy -a the-governor --config the-governor/fly.toml --dockerfile the-governor/Dockerfile ~/dev/
```

### When to Retire Legacy Clone Path

Retire when:
1. GOVERNOR_INVERT_MODE=1 has been stable in production for at least 2 weeks
2. No customer reports of missed Check Runs under invert mode
3. All active Sentinel customers have been notified of the migration

To retire: remove the git clone block in `handle_pull_request()` starting at
"Sandboxed temp workspace", remove the `tempfile` dependency from Cargo.toml,
and downgrade the Fly.io machine type from 512 MB to 256 MB.

### Marketing Copy Changes After Inversion Is Verified

Update `docs/index.md` and `README.md`:
- Remove the deployment model table caveat
- Change "CLI + GitHub Action: Never | Sentinel: Temporarily" to "Never" for both rows
- Update `docs/privacy.md` Section 2 table: remove the "Sentinel: Temporarily cloned" row
- Remove the Architecture Inversion pending note from `ARCHITECTURE_INVERSION.md`

---

## Section 8 — Post-Launch Validation

### End-to-End Test Sequence

```bash
# 1. Open a test PR in a repo with Sentinel installed
# 2. Verify spinner appears on PR within 5 seconds of opening
# 3. Verify Check Run completes within 60 seconds
# 4. Verify Check Run title is one of:
#    - "Janitor: Clean — PQC Bond Issued"
#    - "Janitor: Code Quality Gate Failed"
```

### SARIF Annotation Test

1. Create a test PR that adds `gets(buf);` to a C file
2. Open the PR → "Files changed" tab
3. Confirm inline annotation appears: `security:gets_unsafe_input — gets() is unsafe`
4. Confirm annotation links to the finding explanation

### Webhook Delivery Test with HMAC Verification

```bash
# Set up a test receiver at webhook.site
# Configure janitor.toml with the webhook.site URL
# Open a PR that scores >= 100 (add a security antipattern)
# Check webhook.site for the delivery
# Verify the X-Janitor-Signature-256 header matches:
PAYLOAD="<body from webhook.site>"
SECRET="your-secret"
echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET"
```

### CSV Audit Trail Test

```bash
janitor export --repo . --out test-audit.csv
head -3 test-audit.csv
# Expected columns (v7.9.3, 16 total):
# PR_Number,Author,Score,Threat_Class,Unlinked_PR,Logic_Clones,
# Antipattern_IDs,Collided_PRs,Time_Saved_Hours,Operational_Savings_USD,
# Timestamp,PR_State,Is_Bot,Repo_Slug,Commit_SHA,Policy_Hash
```

### CBOM Bond Validation

```bash
# Generate a CBOM from any repo with bounce log entries
janitor report --repo . --format cbom --out test-cbom.json

# Validate at cyclonedx.org
# Upload test-cbom.json to https://cyclonedx.org/tool-center/
# Expect: "Valid CycloneDX v1.5 SBOM"
```

### NCD Calibration Measurement

```bash
# Count PRs flagged with ncd_anomaly antipattern in the global bounce log
janitor report --global --format json \
  | jq '.[] | select(.antipatterns[] | contains("ncd_anomaly")) | .pr_number' \
  | wc -l
# Expected: < 5% of total PRs for a healthy codebase (threshold = 0.15 NCD ratio)
```
