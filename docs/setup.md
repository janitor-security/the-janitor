# Setup

Configuration reference and CI integration guide for The Janitor.

> **For Engineering Managers:** The Janitor protects your public repository
> from being flagged as low-quality AI spam by Google and other indexers.
> Every pull request that passes the gate carries a cryptographically signed
> Integrity Bond — machine-verifiable proof that the merged code meets your
> structural quality threshold. AI-generated boilerplate (NCD ratio < 0.15)
> is intercepted before merge, keeping your codebase's information density
> consistent with human-authored work and out of reach of low-quality content
> classifiers.

---

## Janitor Sentinel — GitHub App

**Janitor Sentinel** is the GitHub App that runs the engine against every pull request.
It posts a Check Run, uploads SARIF findings to Code Scanning, and issues a CycloneDX
v1.5 PQC Integrity Bond for clean PRs.

### Install

[Install Janitor Sentinel](https://github.com/apps/janitor-sentinel/installations/new)

Select the repositories you want Sentinel to guard.

### Permissions

| Permission | Level | Why |
|---|---|---|
| `checks` | Write | Post a Check Run on every PR with pass/fail status and the full Integrity Score |
| `contents` | Read | Clone the PR branch to run the engine against the actual code |
| `pull_requests` | Read | Read PR metadata (author, body, commit count) for governance evaluation |
| `security_events` | Write | Upload SARIF reports to GitHub Code Scanning for inline PR annotations |
| `statuses` | Write | Set commit statuses as a fallback signal |

### After Install

1. Create `janitor.toml` at your repository root. Minimal example:
   ```toml
   min_slop_score = 100
   require_issue_link = false
   ```
2. The next PR opened will trigger a Check Run automatically. No workflow file required.

### Check Run Outcomes

| Result | Condition |
|---|---|
| **Janitor: Clean — PQC Bond Issued** | score ≤ 1.0, no zombies |
| **Janitor: Code Quality Gate Failed** | score > 1.0, zombie veto, or policy block |
| **Janitor: Zombie Veto Cleared** | neutral result, false positive cleared |

If findings exist, a SARIF report is uploaded to GitHub Code Scanning with inline
annotations in the PR diff. For clean PRs, a CycloneDX v1.5 Integrity Bond signed
with ML-DSA-65 is issued automatically — no token flag or manual step.

### CI Integration — GitHub Action

The `action.yml` composite action handles binary caching, patch extraction, and
Governor reporting.

```yaml
# .github/workflows/janitor.yml
on: [pull_request]
jobs:
  janitor:
    runs-on: ubuntu-latest
    steps:
      - uses: janitor-security/the-janitor@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

**Symmetric Failure**: The action uses `set -eo pipefail` on every shell step. Any
failure — Governor unreachable, binary build failure, patch extraction error — exits
immediately with a non-zero code. The workflow fails visibly rather than silently
swallowing the error and leaving the Governor Check Run pending. There is no silent
pass-through on infrastructure failure.

---

## janitor.toml — Policy Reference

`janitor.toml` at the repository root encodes maintainer-controlled governance as
version-controlled, reviewable configuration. Loaded by `JanitorPolicy::load()` in
`crates/common/src/policy.rs`.

### Quick Start

```toml
# janitor.toml — place at repository root

# Slop score threshold. PRs with a raw score above this value fail the gate.
min_slop_score = 100

# Require every PR to reference a GitHub issue (#N) in the body.
require_issue_link = false

# Downgrade zombie-symbol vetoes to warnings for active refactor cycles.
allowed_zombies = false

# Raise the gate by this amount for PRs tagged [REFACTOR] or [FIXES-DEBT].
refactor_bonus = 0

# Require a PQC attestation bond (ML-DSA-65 / CycloneDX v1.5) — needs Sentinel.
pqc_enforced = false

# Paths to custom .scm tree-sitter query files that define project-specific antipatterns.
custom_antipatterns = []

# Handles exempt from the unlinked-PR penalty.
trusted_bot_authors = []

[forge]
# Ecosystem accounts that lack the [bot] suffix but are non-human contributors.
automation_accounts = []
```

### Field Reference

| Field | Type | Default | Description |
|---|---|---|---|
| `min_slop_score` | `u32` | `100` | Raw slop score ceiling. PRs above this threshold fail the gate. Lower = stricter. |
| `require_issue_link` | `bool` | `false` | When `true`, PRs with no `#<digits>` reference in the body are blocked regardless of score. |
| `allowed_zombies` | `bool` | `false` | Downgrade zombie-symbol re-introductions to a Warning. Set only during active symbol-resurrection refactors. |
| `refactor_bonus` | `u32` | `0` | Points added to `min_slop_score` for PRs tagged `[REFACTOR]` or `[FIXES-DEBT]`. |
| `pqc_enforced` | `bool` | `false` | Block PRs where the ML-DSA-65 / CycloneDX v1.5 Integrity Bond could not be issued. Requires Sentinel. |
| `custom_antipatterns` | `[String]` | `[]` | Paths to custom `.scm` tree-sitter query files. Each `@slop`-capturing pattern adds +50 per match. |
| `trusted_bot_authors` | `[String]` | `[]` | Handles exempt from the unlinked-PR penalty. Case-insensitive exact match. |

### `[forge]` Sub-table

| Field | Type | Default | Description |
|---|---|---|---|
| `automation_accounts` | `[String]` | `[]` | Ecosystem automation accounts exempt from the unlinked-PR penalty. Example: `["r-ryantm", "app/nixpkgs-ci"]`. Full slop analysis still runs; only the issue-link check is bypassed. |

### Automation Shield

The engine detects bot authors via four layers (all zero-allocation):

1. **`app/` prefix** — any author starting with `app/` is a GitHub App installation.
2. **`[bot]` suffix** — any author ending with `[bot]` is automatically detected.
3. **`trusted_bot_authors`** — handles listed at the top level of `janitor.toml`.
4. **`[forge].automation_accounts`** — handles without the `[bot]` suffix (e.g. `r-ryantm`).

When detected: exempt from the unlinked-PR penalty only. All other detection runs unchanged.

### Effective Gate Formula

```
effective_gate = min_slop_score + (refactor_bonus IF [REFACTOR] or [FIXES-DEBT] in body)
PR passes      = raw_slop_score < effective_gate
```

### `[webhook]` Sub-table

Outbound webhook delivery to SIEM systems, Slack, or Teams.

| Field | Type | Default | Description |
|---|---|---|---|
| `url` | `String` | `""` | Destination HTTPS URL. Empty disables delivery. |
| `secret` | `String` | `""` | HMAC-SHA256 signing secret. Use `"env:VAR_NAME"` to read from environment. |
| `events` | `[String]` | `["critical_threat"]` | Filter: `"critical_threat"`, `"necrotic_flag"`, `"all"`. |

The signature is in the `X-Janitor-Signature-256: sha256=<hex>` header.

```toml
[webhook]
url    = "https://hooks.slack.com/services/..."
secret = "env:JANITOR_WEBHOOK_SECRET"
events = ["critical_threat", "necrotic_flag"]
```

Test delivery without waiting for a real PR:

```sh
janitor webhook-test --repo .
# info: webhook-test — HTTP 200 ✓ delivery confirmed
```

### `[billing]` Sub-table

Overrides actuarial ledger rates.

| Field | Type | Default | Description |
|---|---|---|---|
| `triage_minutes_per_finding` | `f64` | `12.0` | Senior-engineer minutes per finding (Workslop 2026 default). |
| `critical_threat_usd` | `f64` | `150.0` | Billing rate for Critical Threats. |
| `necrotic_usd` | `f64` | `20.0` | Billing rate for Necrotic GC flags. |

### Custom Antipatterns

Point `custom_antipatterns` at `.scm` files containing tree-sitter queries with
`@slop` captures. Each match adds +50 to the composite slop score.

```toml
custom_antipatterns = [
    "tools/queries/no_global_state.scm",
    ".janitor/queries/no_direct_sql.scm",
]
```

### pqc_enforced

When `pqc_enforced = true` and the ML-DSA-65 / CycloneDX v1.5 Integrity Bond cannot
be issued (e.g. the Governor is unreachable), the PR is blocked:

```
BLOCKED by repository-defined governance policy (janitor.toml).
Reason: pqc_enforced = true. The ML-DSA-65 Integrity Bond could not be issued.
```
