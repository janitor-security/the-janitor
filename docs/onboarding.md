# Janitor Sentinel — 30-Second Setup

## 1. Install the App

[**→ Install Janitor Sentinel**](https://github.com/apps/janitor-sentinel)

Click **Install** → select your repository → confirm.

---

## 2. Add the Workflow

Create `.github/workflows/janitor.yml`:

```yaml
name: Janitor Sentinel

on:
  pull_request:
    types: [opened, synchronize, reopened]

permissions:
  contents: read
  pull-requests: read

jobs:
  janitor:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: janitor-security/the-janitor@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
```

---

## 3. Add Your API Token

In your repository: **Settings → Secrets and variables → Actions → New repository secret**

| Name | Value |
|------|-------|
| `JANITOR_TOKEN` | *(paste the `gov_...` token from your welcome email)* |

Update the workflow `with:` block:

```yaml
      - uses: janitor-security/the-janitor@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          installation_id: ${{ secrets.JANITOR_TOKEN }}
```

---

Done. Open a pull request — the **Janitor Integrity Check** appears within 30 seconds.

> [→ Get a token](https://thejanitor.lemonsqueezy.com/checkout/buy/cf4f5dbd-1354-4e97-8b55-0d4375ec9be7?enabled=1361348) · [Architecture](architecture.md) · [Governance config](governance.md)
