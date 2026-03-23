# Janitor Sentinel — Setup Guide

**Janitor Sentinel** is the GitHub App that runs the Janitor engine against every
pull request. It posts a Check Run, uploads SARIF findings to Code Scanning, and
issues a CycloneDX v1.5 PQC Integrity Bond for clean PRs.

## Install

[Install Janitor Sentinel](https://github.com/apps/janitor-sentinel/installations/new)

One click. Select the repositories you want Sentinel to guard.

## What Permissions Are Requested

| Permission | Level | Why |
|---|---|---|
| `checks` | Write | Post a Check Run on every PR with pass/fail status and the full Integrity Score |
| `contents` | Read | Clone the PR branch to run the Janitor engine against the actual code |
| `pull_requests` | Read | Read PR metadata (author, body, commit count) for governance and Mesa Guard evaluation |
| `security_events` | Write | Upload SARIF reports to GitHub Code Scanning for inline PR annotations |
| `statuses` | Write | Set commit statuses as a fallback signal on older GitHub UI surfaces |

## After Install

1. Create `.janitor/janitor.toml` in your repository root to configure governance
   policy. See the [full field reference](governance.md) for all available options.

   Minimal example:
   ```toml
   min_slop_score = 100
   require_issue_link = false
   ```

2. The next PR you open will trigger a Check Run automatically. No workflow file
   required — Sentinel receives the webhook from GitHub directly.

## Expected First Behavior

When a PR is opened:

1. GitHub sends a `pull_request` webhook to Sentinel.
2. Sentinel creates an `in_progress` Check Run — a spinner appears on the PR.
3. Sentinel clones the PR branch, generates a diff, and runs `janitor bounce`.
4. The Check Run is updated with the result:
   - **Janitor: Clean — PQC Bond Issued** (score ≤ 1.0, no zombies)
   - **Janitor: Code Quality Gate Failed** (score > 1.0, zombie veto, policy block)
   - **Janitor: Zombie Veto Cleared — LSH Integrity Verified** (neutral, FP cleared)
5. If findings exist, a SARIF report is uploaded to GitHub Code Scanning — findings
   appear as inline annotations directly in the PR diff.
6. For clean PRs, a CycloneDX v1.5 Integrity Bond signed with ML-DSA-65 is written
   to the Governor's `bonds/` directory.

## Pricing

**$499/yr — Team Tier**

Covers unlimited repositories for a single GitHub organisation. API tokens are
issued automatically on payment via LemonSqueezy. No per-seat limits.

Questions: [support@thejanitor.app](mailto:support@thejanitor.app)
