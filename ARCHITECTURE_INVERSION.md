# Architecture Inversion — Governor Zero-Upload Transition

## The Problem

The current Janitor Sentinel architecture contradicts the product's central trust proposition.

**Claim** (`docs/index.md`, `README.md`):
> "Your source code is never copied to heap, never serialized, never transmitted."

**Reality** (`the-governor/src/main.rs`, `handle_pull_request()`):

```rust
// main.rs:1047 — build authenticated clone URL
let auth_clone_url = if let Some(rest) = clone_url.strip_prefix("https://") {
    format!("https://x-access-token:{}@{}", install_token, rest)
} else {
    clone_url.to_owned()
};

// main.rs:1063 — clone PR head branch to Fly.io temp directory
let clone_ok = Command::new("git")
    .args(["clone", "--depth", "1", "--branch", head_ref, &auth_clone_url, repo_path.to_str().unwrap()])
    .status().await
    .context("Failed to spawn git clone")?
    .success();
```

A security engineer evaluating the product will find this contradiction within minutes of reading
the webhook handler source. The clone lands in a Fly.io ephemeral volume at a temp path allocated
by `tempfile::TempDir`. That directory is destroyed when the TempDir guard drops, but the source
code was present on Janitor infrastructure for the duration of the analysis.

---

## The Two-Product Model (Current)

### CLI + GitHub Action (`action.yml`)

The GitHub Action invokes the `janitor` binary directly on the GitHub Actions runner. The runner
is customer-owned hardware (or GitHub-hosted, within the customer's org). Source code is accessed
via `git checkout` which already happened as part of the workflow. The `janitor bounce` invocation
uses `--patch` (diff from `gh pr diff`) or `--repo --base --head` (libgit2 in-process blob
extraction). No source code leaves the runner at any point. This model satisfies the zero-upload
guarantee truthfully.

### Janitor Sentinel (GitHub App / Governor)

The Governor is a Fly.io service that receives GitHub webhook events for `pull_request` actions.
On each event, `handle_pull_request()` in `the-governor/src/main.rs`:

1. Exchanges the installation token at `main.rs:1047` to obtain an authenticated clone URL.
2. Executes `git clone --depth 1` at `main.rs:1063`, landing the PR head branch in a temp
   directory on the Fly.io machine's local filesystem.
3. Fetches the base SHA (`git fetch origin <base_sha>`) to enable diff construction.
4. Invokes the `janitor` binary (sidecar on the same machine) with the local repo path.
5. The `TempDir` guard drops when `handle_pull_request()` returns, deleting the clone.

Source code is present on Janitor infrastructure for the duration of steps 2–5 only.
It is not persisted, indexed, or transmitted to any secondary system.

---

## The Target Architecture

In the inverted model, the Governor never receives source code. Instead:

1. The Governor receives the GitHub webhook and issues a signed **analysis token** back to
   the customer's environment (GitHub Actions, customer-hosted runner, or customer's CI agent).
2. The customer-side runner calls `janitor bounce` locally using the analysis token.
3. The bounce result — a scored `BounceLogEntry` JSON — is POSTed back to the Governor for
   attestation and Check Run update.
4. The Governor signs the entry with ML-DSA-65 and issues the CycloneDX CBOM bond.

The Governor's role becomes: **webhook receiver + token issuer + attestation signer + Check Run
updater**. It never touches source code.

---

## What Must Change

### In the Governor (`the-governor`)

| Component | Current | Target |
|---|---|---|
| `handle_pull_request()` (`main.rs:1041–1074`) | Git clone to temp dir | Remove git clone; issue analysis token instead |
| `run_janitor_analysis()` | Exec `janitor bounce` on local clone | Receive signed `BounceLogEntry` from customer runner via POST `/v1/report` |
| Fly.io storage | Ephemeral clone volume | No source storage needed — remove `tempfile::TempDir` usage |
| New endpoint | — | `POST /v1/report` — accepts signed bounce result, verifies token, issues CBOM, updates Check Run |
| New endpoint | — | `POST /v1/analysis-token` — issues short-lived (5 min TTL) signed token for a specific PR |

The Governor becomes a stateless attestation relay. No disk I/O beyond the bounce log.

### In the CLI (`the-janitor`)

| Component | Change |
|---|---|
| `cmd_bounce` (`crates/cli/src/main.rs`) | Add `--report-url` flag: after computing `BounceLogEntry`, POST it to the Governor's `/v1/report` endpoint with the analysis token in the `Authorization` header |
| `fire_webhook_if_configured` (`crates/cli/src/report.rs`) | Already handles outbound POST — can serve as the template for the report POST |
| GitHub Action (`action.yml`) | Add step: call Governor's `/v1/analysis-token` with `GITHUB_TOKEN`, pass token to `janitor bounce --report-url` |

### Transition Period

Dual-mode support is required during the transition. The Governor must support both architectures
simultaneously (feature flag: `GOVERNOR_INVERT_MODE=true`):

- **Legacy mode** (default): git clone + local analysis. Existing Sentinel customers continue
  uninterrupted.
- **Inverted mode**: token-issue + remote result acceptance. Opt-in for new customers and
  customers who require the zero-upload guarantee.

The landing page claim should be qualified with the deployment model table (already added in v7.9.3)
until legacy mode is fully retired.

---

## Implementation Sequence

1. **Governor: add `POST /v1/analysis-token`** — IMPLEMENTED in v7.9.4
   - Issues a JWT signed with the Governor's Ed25519 key, scoped to `{repo_full}:{pr_number}:{head_sha}`.
   - 5-minute TTL.  Rate-limited: one token per (repo, PR) per 60 s.
   - Controlled by `GOVERNOR_INVERT_MODE=1`; returns 404 in legacy mode.

2. **CLI: add `--report-url` to `cmd_bounce`** — IMPLEMENTED in v7.9.4
   - After `append_bounce_log`, if `--report-url` and `--analysis-token` are set, POSTs the
     `BounceLogEntry` to the URL with `Authorization: Bearer <token>`.
   - Non-fatal: source code stays on the runner regardless of POST outcome.

3. **Governor: add `POST /v1/report`** — IMPLEMENTED in v7.9.4
   - Verifies the JWT.  Verifies `BounceLogEntry.commit_sha` matches the token's `head_sha` claim.
   - Retrieves `(check_run_id, install_octo)` from `pending_checks` DashMap.
   - Updates GitHub Check Run with score summary.
   - Only active when `GOVERNOR_INVERT_MODE=1`.

4. **GitHub Action: wire the token exchange** — IMPLEMENTED in v7.9.4
   - New inputs: `governor_url` (default: `https://the-governor.fly.dev`), `invert_mode` (default: `false`).
   - Pre-bounce step fetches analysis token from `/v1/analysis-token`.
   - Token passed to `janitor bounce --report-url --analysis-token`.

5. **Governor: retire legacy clone path** (1 sprint after inverted mode is stable in prod)
   - Remove `handle_pull_request()` clone block.
   - Remove `tempfile` dependency.
   - Fly.io machine type can be downgraded (no longer needs clone-capable ephemeral storage).

6. **Update landing page** (on retirement of legacy mode)
   - Remove deployment model caveat.  Zero-upload claim becomes universally true.

---

## Security Properties After Inversion

After full transition, the following can be truthfully claimed for all deployment models:

- Source code is memory-mapped on the customer's hardware and never transmitted.
- The Governor receives only scored metadata (`BounceLogEntry` JSON, ~2 KB per PR) — no source
  code, no diff, no file content.
- The `commit_sha` and `policy_hash` fields in `BounceLogEntry` (v7.9.3) provide a cryptographic
  reference to the exact code state without transmitting the code itself.
- SOC 2 Type II audit trail: `policy_hash` (BLAKE3 of `janitor.toml`) + ML-DSA-65 CBOM bond +
  `commit_sha` establish provenance without requiring source code custody.
- The Governor becomes a pure attestation relay — no data retention requirement, no DPA surface.

---

*Authored 2026-03-23. Implementation (Steps 1–4) completed in v7.9.4 (2026-03-23). Current Governor version: see `the-governor/Cargo.toml`.*
