# Rule: Operational Coupling — Deployment Trigger Mandates

Code changes that affect the live system have no value until they are deployed.
This rule closes the "last mile" gap between a committed change and a running system.

## The Three Laws

### Law I — Engine Release
If you modify core engine logic (any change that bumps the version, i.e. `v8.X.Y`),
you **MUST** propose a `/release` after the merge is confirmed on `main`.

- "Propose" means: state the exact command (`/release 8.X.Y`) and confirm the user
  wants to cut the tag before executing.
- Exception: hotfix commits to patch an in-progress release that will be tagged
  as a single unit with the next version bump.

### Law II — Governor Deployment
If you modify the Governor API or data contracts, you **MUST** execute `/deploy-gov`
immediately after the engine is updated and the release tag is pushed.

Governor API changes include:
- Any `POST /v1/*` route signature (request body shape, response fields).
- `BounceResult` struct fields (added, removed, or renamed).
- JWT analysis-token format, claims, or TTL.
- Database schema migrations that alter the query contract.

Failure to deploy the Governor after an API contract change leaves the live
Check Run system operating on a stale binary — a silent divergence that
manifests only under real PR traffic.

### Law III — Docs Deployment
If you modify any `.md` file in `docs/`, you **MUST** execute `/deploy-docs`
before concluding the session.

A committed doc change that is not deployed leaves the GitHub Pages site
out of sync with the repository.  Users reading the live site see stale
content.  This is equivalent to a broken release.

## Enforcement checklist

Before ending any session, verify:

- [ ] Did any commit in this session bump `Cargo.toml` version? → `/release` proposed
- [ ] Did any commit touch Governor API contracts? → `/deploy-gov` queued
- [ ] Did any commit modify `docs/*.md`? → `/deploy-docs` executed

## Cross-reference

- `/release` → `.claude/commands/release.md`
- `/deploy-gov` → `.claude/commands/deploy-gov.md`
- `/deploy-docs` → `.claude/commands/deploy-docs.md`
