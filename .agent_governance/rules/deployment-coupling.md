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

### Law IV — Documentation Staleness is a Compliance Breach

Every time a feature is added, modified, or removed, you **MUST** run a global
documentation audit to ensure no obsolete claims remain in marketing or
technical docs.

**Protocol — mandatory after every feature change:**

```bash
rg <old_feature_name> docs/
rg <old_api_field> docs/
rg <old_flag_name> docs/
```

If any match is found, update or retract the stale claim **in the same commit**
as the feature change. A committed feature with contradicted documentation is
equivalent to a broken release — users reading the live site will act on false
information.

**Scope:**
- Any new or removed CLI flag → search `docs/` for the old flag name
- Any renamed struct field or JSON key → search `docs/` for the old name
- Any changed API route or endpoint → search `docs/` for the old path
- Any version claim update → search `docs/` for superseded version strings

**Hard rule:** Do not commit a feature change and a separate doc-fix in
different commits. The feature commit and its doc update are a single atomic
unit. Split commits for doc-only changes are permitted; split commits that
leave docs temporarily wrong are not.

## Enforcement checklist

Before ending any session, verify:

- [ ] Did any commit in this session bump `Cargo.toml` version? → `/release` proposed
- [ ] Did any commit touch Governor API contracts? → `/deploy-gov` queued
- [ ] Did any commit modify `docs/*.md`? → `/deploy-docs` executed
- [ ] Did any commit add/modify/remove a feature? → `rg <feature_name> docs/` run, stale claims resolved

## Cross-reference

- `/release` → `.claude/commands/release.md`
- `/deploy-gov` → `.claude/commands/deploy-gov.md`
- `/deploy-docs` → `.claude/commands/deploy-docs.md`
