# Command: /deploy-gov

Deploy the Governor service to Fly.io production.

## Usage

```
/deploy-gov
```

## Mapped command

```bash
cd ~/dev/the-governor && fly deploy -a the-governor --config fly.toml --dockerfile Dockerfile .
```

## What this does

Builds the Governor Docker image from `~/dev/the-governor/Dockerfile` and
deploys it to the `the-governor` Fly.io application using the project's
`fly.toml` configuration.  The build context is the `the-governor/` directory.

## Preconditions

- `~/dev/the-governor/` must exist and be on the correct commit.
- `fly` CLI must be authenticated (`fly auth whoami`).
- Any schema migrations required by the new Governor version must be staged
  in the migration files — the deploy does NOT run ad-hoc SQL.

## When to invoke

Immediately after the engine (`the-janitor`) is updated whenever:
- The Governor API contract changes (new routes, modified request/response shapes).
- A `BounceResult` field is added or removed.
- The JWT analysis-token format or TTL is changed.
- Any `POST /v1/*` endpoint signature changes.

See `.claude/rules/deployment-coupling.md` for the mandatory invocation policy.
