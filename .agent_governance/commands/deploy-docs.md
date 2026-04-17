# Command: /deploy-docs

Build and push the documentation site to GitHub Pages.

## Usage

```
/deploy-docs
```

## Mapped command

```bash
just deploy-docs
```

Which expands to:

```bash
uv run --with "mkdocs-material<9.6" --with "mkdocs<2" mkdocs gh-deploy --force
```

## What this does

Builds the MkDocs Material site from `docs/` and force-pushes the rendered
HTML to the `gh-pages` branch.  GitHub Pages serves from that branch.

## Preconditions

- `uv` must be available in PATH.
- Must be run from the repository root (where `mkdocs.yml` lives).
- The `gh-pages` branch must not have a stale ref lock; if the push fails
  with "cannot lock ref", run `git fetch origin gh-pages` then retry.

## When to invoke

Before concluding any session in which a `.md` file under `docs/` was
modified.  Documentation changes that are committed but not deployed leave
the live site out of sync with the repository.

See `.claude/rules/deployment-coupling.md` for the mandatory invocation policy.
