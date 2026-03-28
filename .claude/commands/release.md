# Command: /release <v>

Cut a tagged GitHub release with the full audit gate.

## Usage

```
/release <v>
```

Where `<v>` is a bare version string — e.g. `8.0.6`, NOT `v8.0.6`.
The recipe prepends `v` for the git tag automatically.

## Mapped command

```bash
just release <v>
```

## What the recipe does

1. Runs `just audit` (fmt + clippy + check + test) — hard-fails on any violation.
2. Builds the release binary (`cargo build --release --workspace`).
3. Strips the binary.
4. Commits the version state, tags `v<v>` and the floating major tag `v<major>`.
5. Pushes `HEAD:main`, the version tag, and force-updates the major tag.
6. Creates a GitHub Release with the stripped binary.

## Preconditions

- `Cargo.toml [workspace.package].version` must already be set to `<v>`.
- Working tree must be clean (no uncommitted changes) before invoking.
- Must be on `main` branch.

## When to invoke

- After every engine version bump (8.X.Y) that has been merged to `main`.
- See `.claude/rules/deployment-coupling.md` for the mandatory invocation policy.
