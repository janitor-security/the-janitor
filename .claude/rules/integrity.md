# Rule: Pre-Commit Integrity (Law III)

Before finalizing any commit, execute in order:

## Step 1 — `janitor_bounce` (MCP)

Run against `git diff HEAD` or the patch being committed.

- If `slop_score > 0`: read `antipattern_details`, remediate each finding,
  re-run until clean.
- A non-zero score is a **hard block**. Do not commit.

## Step 2 — `janitor_silo_audit` (MCP)

Run any time `Cargo.toml` or `Cargo.lock` is modified.

- New silos introduced by a dependency upgrade must be documented or resolved
  before commit.

## Step 3 — `just audit`

Must exit 0. This is the Definition of Done. No exceptions.

`just audit` runs: `cargo fmt --check` + `cargo clippy -- -D warnings` +
`cargo check` + `cargo test`.

## Hard rules

- Never use `--no-verify` to skip hooks.
- Never amend a published commit.
- Never append `Co-authored-by:` trailers. Sole author: Riley Ghramm.
