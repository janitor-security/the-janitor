# Command: /release <v>

Operational protocol for agent commit discipline and operator-directed releases.

## Usage

```
/release <v>
```

Where `<v>` is a bare version string — e.g. `10.2.0-alpha.5`, NOT `v10.2.0-alpha.5`.
The recipe prepends `v` for the git tag automatically.

## Continuous Commit Mandate (Law 0)

At the successful completion of **EVERY** prompt, the agent **MUST** execute:

```bash
git commit -a -m "<descriptive message summarizing this prompt's work>"
```

No uncommitted work may survive past the end of a prompt. If the working tree
has modifications when a prompt concludes, the agent commits. If the working
tree is clean, no action is required.

### Exceptions

- A hard-block failure (`just audit` non-zero, `cargo test` failing, Crucible
  non-zero) means the prompt did **not** complete successfully — the agent
  fixes the block before committing.
- If the operator explicitly instructs "do not commit" in the prompt, the
  mandate is suspended for that prompt only.

## Release Cadence Mandate (Law I)

`just fast-release <version>` executes **only** when:

1. The Sovereign Operator explicitly commands a release in the prompt, OR
2. The current prompt represents the completion of a **major Phase block** —
   defined as every 5th feature integration since the last published tag.

Agents track the feature-integration counter mentally per session and trigger
the automatic release gate when the counter reaches 5. A "feature integration"
is a commit whose subject line starts with `feat(`, `feat!:`, or `perf(` —
`chore`, `docs`, `fix`, and `refactor` commits do not advance the counter.

## Test Concurrency Mandate (Law II)

All `cargo test` invocations **MUST** use `-- --test-threads=4` to balance
speed and memory. Example:

```bash
cargo test --workspace -- --test-threads=4
```

Do **NOT** use `--test-threads=1` unless explicitly instructed by the operator
or required to reproduce a race condition.

## Release Execution Order (when commanded)

Execute **in order**. Stop only on hard failure.

### Step 1 — Requested file modifications
Complete all code, docs, or workflow edits explicitly requested by the
directive.

### Step 2 — Governance logs
1. Append the current session's directive to `docs/CHANGELOG.md`.
2. Update `.INNOVATION_LOG.md` only when the directive explicitly changes the
   roadmap, closes backlog items, or seeds new architecture.

### Step 3 — Deterministic test gate
```bash
cargo test --workspace -- --test-threads=4
```
Hard stop on any failure.

### Step 4 — Full audit gate
```bash
just audit
```
Hard stop on any failure.

### Step 5 — Version bump
Edit `Cargo.toml` `[workspace.package].version` to the target version. This
bump is the only permitted manual edit to that field.

### Step 6 — Fast release
```bash
just fast-release <version>
```
This recipe handles commit, signed tag, push, and GH Release publication via
the idempotency-guarded pipeline (`.agent_governance/rules/idempotency.md`).

## Preconditions

- `/release <v>` is operator-directed or Phase-block-triggered only.
- Version bumps are monotonic — never reuse or reorder a published version.
- `gpg-unlock` must have been executed within the current 8-hour window.

## Hard prohibitions

- **Never** use `--no-verify` to skip signing hooks.
- **Never** force-push a signed tag.
- **Never** append `Co-authored-by:` trailers — sole author: Riley Ghramm.
- **Never** stage `CLAUDE.md`, `.env*`, `secrets/`, or `.gitignore`-matched
  files.
