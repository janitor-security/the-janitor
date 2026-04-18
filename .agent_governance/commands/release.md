# Command: /release <v>

Batched Engineering governance for operator-directed releases only.

## Usage

```
/release <v>
```

Where `<v>` is a bare version string — e.g. `9.0.1`, NOT `v9.0.1`.
The recipe prepends `v` for the git tag automatically.

## Batched Engineering Standard

Unless the Sovereign Operator explicitly commands a release, agents must treat
all work as a batch-preparation pass, not a publish pass.

### Default agent stop state

Execute **in order**. Stop after Step 4.

### Step 1 — Requested file modifications
Complete only the code, docs, or workflow edits explicitly requested by the
directive. Do not invent release work.

### Step 2 — Governance logs
1. Append the current session's directive to `docs/CHANGELOG.md`.
2. Update `.INNOVATION_LOG.md` only when the directive explicitly changes the
   roadmap, closes backlog items, or seeds new architecture.

### Step 3 — Deterministic test gate
```bash
cargo test --workspace -- --test-threads=1
```
Hard stop on any failure.

### Step 4 — Full audit gate
```bash
just audit
```
Hard stop on any failure.

### Mandatory stop
After Step 4, agents must stop and leave the modified files in the working tree
for the Sovereign Operator to review, commit, sign, tag, and publish manually.

## Absolute prohibitions without explicit operator command

- Do **not** run `just fast-release`.
- Do **not** run `just release`.
- Do **not** create commits.
- Do **not** create tags.
- Do **not** push branches or tags.
- Do **not** create GitHub Releases.
- Do **not** deploy docs.

The only exception is a directive that explicitly commands those actions.

## Preconditions

- `/release <v>` is operator-only. Agents must not invoke it speculatively.
- If a release is explicitly commanded, the operator must separately authorize
  version bumps, commit/tag creation, and publishing.

## When to invoke

- Only when the Sovereign Operator explicitly commands a release batch.
- Normal prompts use Batched Engineering and stop after tests plus audit.
