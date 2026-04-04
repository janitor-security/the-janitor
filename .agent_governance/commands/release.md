# Command: /release <v>

Cut a tagged GitHub release with the full audit gate.

## Usage

```
/release <v>
```

Where `<v>` is a bare version string — e.g. `9.0.1`, NOT `v9.0.1`.
The recipe prepends `v` for the git tag automatically.

## AI-Guided Release Sequence (strictly linear — no re-auditing)

Execute **in order**. Do not skip or reorder steps.

### Step 1 — Version bump (single file)
Edit `Cargo.toml [workspace.package].version` to `<v>`.
This is the **only** file that requires a version change. All crates inherit
the version via `version.workspace = true`. Do not edit crate-level `Cargo.toml`
files or any `docs/` file to reflect the version — Cargo propagates it.

### Step 2 — Update governance logs
1. Append the current session's directive to `docs/IMPLEMENTATION_BACKLOG.md`.
2. Append CT entries (or `<!-- no telemetry findings this session -->`) to
   `docs/INNOVATION_LOG.md` under a `## Continuous Telemetry — YYYY-MM-DD` section.
3. Run the Evolution Tracker Auto-Purge check: if all findings under any H2/H3
   section are marked `[COMPLETED — ...]`, delete that section now.

Both logs **must** be current before Step 3. See `.claude/skills/evolution-tracker/SKILL.md`.

### Step 3 — Audit (once)
```bash
just audit
```
Hard stop on any failure. Do **not** re-run audit after this point — the working
tree must be clean from this step forward.

### Step 4 — Release
```bash
just fast-release <v>
```
The recipe skips the audit dependency (audit was already run in Step 3) and
performs: commits staged changes → tags `v<v>` + floating `v<major>` →
pushes `HEAD:main` + tags → creates GitHub Release → runs `just deploy-docs`.

Do **not** use `just release` — it re-runs `just audit` as a prerequisite,
producing a redundant second audit pass.

### GPG fallback (if `just fast-release` fails with `fatal: no tag message?`)

The global git config `tag.gpgSign = true` requires an explicit message on all
tags. If `just release` aborts at the `git tag v<v>` step, run manually:

```bash
git tag -s v<v> -m "v<v> — <short description>"
MAJOR=$(echo <v> | cut -d. -f1)
git tag -fa "v${MAJOR}" -m "v${MAJOR} → v<v>"
cargo build --release --workspace && strip target/release/janitor
git push origin HEAD:main "v<v>"
git push origin "v${MAJOR}" --force
"/mnt/c/Program Files/GitHub CLI/gh.exe" release create "v<v>" target/release/janitor \
    --title "v<v> — <short description>" --notes-file README.md --latest
just deploy-docs
```

## Preconditions

- Must be on `main` branch with a clean working tree **after** Step 2.
- `Cargo.toml [workspace.package].version` set to `<v>` (done in Step 1).

## When to invoke

- After every engine version bump that has been merged to `main`.
- See `.claude/rules/deployment-coupling.md` for the mandatory invocation policy.
