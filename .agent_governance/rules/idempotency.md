# Rule: The Idempotency Law — Mutation State Awareness

All shell scripts and `just` recipes that mutate external state **MUST** be
idempotent. Before executing any mutation, query the target state. If the
desired state already exists, log a clear message and `exit 0` cleanly.

## The Law

A release pipeline that crashes on the second run is not a release pipeline —
it is a minefield. Every mutation step (Git tag creation, GitHub Release
publication, disk writes) must tolerate being called twice with the same
arguments without error, data loss, or side-channel damage.

## Scope

This applies to all operations that:
- Create or push a Git tag
- Create a GitHub Release
- Write to a shared artifact store or registry
- Invoke any external API endpoint that creates a resource

## Guard Protocol

Before each mutation, inject an existence check:

```bash
# Git tag guard
if git rev-parse "v${VERSION}" >/dev/null 2>&1 \
   || git ls-remote --tags origin "refs/tags/v${VERSION}" | grep -q .; then
    echo "Idempotency guard: Release v${VERSION} already exists. Halting gracefully."
    exit 0
fi

# GitHub Release guard (call before gh release create)
if gh release view "v${VERSION}" >/dev/null 2>&1; then
    echo "Idempotency guard: GitHub Release v${VERSION} already exists. Skipping."
else
    gh release create "v${VERSION}" --generate-notes --title "The Janitor v${VERSION}"
fi
```

## Hard constraints

1. **Never use `--force` to overwrite a published tag.** Force-pushing a signed
   tag destroys the cryptographic record and invalidates any downstream
   verification. An idempotency guard is the correct fix — not force.
2. **Exit code 0 on already-exists.** A pipeline triggered twice by a race
   must not page oncall. Clean exit is the correct outcome.
3. **Log the guard decision.** Every `exit 0` from an idempotency guard must
   emit a human-readable message stating *why* it exited early. Silent exits
   are indistinguishable from silent failures.
4. **The guard checks both local and remote state.** Checking only
   `git rev-parse` misses tags that exist on the remote but were not fetched.
   Always pair with `git ls-remote --tags origin`.

## Enforcement checklist

- [ ] Release recipes check local AND remote tag existence before `git tag`
- [ ] `gh release create` is guarded by `gh release view` pre-check
- [ ] All guard exits emit a log line explaining the early-exit decision
- [ ] No `--force` flags on published tag mutations
