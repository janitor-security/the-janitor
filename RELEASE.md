# Release Verification

## v5.7.0

**Date:** 2026-02-16
**Repository:** https://github.com/GhrammR/the-janitor
**Tag:** `v5.7.0`

---

## Build Verification

To reproduce the release binary from source:

```sh
git clone https://github.com/GhrammR/the-janitor
cd the-janitor
git checkout v5.7.0
just build
# Binary: target/release/janitor
```

Verify the binary against the published SHA-256:

```sh
sha256sum target/release/janitor
```

The expected SHA-256 digest is published on [thejanitor.app/releases](https://thejanitor.app/releases) after each tagged release. Cross-reference this digest against the pre-built binary attached to the GitHub Release to confirm build reproducibility.

---

## Audit Protocol

Every cleanup operation records an entry in `.janitor/audit_log.json`:

```json
[
  {
    "timestamp": "2026-02-16T14:30:00Z",
    "file_path": "/abs/path/src/module.py",
    "symbol_name": "unused_helper",
    "sha256_pre_cleanup": "a3b4c5d6e7f8...",
    "heuristic_id": "DEAD_SYMBOL",
    "lines_removed": 14
  }
]
```

`sha256_pre_cleanup` is the SHA-256 digest of the entire file *before* modification. Auditors can verify that any `.janitor/ghost/*.bak` backup matches this digest.

---

## Minimum Verification Checklist

- [ ] `git tag v5.7.0` matches the commit hash on `main`
- [ ] `just audit` passes (0 test failures, 0 clippy warnings)
- [ ] `sha256sum target/release/janitor` matches published digest
- [ ] `.janitor/audit_log.json` is present after any `--force-purge` run
- [ ] `janitor scan` completes without error on a clean Python project

---

## Changelog Summary

| Component | Change |
|-----------|--------|
| Pricing model | Cleanup is now **free**. Tokens required only for signed attestation. |
| `audit_log.json` | Fields renamed: `sha256_pre_cleanup`, `lines_removed`. |
| Windows shadow | Hard links (no Admin/Developer Mode required). NTFS junctions for directory-level mirroring. |
| `janitor undo` | New command: `git stash` primary, `.janitor/ghost/` fallback. |
| `janitor badge` | New command: generates code health SVG badge. |
| Branding | "SOVEREIGN.md" → "ARCHITECTURE.md". "Metabolic Bloat" → "Code Bloat". "Guerrilla Mandate" → "Resource-Efficient Architecture". |
