# Command: /audit

Run the full Definition-of-Done audit suite.

## Usage

```
/audit
```

## Mapped command

```bash
just audit
```

## Description

Runs the complete audit pipeline in the hermetic Nix shell:

1. `cargo fmt --check` — formatting compliance
2. `cargo clippy -- -D warnings` — zero warnings policy
3. `cargo check` — type correctness
4. `cargo test` — all unit and integration tests

Must exit 0 before any commit is finalized. This is the Definition of Done.
