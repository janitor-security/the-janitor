---
# Command: /crucible

Run the Threat Gallery regression harness and verify every active detector
intercepts its target pattern with zero false-positive leakage.

## Usage

```
/crucible
```

## Mapped command

```bash
cargo run -p crucible
```

## Description

Executes the Threat Gallery — a collection of hardcoded, minimal source
fixtures organized as `(language, source, must_intercept, desc_fragment)`
tuples — against `forge::slop_hunter::find_slop`.

### Verdicts

| Symbol | Meaning |
|--------|---------|
| `[PASS]` | Threat intercepted (or safe fixture passed cleanly) |
| `[FAIL]` | Detector missed a threat OR fired on safe code |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | SANCTUARY INTACT — all entries passed |
| `1` | BREACH DETECTED — one or more detectors failed |

### Coverage

Active galleries (one entry per distinct trigger path):

- YAML: VirtualService, Ingress, HTTPRoute, Gateway wildcard host + safe counterparts
- C/C++: `gets()`, `strcpy()`, `sprintf()`, `scanf()` + safe counterpart
- HCL/Terraform: open CIDR `0.0.0.0/0`, S3 `public-read` + safe counterparts
- Python: `subprocess` with `shell=True` + safe counterparts
- JavaScript/TypeScript: `innerHTML` assignment + safe counterpart

## When to run

- Before any commit that modifies `crates/forge/` or `crates/anatomist/`
  (enforced by the Crucible skill — see `.claude/skills/crucible/SKILL.md`)
- After adding a new detector rule (add a gallery entry first — red → green)
- Before cutting a release to confirm the full threat surface is covered

## Integration with `just audit`

The Threat Gallery also runs as a `#[test]` block inside `crates/crucible/src/main.rs`.
`just audit` → `cargo test --workspace` will catch any gallery breach automatically.
`cargo run -p crucible` gives the human-readable per-entry output.
