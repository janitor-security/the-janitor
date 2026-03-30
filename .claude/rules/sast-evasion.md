# Rule: SAST Evasion — Static Assertion Hygiene

To prevent cloud SAST false positives (CodeQL `cleartext-logging-sensitive-data`,
SonarCloud `S2068`), NEVER interpolate synthetic secrets, threat payloads,
or finding structs into test assertion messages or console logs.

## The Law

Assertion messages and log statements must use **static strings only**.
Dynamic interpolation of finding results, patch text, or matched credential
strings causes cloud SAST scanners to trace the tainted data flow from the
detection fixture into the assertion message and flag a cleartext logging
violation — a false positive that cannot be suppressed without disabling the
rule entirely.

## Prohibited patterns

```rust
// BANNED — {findings:?} logs matched credential strings
assert!(!findings.is_empty(), "AKIA prefix must be detected: {findings:?}");

// BANNED — {patch} may contain injected test payloads
assert!(result.is_some(), "logic_erasure should fire: {patch}");

// BANNED — three-arg assert with tainted expr as format argument
assert!(
    findings[0].description.contains("credential_leak"),
    "description must cite credential_leak: {}",
    findings[0].description
);
```

## Required patterns

```rust
// CORRECT — static failure message only
assert!(!findings.is_empty(), "AKIA prefix must be detected");

// CORRECT — static message, no trailing format args
assert!(result.is_some(), "logic_erasure should fire");

// CORRECT — static message, no interpolated expression
assert!(
    findings[0].description.contains("credential_leak"),
    "description must cite credential_leak"
);
```

## Scope

This applies to all `assert!`, `assert_eq!`, `assert_ne!`, and `panic!` macros
across all crates in the workspace, including:
- `crates/forge/src/slop_hunter.rs` — credential, entropy, KEV gate tests
- `crates/forge/src/metadata.rs` — hallucinated-fix keyword tests
- `crates/experimental/advanced_threats/src/binary_hunter.rs` — credential scan tests
- Any future test module that uses synthetic threat fixtures

## Engine logs (production code)

`SlopFinding` structs and `antipattern_details` vecs must not be blindly dumped
to `stdout`/`stderr` via `println!` or `eprintln!` outside of explicitly
opted-in diagnostic modes (e.g., `--verbose` flag or `JANITOR_DEBUG=1`).

The bounce output in `cmd_bounce` already routes findings through the structured
bounce table — this is the correct path. Do not add naked `eprintln!("{findings:?}")`
calls in production code paths.

## Why

CodeQL's `cleartext-logging-sensitive-data` query traces taint from sources
annotated as sensitive (credential strings, PEM headers, entropy-qualifying
tokens) to sinks that write to console or assertion failure output. Even
`#[cfg(test)]` modules are analysed in the default CodeQL scan configuration.
Static assertion messages contain no tainted data and produce zero alerts.
