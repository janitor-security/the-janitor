# Skill: Crucible Enforcement — Mandatory TDD Cycle (Auto-Invoked)

**Trigger:** Whenever implementing a new feature, fixing a bug, or adding a
detection rule in any crate under `crates/`.

This skill enforces the red-green cycle mandated by `.Codex/rules/testing.md`.
It cannot be bypassed.

## The Mandatory TDD Cycle

### Step 1 — Identify the target
Identify the specific detector, logic block, or crate being modified:
- For a new antipattern rule: identify the `find_slop()` / `slop_hunter.rs` call site.
- For a bug fix: identify the function whose behavior is being corrected.
- For a new manifest scanner: identify the `anatomist/manifest.rs` scan path.

### Step 2 — Write a failing test FIRST
Before implementing the fix or feature, write the `#[test]` that asserts the
desired behavior.

**For detectors**, a Crucible Gallery entry is mandatory in addition to any
`#[test]` in the module:

```rust
// crates/crucible/src/main.rs — add to GALLERY:
Entry {
    name: "<Lang>/<pattern> — INTERCEPT",
    lang: "<ext>",
    source: b"<minimal fixture that triggers the rule>",
    must_intercept: true,
    desc_fragment: Some("<keyword from finding description>"),
},
Entry {
    name: "<Lang>/<safe variant> — SAFE",
    lang: "<ext>",
    source: b"<minimal fixture that must NOT trigger the rule>",
    must_intercept: false,
    desc_fragment: None,
},
```

### Step 3 — Verify the FAILURE
Run the test to confirm it fails (red):

```bash
cargo test -p <crate> <test_name>  # must FAIL
cargo run -p crucible               # must show [FAIL] for the new entry
```

If the test passes before the implementation, the test is wrong — fix it.

### Step 4 — Implement the fix or feature
Write the production code that makes the test pass.

### Step 5 — Verify the PASS
Run the full suite to confirm green:

```bash
cargo run -p crucible   # must exit 0 (SANCTUARY INTACT)
just audit              # must exit 0 (✅ System Clean)
```

If either fails, return to Step 4.  Do not proceed to commit until both pass.

## Abort conditions

| Condition | Action |
|-----------|--------|
| New detector added with no Crucible Gallery entry | Block commit — add entry |
| New `#[test]` added but test was never run in FAIL state | Flag and confirm the test actually validates the behavior |
| `cargo run -p crucible` shows any `[FAIL]` | Block commit — fix the breach |
| `just audit` exits non-zero | Block commit — fix all violations |

## Scope

This skill applies to ALL of:
- `crates/forge/src/slop_hunter.rs` — new antipattern rules
- `crates/forge/src/slop_filter.rs` — bouncer logic changes
- `crates/forge/src/migration_guard.rs` — migration rules
- `crates/anatomist/src/manifest.rs` — manifest scanner changes
- `crates/common/src/policy.rs` — policy predicate changes
- Any new file under `crates/`

## Notes

- The minimum test surface is defined in `.Codex/rules/testing.md`.
- The Crucible Gallery (`crates/crucible/src/main.rs`) is the authoritative
  intercept proof.  `just audit` runs it as a `#[test]` — any gallery breach
  blocks the entire test suite.
- A fix with no test is not a fix.  It is a deferred defect.
