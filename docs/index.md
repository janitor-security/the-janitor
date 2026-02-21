# The Janitor

**v6.1.8 — Rust-Native. Zero-Copy. Polyglot Dead Symbol Excision.**

*"Code is Liability. Precision is the Cure."*

> **Sonar takes your code to the cloud. The Janitor cleans it on your metal.**
>
> Every analysis runs locally. Your source code never leaves your machine.

---

## I. THE PROBLEM: CODE BLOAT

Every codebase accumulates dead weight. Functions that were called once, classes that were subclassed by a deleted module, utilities from a refactoring that never shipped. Traditional linters flag style violations. They do not detect dead code.

The consequence is **Code Bloat**: dead symbols that occupy binary space, extend build times, inflate cognitive load, and survive code review because no tool has the reference resolution to prove they are unreachable.

Don't guess your technical debt. The Janitor generates a verifiable **Code Health Badge** so your team can surgically monitor the decay of the monolith before it impacts production.

### Data Sovereignty

Unlike cloud-based static analysis tools, The Janitor performs all operations — reference graph construction, structural clone detection, shadow-tree simulation — **offline, on your hardware**. Your source code is memory-mapped locally and never transmitted to any server. The signed attestation token is verified by a 32-byte public key embedded in the binary. No network call is made at any point in the pipeline.

---

## II. THE CURE: THE TECHNICAL STACK

The Janitor is not a linter. It is a surgical instrument.

### The Anatomist

Parses source code via zero-copy Tree-sitter CSTs across **9 grammars: C, C++, Rust, Go, Java, C#, JavaScript, TypeScript, and Python**. Extracts every function, class, and top-level symbol as a zero-copy `Entity` with byte ranges, qualified names, decorator lists, and structural hashes. Builds a directed reference graph resolving imports, attribute calls, and language-specific linkage (`#include`, `import`, `use`, `require`).

### The 6-Stage Dead Symbol Pipeline

| Stage | Filter | Guard |
|-------|--------|-------|
| 0 | Directory exclusion (`tests/`, `migrations/`, `venv/`) | `Protection::Directory` |
| 1 | Reference graph: in-degree > 0 | `Protection::Referenced` |
| 2+4 | Heuristic wisdom + `__all__` exports | Various |
| 3 | Library mode: all public symbols | `Protection::LibraryMode` |
| 5 | Aho-Corasick scan of non-`.py` files | `Protection::GrepShield` |

Anything that survives all five gates is a confirmed dead symbol.

### The Reaper

Executes surgical byte-range deletion. Sorts targets **descending by `start_byte`** (bottom-to-top splice) to preserve upstream offsets. UTF-8 hardened via `str::is_char_boundary()`. Atomic backup to `.janitor/ghost/` before first write.

### The Forge

Alpha-normalized BLAKE3 structural hashing detects duplicate functions with identical logic but different names. Injects Safe Proxy Pattern: duplicate bodies become one-line wrappers delegating to a shared canonical implementation.

### The Shadow

Symlink-based overlay of the source tree. Before any physical deletion, symlinks for dead-symbol files are unmapped and `pytest` is run in the shadow tree. Physical deletion proceeds only on a passing test suite; symlinks are restored on failure.

---

## III. THE ECONOMICS: UTILITY PRICING

**Automated Cleanup is Free. Integrity Proof is the Standard.**

| Tier | Cost | Scope |
|:-----|:-----|:------|
| **Junior Janitor** | **Free** | Unlimited Scan, Cleanup, Dedup, Dashboard. No signed logs. No PQC attestation. |
| **[Lead Specialist](https://thejanitor.lemonsqueezy.com/checkout/buy/lazarus_key)** | **$4,900/yr** | All free features + PQC-Signed Audit Logs + Sovereign Status Badges + CI/CD Compliance Attestation. Up to 10 seats. |
| **[Industrial Core](https://thejanitor.lemonsqueezy.com/checkout/buy/lazarus_key)** | **From $50,000/yr** | For monoliths >1M LOC. On-Prem Token Server + Keypair Rotation Protocol + Enterprise SLA. Unlimited seats. |

[**Get Certified → thejanitor.lemonsqueezy.com**](https://thejanitor.lemonsqueezy.com/checkout/buy/lazarus_key)

---

## IV. INSTALLATION

### From Source (Recommended)

Requires: **Rust 1.82+**, `just`.

```sh
git clone https://github.com/GhrammR/the-janitor
cd the-janitor
just build
# Binary at: target/release/janitor
```

Or with audit verification:

```sh
just audit   # fmt + clippy + check + 103 tests
just build
```

### Pre-built Binary

Download the stripped release binary from [Releases](https://github.com/GhrammR/the-janitor/releases).

```sh
chmod +x janitor
sudo mv janitor /usr/local/bin/
```

---

## V. COMMANDS

```sh
# Detect dead symbols (free)
janitor scan <path> [--library] [--verbose]

# Machine-readable dead-code report for CI/GitHub Checks (free)
janitor scan <path> --format json

# Score a pull request patch for dead symbol reintroductions (free)
janitor bounce <path> [--patch <file>] [--format json]

# Find structurally duplicate functions (free, report only)
janitor dedup <path>

# Apply Safe Proxy deduplication (free, explicit flag required)
janitor dedup <path> --apply --force-purge

# Shadow-simulate deletion + test, then physically remove dead symbols (free)
janitor clean <path> --force-purge

# Generate a code health badge (free)
janitor badge <path>

# Undo last cleanup (git stash or ghost restore)
janitor undo <path>

# Load .janitor/symbols.rkyv and launch TUI dashboard (free)
janitor dashboard <path>
```

---

> See [Safety Guarantees](safety.md) for the Shadow Tree isolation and atomic rollback protocol.
> See [Licensing](licensing.md) for the BUSL-1.1 terms and commercial tier details.
> See [Terms of Service](terms.md) · [Privacy Policy](privacy.md) for legal and data handling.
> Pre-v5 Python implementation history: [Archive](archive/legacy.md).
